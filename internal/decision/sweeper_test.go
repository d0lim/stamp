package decision_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// Two sweepers, one table. Every expired decision must be resolved exactly
// once: twice would mean two audit rows claiming to be the moment the decision
// ended, and an audit log that says a decision expired twice is one nobody can
// reason from.
//
// The claim's SKIP LOCKED keeps the two from queueing behind each other; the
// conditional update behind Next is what makes "exactly once" true rather than
// merely likely. This test would still pass with only the second mechanism,
// which is the point — the guarantee does not rest on the lock timing.
func TestTwoSweepersResolveEachDecisionExactlyOnce(t *testing.T) {
	ctx := context.Background()
	opts := harnessOptions{
		ttl:            10 * time.Minute,
		maxOutstanding: -1,
		policies:       []*policy.Policy{gatedPolicy("wire-transfer", 2, "alice", "bob", "carol")},
	}
	h := newHarness(t, opts)

	const decisions = 16
	ids := make([]string, 0, decisions)
	for i := 0; i < decisions; i++ {
		res, err := h.svc.Decide(ctx, decision.Request{
			Caller: workload("payments"), Input: transferRequest("u1"),
		})
		if err != nil {
			t.Fatalf("decide %d: %v", i, err)
		}
		ids = append(ids, res.ID)
	}

	// The second sweeper runs on its own audit writer, as a second process
	// would: a writer identifier belongs to exactly one claimant.
	second := h.newService(h.claimWriter("decide-2"), opts)

	h.clock.Advance(11 * time.Minute)

	sweepers := []*decision.Service{h.svc, second}
	reports := make([]decision.SweepReport, len(sweepers))
	errs := make([]error, len(sweepers))
	var wg sync.WaitGroup
	for i, svc := range sweepers {
		sweeper, err := decision.NewSweeper(decision.SweeperConfig{Service: svc, Batch: decisions})
		if err != nil {
			t.Fatalf("new sweeper %d: %v", i, err)
		}
		wg.Add(1)
		go func(i int, s *decision.Sweeper) {
			defer wg.Done()
			// Each sweeper drains, so between them they cover every decision no
			// matter how the claims split.
			for {
				report, err := s.SweepOnce(ctx)
				reports[i].Claimed += report.Claimed
				reports[i].Expired += report.Expired
				reports[i].Skipped += report.Skipped
				if err != nil {
					errs[i] = err
					return
				}
				if report.Claimed == 0 {
					return
				}
			}
		}(i, sweeper)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("sweeper %d: %v", i, err)
		}
	}
	total := reports[0].Expired + reports[1].Expired
	if total != decisions {
		t.Errorf("the two sweepers expired %d decisions between them (%d + %d), want %d",
			total, reports[0].Expired, reports[1].Expired, decisions)
	}

	for _, id := range ids {
		if got := h.decisionState(id); got != store.DecisionExpired {
			t.Errorf("decision %s is %q, want expired", id, got)
		}
		if rows := h.auditPayloads(store.AuditKindDecisionResolved, id); len(rows) != 1 {
			t.Errorf("decision %s has %d resolution audit rows, want exactly 1", id, len(rows))
		}
	}
}

// A sweep that finds a challenge timer rather than an expiry asks the handler
// what the elapsed timer meant. A delay answers satisfied — which is why the
// contract has no separate "your deadline fired" callback, since one would have
// had to guess between satisfied and failed.
func TestSweeperSettlesAnElapsedChallengeTimer(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:      2 * time.Hour,
		policies: []*policy.Policy{delayedPolicy("cooling-off", 30*time.Minute)},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if res.State != store.DecisionPending {
		t.Fatalf("a delayed decision is %q, want pending", res.State)
	}

	// Before the timer: nothing is due, and the decision stays pending.
	if report := h.sweepOnce(h.svc); report.Claimed != 0 {
		t.Fatalf("sweep before the timer claimed %d decisions, want 0", report.Claimed)
	}

	h.clock.Advance(31 * time.Minute)
	report := h.sweepOnce(h.svc)
	if report.Advanced != 1 || report.Expired != 0 {
		t.Fatalf("sweep report = %+v, want one advanced and none expired", report)
	}
	if got := h.decisionState(res.ID); got != store.DecisionAllowed {
		t.Fatalf("decision is %q after its delay elapsed, want allowed", got)
	}
}

// A quorum's deadline elapsing is the opposite case: the handler still reports
// pending, and a challenge that ran out of time fails, taking the decision to
// denied rather than to allowed.
func TestSweeperFailsAChallengeThatRanOutOfTime(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{
		ttl:      2 * time.Hour,
		policies: []*policy.Policy{gatedPolicy("wire-transfer", 2, "alice", "bob", "carol")},
	})

	res, err := h.svc.Decide(ctx, decision.Request{Caller: workload("payments"), Input: transferRequest("u1")})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	// The quorum handler issues no timer of its own, so one is set here to
	// stand for the per-challenge deadline U10 and U11 issue.
	deadline := h.clock.Now().Add(10 * time.Minute)
	if _, err := h.store.Pool().Exec(ctx, `
		UPDATE challenge_progress SET deadline = $2 WHERE decision_id = $1`, res.ID, deadline); err != nil {
		t.Fatalf("set challenge deadline: %v", err)
	}
	if _, err := h.store.Pool().Exec(ctx, `
		UPDATE decisions SET next_deadline = $2, next_deadline_kind = 'challenge' WHERE id = $1`,
		res.ID, deadline); err != nil {
		t.Fatalf("set next_deadline: %v", err)
	}

	h.clock.Advance(11 * time.Minute)
	report := h.sweepOnce(h.svc)
	if report.Advanced != 1 {
		t.Fatalf("sweep report = %+v, want one advanced", report)
	}
	if got := h.decisionState(res.ID); got != store.DecisionDenied {
		t.Fatalf("decision is %q after its quorum ran out of time, want denied", got)
	}
	if got := h.svc.Now(); got != h.clock.Now() {
		t.Errorf("service clock = %s, want the test clock %s", got, h.clock.Now())
	}
}

// Run stops when its context is cancelled: the sweeper is a registry component
// and a component that ignored cancellation would hang shutdown.
func TestSweeperRunStopsOnContextCancel(t *testing.T) {
	h := newHarness(t, harnessOptions{policies: []*policy.Policy{openPolicy("read-only")}})
	sweeper, err := decision.NewSweeper(decision.SweeperConfig{
		Service:  h.svc,
		Interval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new sweeper: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sweeper.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}
