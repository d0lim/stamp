package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

func newDecision(t *testing.T, s *store.Store, w *store.AuditWriter, expiresIn time.Duration, challenges ...store.NewChallenge) store.Decision {
	t.Helper()
	rec := seedPolicy(t, s, "wire-transfer", policy.Delay{Duration: time.Hour})
	d, err := w.CreateDecision(context.Background(), store.NewDecision{
		CallerID:      "pep-1",
		PolicyID:      rec.ID,
		PolicyVersion: rec.Version,
		SubjectID:     "u1",
		ResourceID:    "acct-9",
		Action:        "transfer",
		Request:       map[string]any{"amount": 5000},
		FactSnapshot:  map[string]any{"risk_score": 0.42, "groups": []string{"eng"}},
		ExpiresAt:     s.Now().Add(expiresIn),
		Challenges:    challenges,
	})
	if err != nil {
		t.Fatalf("create decision: %v", err)
	}
	return d
}

// The load-bearing separation: a delay timer sitting in the scheduler column
// must not make the decision read as expired. Collapsing the two columns is the
// exact bug this schema exists to prevent.
func TestDelayTimerInNextDeadlineDoesNotExpireTheDecision(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")

	delayUntil := s.Now().Add(5 * time.Minute)
	d := newDecision(t, s, w, time.Hour, store.NewChallenge{
		Ordinal: 0, Kind: policy.ChallengeDelay, Deadline: &delayUntil,
	})

	if d.NextDeadlineKind != store.DeadlineChallenge {
		t.Fatalf("next_deadline_kind = %q, want %q", d.NextDeadlineKind, store.DeadlineChallenge)
	}
	if d.NextDeadline == nil || !d.NextDeadline.Equal(delayUntil.Truncate(time.Microsecond)) {
		t.Fatalf("next_deadline = %v, want the delay timer %v", d.NextDeadline, delayUntil)
	}
	if d.ExpiresAt.Equal(*d.NextDeadline) {
		t.Fatal("expires_at and next_deadline collapsed into the same instant")
	}

	// Now stand at a moment past the delay timer but well before expiry — the
	// instant a single-column design gets wrong.
	between := delayUntil.Add(time.Minute)
	if d.Expired(between) {
		t.Fatal("a decision with a passed delay timer but a live expires_at was judged expired")
	}

	active, err := s.ActiveDecision(ctx, d.ID)
	if err != nil {
		t.Fatalf("ActiveDecision refused a live decision: %v", err)
	}
	if active.State != store.DecisionPending {
		t.Fatalf("state = %q, want pending", active.State)
	}

	// The sweeper, in contrast, does see it — with the kind that says why.
	var swept []store.Decision
	err = s.ClaimDue(ctx, between, 10, func(_ context.Context, _ pgx.Tx, due []store.Decision) error {
		swept = due
		return nil
	})
	if err != nil {
		t.Fatalf("claim due: %v", err)
	}
	if len(swept) != 1 {
		t.Fatalf("sweeper claimed %d decisions, want 1", len(swept))
	}
	if swept[0].NextDeadlineKind != store.DeadlineChallenge {
		t.Fatalf("swept kind = %q, want %q — the sweeper must not expire a delayed decision",
			swept[0].NextDeadlineKind, store.DeadlineChallenge)
	}
}

func TestExpiredDecisionIsRefusedOnEntry(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")

	d := newDecision(t, s, w, -time.Minute)
	if !d.Expired(s.Now()) {
		t.Fatal("a decision whose expires_at has passed did not report as expired")
	}
	_, err := s.ActiveDecision(ctx, d.ID)
	if !errors.Is(err, store.ErrDecisionExpired) {
		t.Fatalf("ActiveDecision returned %v, want ErrDecisionExpired", err)
	}
}

func TestNextDeadlineNeverExceedsExpiry(t *testing.T) {
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")

	// A challenge timer beyond expiry cannot become the scheduler deadline: the
	// decision is over first.
	late := s.Now().Add(10 * time.Hour)
	d := newDecision(t, s, w, time.Hour, store.NewChallenge{
		Ordinal: 0, Kind: policy.ChallengeDelay, Deadline: &late,
	})
	if d.NextDeadlineKind != store.DeadlineExpiry {
		t.Fatalf("next_deadline_kind = %q, want %q", d.NextDeadlineKind, store.DeadlineExpiry)
	}
	if d.NextDeadline == nil || !d.NextDeadline.Equal(d.ExpiresAt) {
		t.Fatalf("next_deadline = %v, want expires_at %v", d.NextDeadline, d.ExpiresAt)
	}
}

// The database refuses a row that puts the scheduler deadline past expiry, so a
// writer that bypasses the storage API cannot create one either.
func TestDeadlineBoundIsEnforcedBySchema(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	d := newDecision(t, s, w, time.Hour)

	_, err := s.Pool().Exec(ctx,
		`UPDATE decisions SET next_deadline = expires_at + interval '1 hour' WHERE id = $1`, d.ID)
	if err == nil {
		t.Fatal("the schema accepted a next_deadline past expires_at")
	}
	if !strings.Contains(err.Error(), "decisions_deadline_bound_check") {
		t.Fatalf("error = %v, want the deadline bound constraint", err)
	}

	_, err = s.Pool().Exec(ctx,
		`UPDATE decisions SET next_deadline_kind = NULL WHERE id = $1`, d.ID)
	if err == nil {
		t.Fatal("the schema accepted a next_deadline with no kind")
	}
}

// Satisfying the challenge that owned the scheduler deadline hands it back to
// expiry, in the same statement that recomputes it.
func TestSatisfyingAChallengeMovesTheDeadlineBackToExpiry(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")

	delayUntil := s.Now().Add(5 * time.Minute)
	d := newDecision(t, s, w, time.Hour, store.NewChallenge{
		Ordinal: 0, Kind: policy.ChallengeDelay, Deadline: &delayUntil,
	})

	if err := w.SetChallengeState(ctx, d.ID, 0, store.ChallengeSatisfied, map[string]any{"by": "timer"}); err != nil {
		t.Fatalf("set challenge state: %v", err)
	}
	after, err := store.GetDecision(ctx, s.Pool(), d.ID)
	if err != nil {
		t.Fatalf("get decision: %v", err)
	}
	if after.NextDeadlineKind != store.DeadlineExpiry {
		t.Fatalf("next_deadline_kind = %q, want %q", after.NextDeadlineKind, store.DeadlineExpiry)
	}
	if !after.NextDeadline.Equal(after.ExpiresAt) {
		t.Fatalf("next_deadline = %v, want expires_at %v", after.NextDeadline, after.ExpiresAt)
	}

	progress, err := store.ChallengeProgressFor(ctx, s.Pool(), d.ID)
	if err != nil {
		t.Fatalf("challenge progress: %v", err)
	}
	if len(progress) != 1 || progress[0].State != store.ChallengeSatisfied || progress[0].SatisfiedAt == nil {
		t.Fatalf("progress = %+v, want one satisfied challenge with a timestamp", progress)
	}
}

// The policy version, the fact snapshot and the audit row are one transaction.
func TestDecisionPolicyVersionFactsAndAuditLandTogether(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")

	d := newDecision(t, s, w, time.Hour)

	stored, err := store.GetDecision(ctx, s.Pool(), d.ID)
	if err != nil {
		t.Fatalf("get decision: %v", err)
	}
	if stored.PolicyVersion != 1 || stored.PolicyID != "wire-transfer" {
		t.Fatalf("decision points at %s v%d, want wire-transfer v1", stored.PolicyID, stored.PolicyVersion)
	}
	var facts map[string]any
	if err := json.Unmarshal(stored.FactSnapshot, &facts); err != nil {
		t.Fatalf("fact snapshot is not JSON: %v", err)
	}
	if facts["risk_score"] != 0.42 {
		t.Fatalf("fact snapshot = %v, want the frozen risk score", facts)
	}

	var kind, subject, payload string
	err = s.Pool().QueryRow(ctx,
		`SELECT kind, subject, payload::text FROM audit_log WHERE writer_id = 'w0' ORDER BY seq DESC LIMIT 1`).
		Scan(&kind, &subject, &payload)
	if err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if kind != store.AuditKindDecisionCreated || subject != d.ID {
		t.Fatalf("audit row = (%q, %q), want a decision.created row for %s", kind, subject, d.ID)
	}
	if !strings.Contains(payload, `"policy_version": 1`) {
		t.Fatalf("audit payload %q does not record the policy version", payload)
	}
	if !strings.Contains(payload, "risk_score") {
		t.Fatalf("audit payload %q does not record the fact snapshot", payload)
	}
	if report := verifyChain(t, s); !report.OK() {
		t.Fatalf("chain broken after storing a decision: %v", report.Err())
	}
}

// If the audit append fails, the decision must not exist either. The append is
// the last write in the transaction, so this is the direction that proves they
// share one.
func TestDecisionRollsBackWhenTheAuditAppendFails(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	rec := seedPolicy(t, s, "wire-transfer")

	// Squat the sequence number the writer is about to use, so its append
	// collides on the primary key.
	if _, err := s.Pool().Exec(ctx, `
		INSERT INTO audit_log (writer_id, seq, prev_hash, hash, kind, subject, payload, recorded_at)
		VALUES ('w0', 1, decode(repeat('00',32),'hex'), decode(repeat('ab',32),'hex'),
		        'squatter', '', '{}'::jsonb, now())`); err != nil {
		t.Fatalf("squat sequence: %v", err)
	}

	id, err := store.NewDecisionID()
	if err != nil {
		t.Fatalf("new id: %v", err)
	}
	_, err = w.CreateDecision(ctx, store.NewDecision{
		ID:            id,
		CallerID:      "pep-1",
		PolicyID:      rec.ID,
		PolicyVersion: rec.Version,
		SubjectID:     "u1",
		ResourceID:    "acct-9",
		Action:        "transfer",
		FactSnapshot:  map[string]any{"risk_score": 0.9},
		ExpiresAt:     s.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatal("the decision was created even though its audit row could not be appended")
	}
	if !errors.Is(err, store.ErrChainConflict) {
		t.Fatalf("error = %v, want ErrChainConflict", err)
	}

	if _, err := store.GetDecision(ctx, s.Pool(), id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the decision row survived a failed audit append: %v", err)
	}

	// The writer refuses further work rather than silently forking the chain.
	// The squatted row is not one this writer could have written — it does not
	// hash to its own contents — so automatic reconciliation declines it and
	// only an operator's ReloadHead moves the head onto it.
	if _, err := w.Append(ctx, store.AuditEntry{Kind: "x", Payload: map[string]any{}}); !errors.Is(err, store.ErrChainConflict) {
		t.Fatalf("a conflicted writer kept appending: %v", err)
	}
	if err := w.ReloadHead(ctx); err != nil {
		t.Fatalf("reload head: %v", err)
	}
	if _, err := w.Append(ctx, store.AuditEntry{Kind: "x", Payload: map[string]any{}}); err != nil {
		t.Fatalf("append after reconciling the head: %v", err)
	}
}

func TestResolveDecisionIsTerminalAndAudited(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	d := newDecision(t, s, w, time.Hour)

	resolved, err := w.ResolveDecision(ctx, d.ID, store.DecisionAllowed,
		[]map[string]any{{"type": "notify"}}, "operator")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.State != store.DecisionAllowed || resolved.ResolvedAt == nil {
		t.Fatalf("resolved = %+v, want an allowed decision with a resolution time", resolved)
	}
	if resolved.NextDeadline != nil || resolved.NextDeadlineKind != "" {
		t.Fatal("a resolved decision still carries a scheduler deadline")
	}

	if _, err := w.ResolveDecision(ctx, d.ID, store.DecisionDenied, nil, "operator"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("re-resolving returned %v, want ErrConflict", err)
	}
	if report := verifyChain(t, s); !report.OK() {
		t.Fatalf("chain broken after resolving: %v", report.Err())
	}
}

func TestApprovalsAreDistinctPerApprover(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")

	deadline := s.Now().Add(30 * time.Minute)
	d := newDecision(t, s, w, time.Hour, store.NewChallenge{
		Ordinal: 0, Kind: policy.ChallengeQuorum, Deadline: &deadline,
	})

	var binding [32]byte
	binding[0] = 0xAA

	for _, approver := range []string{"alice", "bob"} {
		if _, err := w.RecordApproval(ctx, store.NewApproval{
			DecisionID: d.ID, ChallengeOrdinal: 0, ApproverID: approver,
			Verdict: store.VerdictApprove, BindingHash: binding,
		}); err != nil {
			t.Fatalf("record approval by %s: %v", approver, err)
		}
	}

	_, err := w.RecordApproval(ctx, store.NewApproval{
		DecisionID: d.ID, ChallengeOrdinal: 0, ApproverID: "alice",
		Verdict: store.VerdictApprove, BindingHash: binding,
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a repeated approval returned %v, want ErrConflict", err)
	}

	n, err := store.CountApprovals(ctx, s.Pool(), d.ID, 0, store.VerdictApprove)
	if err != nil {
		t.Fatalf("count approvals: %v", err)
	}
	if n != 2 {
		t.Fatalf("counted %d approvals, want 2", n)
	}
	if report := verifyChain(t, s); !report.OK() {
		t.Fatalf("chain broken after approvals: %v", report.Err())
	}
}

// Two sweepers must not both claim the same row.
func TestClaimDueSkipsLockedRows(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	newDecision(t, s, w, -time.Minute)

	now := s.Now()
	held := make(chan struct{})
	release := make(chan struct{})
	firstCount := make(chan int, 1)

	go func() {
		err := s.ClaimDue(ctx, now, 10, func(_ context.Context, _ pgx.Tx, due []store.Decision) error {
			firstCount <- len(due)
			close(held)
			// Hold the row locked until the second sweeper has had its turn.
			<-release
			return nil
		})
		if err != nil {
			t.Errorf("first sweeper: %v", err)
		}
	}()

	<-held
	if n := <-firstCount; n != 1 {
		t.Fatalf("first sweeper claimed %d rows, want 1", n)
	}

	var second int
	if err := s.ClaimDue(ctx, now, 10, func(_ context.Context, _ pgx.Tx, due []store.Decision) error {
		second = len(due)
		return nil
	}); err != nil {
		t.Fatalf("second sweeper: %v", err)
	}
	close(release)
	if second != 0 {
		t.Fatalf("the second sweeper claimed %d rows while the first held them, want 0", second)
	}
}
