package revision_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/d0lim/stamp/internal/policy/revision"
)

// Break-glass is the only route back from the lock, so both halves of its
// contract are tested: that it refuses while anything is running, and that when
// it does run it leaves the loudest record the chain has.

// A live audit-writer claim means a stamp process is talking to this database,
// wherever it is running from.
func TestBreakGlassRefusesWhileAnInstanceHoldsItsWriter(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.lock(2, "a", "b", "c")

	_, err := revision.BreakGlass(context.Background(), revision.BreakGlassConfig{
		Store: h.store, Actor: "operator", Reason: "the approvers left the company",
	})
	if !errors.Is(err, revision.ErrListenersRunning) {
		t.Fatalf("err = %v, want %v", err, revision.ErrListenersRunning)
	}
	if got := h.mode(); got != revision.ModeQuorum {
		t.Fatalf("mode = %q, want the lock to be intact", got)
	}
}

// A bound listen address catches an instance that is starting up and has not
// claimed a writer yet.
func TestBreakGlassRefusesWhileAListenAddressIsBound(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.lock(2, "a", "b", "c")
	h.releaseWriter()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind a stand-in listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	_, err = revision.BreakGlass(context.Background(), revision.BreakGlassConfig{
		Store: h.store, Actor: "operator", Reason: "incident",
		Addresses: []string{ln.Addr().String()},
	})
	if !errors.Is(err, revision.ErrListenersRunning) {
		t.Fatalf("err = %v, want %v", err, revision.ErrListenersRunning)
	}
	if got := h.mode(); got != revision.ModeQuorum {
		t.Fatalf("mode = %q, want the lock to be intact", got)
	}
}

func TestBreakGlassResetsGovernanceAndLeavesTheLoudestRecord(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.lock(2, "a", "b", "c")
	h.releaseWriter()

	result, err := revision.BreakGlass(context.Background(), revision.BreakGlassConfig{
		Store: h.store, Actor: "operator", Reason: "two of three approvers left the company",
		Instance: "laptop", Addresses: []string{"127.0.0.1:0"},
	})
	if err != nil {
		t.Fatalf("break-glass: %v", err)
	}
	if result.Token == "" {
		t.Fatal("break-glass issued no bootstrap token, leaving no way back in")
	}
	if got := h.mode(); got != revision.ModeSolo {
		t.Fatalf("mode = %q, want %q", got, revision.ModeSolo)
	}

	rows := h.auditPayloadsFor(revision.AuditKindGovernanceReset, revision.GovernancePolicyID)
	if len(rows) != 1 {
		t.Fatalf("audit holds %d reset rows, want 1", len(rows))
	}
	if rows[0][revision.SeverityKey] != revision.SeverityCritical {
		t.Fatalf("reset severity = %v, want %q", rows[0][revision.SeverityKey], revision.SeverityCritical)
	}
	if rows[0]["reason"] != "two of three approvers left the company" {
		t.Fatalf("reset reason = %v, want it recorded verbatim", rows[0]["reason"])
	}
	if rows[0]["actor"] != "operator" {
		t.Fatalf("reset actor = %v, want the operator's name", rows[0]["actor"])
	}
	h.verifyChain()

	// The fresh token is live, and the old lock is gone: the installation can be
	// locked again.
	h.token = result.Token
	h.reclaimWriter()
	h.lock(1, "a", "b")
	if got := h.mode(); got != revision.ModeQuorum {
		t.Fatalf("mode after re-locking = %q, want %q", got, revision.ModeQuorum)
	}
	h.verifyChain()
}

// Break-glass names an operator and a reason, and refuses without either. It is
// not a security control — the liveness check and the audit row are — but a
// reset nobody has to answer for is a reset that happens by reflex.
func TestBreakGlassRequiresAnOperatorAndAReason(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.releaseWriter()

	for name, cfg := range map[string]revision.BreakGlassConfig{
		"no actor":  {Store: h.store, Reason: "incident"},
		"no reason": {Store: h.store, Actor: "operator"},
		"no store":  {Actor: "operator", Reason: "incident"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := revision.BreakGlass(context.Background(), cfg); err == nil {
				t.Fatal("break-glass ran without the details it records")
			}
		})
	}
}

// A reset against an installation that never installed governance has nothing
// to reset, and says so rather than inventing a policy.
func TestBreakGlassNeedsAnInstalledGovernancePolicy(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.releaseWriter()
	if _, err := h.store.Pool().Exec(context.Background(),
		`UPDATE policies SET superseded_at = now() WHERE id = $1`, revision.GovernancePolicyID); err != nil {
		t.Fatalf("remove the governance policy: %v", err)
	}
	_, err := revision.BreakGlass(context.Background(), revision.BreakGlassConfig{
		Store: h.store, Actor: "operator", Reason: "incident",
	})
	if !errors.Is(err, revision.ErrNotInstalled) {
		t.Fatalf("err = %v, want %v", err, revision.ErrNotInstalled)
	}
}

// A sanity check that the reset really is the solo-admin policy and not merely
// a new version of the locked one.
func TestBreakGlassLeavesNoQuorumOnTheReservedPolicy(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.lock(2, "a", "b", "c")
	h.releaseWriter()

	if _, err := revision.BreakGlass(context.Background(), revision.BreakGlassConfig{
		Store: h.store, Actor: "operator", Reason: "incident",
	}); err != nil {
		t.Fatalf("break-glass: %v", err)
	}
	p, live := h.effective(revision.GovernancePolicyID)
	if !live {
		t.Fatal("the reserved policy is gone")
	}
	if q, has := revision.GovernanceQuorum(p); has {
		t.Fatalf("the reset policy still demands a quorum of %d", q.Threshold)
	}
	if len(p.Challenges) != 0 {
		t.Fatalf("the reset policy still carries %d challenge(s)", len(p.Challenges))
	}
}
