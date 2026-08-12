package runtime

// oracle_test.go is the other half of #38, asserted where the bytes are real.
//
// The first half — "not authorised" and "does not exist" answer the same 404 —
// was fixed in the error table and tested against a stub error in
// internal/api/approvals_test.go. That test cannot see this one, and that is the
// point: a table that maps ErrNotTarget to 404 says nothing about whether a
// caller with no standing ever reaches ErrNotTarget. On the submission path they
// did not. The lifecycle asked "is this still collecting" first, so a stranger
// polling one identifier read 404 while the decision was pending and 409 the
// moment it resolved or expired — which is the existence oracle R40 forbids,
// plus the time it closed at, for free on the cancellation route that carries no
// rate limit.
//
// So this test drives a real console credential belonging to nobody at four
// decisions — one that does not exist, one pending, one resolved, one expired —
// over all three routes that answer through [api.approvalError], and asserts the
// response is the same bytes twelve times. It runs against the assembled process
// because every layer between the token and the row is part of what it is
// asserting: a stub that returns the error the test chose is a test of the
// mapping, and the mapping was never what was broken.
//
// The control at the bottom is the other half of the requirement. Collapsing the
// 409s into the 404 for everybody would pass the identity assertion and make the
// product worse: an approver who really is being waited on has to be able to
// tell "you are too late" from "there is nothing here". So the same two
// decisions are read again by the approver they name, and the two 409s have to
// still be there.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/store"
)

// missingDecisionID is well-formed and names nothing. The column is a uuid, so a
// made-up string would come back as a database error rather than as the refusal
// this test is about.
const missingDecisionID = "00000000-0000-4000-8000-000000000000"

// notFoundBody is the one answer every refusal on these routes gives.
const notFoundBody = `{"error":"not_found","message":"no such decision or challenge"}`

// answer is one response, kept whole. The assertion is about bytes, so the body
// is not decoded on the way in — a decoded body compares equal for two responses
// that differ in whitespace, key order or a field one of them does not have.
type answer struct {
	status int
	body   string
}

func (a answer) String() string { return fmt.Sprintf("%d %s", a.status, strings.TrimSpace(a.body)) }

// openClosure creates one decision pending on the seeded quorum.
func (h *harness) openClosure(t *testing.T) decision.Result {
	t.Helper()
	res, err := h.app.Decisions().Decide(context.Background(), decision.Request{
		Caller: &identity.Subject{Kind: identity.SubjectWorkload, Issuer: h.idp.server.URL, ID: "svc-ops"},
		Input: engine.Input{
			Action:   "close",
			Subject:  engine.Entity{Type: "account", ID: "acct-src", Attributes: map[string]any{"number": "1001"}},
			Resource: engine.Entity{Type: "account", ID: "acct-dst", Attributes: map[string]any{"amount": int64(5000)}},
		},
	})
	if err != nil {
		t.Fatalf("open a gated decision: %v", err)
	}
	if !res.Pending() {
		t.Fatalf("the decision is %s, want it pending on its quorum", res.State)
	}
	return res
}

// age moves a decision's own deadline into the past.
//
// It is a write rather than a short TTL and a sleep because the assertion below
// is about a byte comparison and not about timing: a test that waits for a
// deadline is a test that fails on a loaded machine for a reason that has
// nothing to do with what it asserts. The scheduler column moves with it —
// next_deadline is a minimum that includes expires_at and the table refuses a
// row where it is not — and stays NULL if it was NULL.
func (h *harness) age(t *testing.T, decisionID string) {
	t.Helper()
	past := time.Now().UTC().Add(-time.Hour)
	_, err := h.app.Store().Pool().Exec(context.Background(), `
		UPDATE decisions
		   SET expires_at    = $2::timestamptz,
		       next_deadline = CASE WHEN next_deadline IS NULL THEN NULL ELSE $2::timestamptz END
		 WHERE id = $1`, decisionID, past)
	if err != nil {
		t.Fatalf("age decision %s: %v", decisionID, err)
	}
}

func (h *harness) ask(method, path, token string) answer {
	code, body := h.do(method, api.SurfaceConsole, path, token, "", nil)
	return answer{status: code, body: string(body)}
}

// TestAStrangerReadsOneAnswerWhateverTheDecisionIsDoing is R40 stated as the
// property a caller can actually test from outside: with no standing, the four
// states of a decision are one response.
func TestAStrangerReadsOneAnswerWhateverTheDecisionIsDoing(t *testing.T) {
	h := newHarness(t, harnessOptions{writerID: "oracle-writer"})
	h.seed(tenantSchema(), closurePolicy("closure", 1, "alice"))

	alice := h.idp.user(t, "alice")
	// mallory holds a valid console credential and is named by nothing: not the
	// creator of any decision, not in any approver set. Every console endpoint is
	// reachable to her, which is what makes this a test rather than a mount table.
	mallory := h.idp.user(t, "mallory")

	pending := h.openClosure(t)

	resolved := h.openClosure(t)
	if code, body := h.approve(t, resolved.ID, alice); code != http.StatusOK {
		t.Fatalf("alice's approval = %d: %s", code, body)
	}
	if state := h.decisionState(resolved.ID); state != store.DecisionAllowed {
		t.Fatalf("the decision is %s after its quorum, want allowed", state)
	}

	expired := h.openClosure(t)
	h.age(t, expired.ID)

	states := []struct{ name, id string }{
		{"a decision that does not exist", missingDecisionID},
		{"a pending decision", pending.ID},
		{"a resolved decision", resolved.ID},
		{"an expired decision", expired.ID},
	}
	routes := []struct{ name, method, path string }{
		{"the submission", http.MethodPost, "/decisions/%s/challenges/0/approvals"},
		{"the approval screen", http.MethodGet, "/decisions/%s/challenges/0/approval"},
		{"the cancellation", http.MethodPost, "/decisions/%s/challenges/0/cancellation"},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			var first answer
			for i, state := range states {
				got := h.ask(route.method, fmt.Sprintf(route.path, state.id), mallory)
				if i == 0 {
					first = got
					if got.status != http.StatusNotFound || strings.TrimSpace(got.body) != notFoundBody {
						t.Fatalf("%s answers %s for %s, want 404 %s",
							route.name, got, state.name, notFoundBody)
					}
					continue
				}
				if got != first {
					t.Errorf("%s answers %s for %s and %s for %s.\n"+
						"the difference is an existence oracle: one identifier, two requests, and a "+
						"caller with no standing learns that the decision is real and when it stopped "+
						"being open. every refusal on this route has to be the same bytes.",
						route.name, first, states[0].name, got, state.name)
				}
			}
		})
	}

	// The cost of the answer above is paid by nobody who has standing. These two
	// are the same two decisions, read by the approver they actually name, and
	// the distinctions have to survive: an approver who arrives late is told
	// which kind of late it was.
	t.Run("an approver with standing still learns why", func(t *testing.T) {
		for _, tc := range []struct {
			name, id, code string
		}{
			{"a decision that already resolved", resolved.ID, "not_collecting"},
			{"a decision that expired", expired.ID, "expired"},
		} {
			got := h.ask(http.MethodPost, fmt.Sprintf("/decisions/%s/challenges/0/approvals", tc.id), alice)
			if got.status != http.StatusConflict || !strings.Contains(got.body, `"`+tc.code+`"`) {
				t.Errorf("alice submitting to %s = %s, want 409 %s: folding this into the stranger's "+
					"404 would protect nothing and cost the approver the reason", tc.name, got, tc.code)
			}
		}
		// And the read the console makes before the submission answers the same
		// way, for the same person.
		got := h.ask(http.MethodGet, fmt.Sprintf("/decisions/%s/challenges/0/approval", expired.ID), alice)
		if got.status != http.StatusConflict || !strings.Contains(got.body, `"expired"`) {
			t.Errorf("alice reading the approval screen of an expired decision = %s, want 409 expired", got)
		}
	})

	t.Run("the refusals are in the chain and the chain still verifies", func(t *testing.T) {
		refusals := h.auditPayloads(decision.AuditKindAccessRefused)
		if len(refusals) == 0 {
			t.Error("no access refusal reached the audit chain: a caller turned away from a decision " +
				"that exists is a thing an operator has to be able to see")
		}
		h.verifyChain()
	})
}
