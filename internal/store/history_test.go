package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// The audit console's query axes, its one sort order and its keyset cursor,
// against a real database. The two properties worth a test are the ones a page
// number cannot give: adjacent windows tile without overlap, and a page
// sequence stays correct while rows are inserted underneath it.

// seedDecision writes one decision with an explicit policy, subject and
// creation instant, so an axis can be asserted rather than inferred.
func seedDecision(t *testing.T, s *store.Store, w *store.AuditWriter, policyID, subject string, createdAt time.Time, challenges ...store.NewChallenge) store.Decision {
	t.Helper()
	ctx := context.Background()
	rec := seedPolicy(t, s, policyID, policy.Delay{Duration: time.Hour})
	d, err := w.CreateDecision(ctx, store.NewDecision{
		CallerID:      "pep-1",
		PolicyID:      rec.ID,
		PolicyVersion: rec.Version,
		SubjectID:     subject,
		ResourceID:    "acct-9",
		Action:        "transfer",
		Request:       map[string]any{"amount": 5000},
		FactSnapshot:  map[string]any{"risk_score": 0.42},
		ExpiresAt:     s.Now().Add(24 * time.Hour),
		Challenges:    challenges,
	})
	if err != nil {
		t.Fatalf("create decision: %v", err)
	}
	if !createdAt.IsZero() {
		// created_at defaults to now(); the history axis is a period, and a
		// period is only testable against rows that sit at known instants.
		if _, err := s.Pool().Exec(ctx, `UPDATE decisions SET created_at = $2 WHERE id = $1`, d.ID, createdAt); err != nil {
			t.Fatalf("backdate decision: %v", err)
		}
		d.CreatedAt = createdAt.UTC()
	}
	return d
}

func ids(page store.DecisionPage) []string {
	out := make([]string, 0, len(page.Decisions))
	for _, d := range page.Decisions {
		out = append(out, d.ID)
	}
	return out
}

func TestDecisionHistoryFiltersOnEachAxis(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	old := seedDecision(t, s, w, "wire", "alice", base)
	mid := seedDecision(t, s, w, "wire", "bob", base.Add(48*time.Hour))
	recent := seedDecision(t, s, w, "card", "alice", base.Add(96*time.Hour))

	all, err := store.ListDecisions(ctx, s.Pool(), store.DecisionQuery{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// The one sort order: newest first.
	if got := ids(all); len(got) != 3 || got[0] != recent.ID || got[2] != old.ID {
		t.Fatalf("the unfiltered history is %v, want newest first", got)
	}

	byPolicy, err := store.ListDecisions(ctx, s.Pool(), store.DecisionQuery{PolicyID: "wire"})
	if err != nil {
		t.Fatalf("list by policy: %v", err)
	}
	if got := ids(byPolicy); len(got) != 2 || got[0] != mid.ID {
		t.Errorf("the policy axis returned %v", got)
	}

	bySubject, err := store.ListDecisions(ctx, s.Pool(), store.DecisionQuery{SubjectID: "alice"})
	if err != nil {
		t.Fatalf("list by subject: %v", err)
	}
	if got := ids(bySubject); len(got) != 2 || got[0] != recent.ID {
		t.Errorf("the subject axis returned %v", got)
	}

	byState, err := store.ListDecisions(ctx, s.Pool(), store.DecisionQuery{State: store.DecisionPending})
	if err != nil {
		t.Fatalf("list by state: %v", err)
	}
	if len(byState.Decisions) != 3 {
		t.Errorf("the state axis returned %d pending decisions, want 3", len(byState.Decisions))
	}

	// Two axes at once narrow rather than widen.
	both, err := store.ListDecisions(ctx, s.Pool(), store.DecisionQuery{PolicyID: "wire", SubjectID: "alice"})
	if err != nil {
		t.Fatalf("list by two axes: %v", err)
	}
	if got := ids(both); len(got) != 1 || got[0] != old.ID {
		t.Errorf("policy+subject returned %v, want just the one row satisfying both", got)
	}
}

// The period is half-open, so an auditor paging month by month sees every
// decision exactly once. A closed interval would show a boundary row twice, and
// a double-counted decision in an audit is a wrong answer, not a cosmetic one.
func TestDecisionHistoryPeriodIsHalfOpenAndTiles(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	boundary := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)

	before := seedDecision(t, s, w, "wire", "alice", boundary.Add(-time.Hour))
	at := seedDecision(t, s, w, "wire", "alice", boundary)
	after := seedDecision(t, s, w, "wire", "alice", boundary.Add(time.Hour))

	first, err := store.ListDecisions(ctx, s.Pool(), store.DecisionQuery{
		From: boundary.Add(-24 * time.Hour), To: boundary,
	})
	if err != nil {
		t.Fatalf("list first window: %v", err)
	}
	second, err := store.ListDecisions(ctx, s.Pool(), store.DecisionQuery{
		From: boundary, To: boundary.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("list second window: %v", err)
	}

	if got := ids(first); len(got) != 1 || got[0] != before.ID {
		t.Errorf("the window ending at the boundary is %v, want only the row before it", got)
	}
	if got := ids(second); len(got) != 2 || got[1] != at.ID {
		t.Errorf("the window starting at the boundary is %v, want the boundary row and the one after", got)
	}
	_ = after
}

// Keyset pagination, and the property that motivates it: a row inserted ahead
// of the cursor between two page reads does not shift the sequence, duplicate a
// row or drop one. An OFFSET-paged history fails exactly here.
func TestDecisionHistoryPagesStablyWhileTheTableGrows(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	var seeded []string
	for i := range 5 {
		d := seedDecision(t, s, w, "wire", "alice", base.Add(time.Duration(i)*time.Hour))
		seeded = append([]string{d.ID}, seeded...) // newest first
	}

	first, err := store.ListDecisions(ctx, s.Pool(), store.DecisionQuery{Limit: 2})
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if got := ids(first); len(got) != 2 || got[0] != seeded[0] || got[1] != seeded[1] {
		t.Fatalf("first page is %v, want %v", got, seeded[:2])
	}
	if first.Next.Zero() {
		t.Fatal("a page with more rows behind it issued no cursor")
	}

	// The insert an OFFSET reader would be broken by: a new newest row.
	seedDecision(t, s, w, "wire", "alice", base.Add(99*time.Hour))

	second, err := store.ListDecisions(ctx, s.Pool(), store.DecisionQuery{Limit: 2, After: first.Next})
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if got := ids(second); len(got) != 2 || got[0] != seeded[2] || got[1] != seeded[3] {
		t.Fatalf("second page is %v, want %v — an insert ahead of the cursor shifted the sequence",
			got, seeded[2:4])
	}

	third, err := store.ListDecisions(ctx, s.Pool(), store.DecisionQuery{Limit: 2, After: second.Next})
	if err != nil {
		t.Fatalf("third page: %v", err)
	}
	if got := ids(third); len(got) != 1 || got[0] != seeded[4] {
		t.Fatalf("third page is %v, want the last seeded row", got)
	}
	if !third.Next.Zero() {
		t.Error("the last page issued a cursor")
	}
}

func TestDecisionCursorRoundTrips(t *testing.T) {
	t.Parallel()
	want := store.DecisionCursor{
		CreatedAt: time.Date(2026, 8, 9, 1, 2, 3, 456789000, time.UTC),
		ID:        "3f1b0f2a-0000-4000-8000-000000000001",
	}
	got, err := store.DecodeDecisionCursor(want.Encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || got.ID != want.ID {
		t.Fatalf("round trip gave %+v, want %+v", got, want)
	}
	if empty, err := store.DecodeDecisionCursor(""); err != nil || !empty.Zero() {
		t.Fatalf("an empty token is the first page, got %+v err %v", empty, err)
	}
	if _, err := store.DecodeDecisionCursor("not-a-cursor"); err == nil {
		t.Fatal("a malformed cursor decoded")
	}
}

func TestDecisionHistoryClampsThePage(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	seedDecision(t, s, w, "wire", "alice", time.Time{})

	page, err := store.ListDecisions(ctx, s.Pool(), store.DecisionQuery{Limit: store.MaxDecisionPageSize * 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Decisions) != 1 {
		t.Fatalf("got %d rows", len(page.Decisions))
	}
}

// The inbox candidate filter. It admits explicit membership and every
// claim-resolved set, and excludes a set that names somebody else — which is
// the narrowing the partial index exists for. The exact test belongs to
// challenge.isTarget and is asserted there.
func TestOpenQuorumChallengesAdmitsMembersAndClaimSets(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	now := s.Now()

	mine := seedDecision(t, s, w, "wire", "alice", time.Time{}, store.NewChallenge{
		Ordinal: 0, Kind: policy.ChallengeQuorum,
		Detail: map[string]any{"threshold": 2, "mode": "members", "issuer": "https://idp.test",
			"members": []string{"bob", "carol"}, "binding_hash": "aa"},
	})
	claimed := seedDecision(t, s, w, "card", "alice", time.Time{}, store.NewChallenge{
		Ordinal: 0, Kind: policy.ChallengeQuorum,
		Detail: map[string]any{"threshold": 1, "mode": "claim", "issuer": "https://idp.test",
			"claim": "can_approve", "binding_hash": "bb"},
	})
	theirs := seedDecision(t, s, w, "loan", "alice", time.Time{}, store.NewChallenge{
		Ordinal: 0, Kind: policy.ChallengeQuorum,
		Detail: map[string]any{"threshold": 1, "mode": "members", "issuer": "https://idp.test",
			"members": []string{"dave"}, "binding_hash": "cc"},
	})

	got, err := store.OpenQuorumChallenges(ctx, s.Pool(), "bob", now, 0)
	if err != nil {
		t.Fatalf("list open quorums: %v", err)
	}
	seen := map[string]store.OpenQuorumChallenge{}
	for _, item := range got {
		seen[item.Decision.ID] = item
	}
	if _, ok := seen[mine.ID]; !ok {
		t.Error("an explicit member was not offered their own decision")
	}
	if _, ok := seen[claimed.ID]; !ok {
		t.Error("a claim-resolved set was not offered as a candidate")
	}
	if _, ok := seen[theirs.ID]; ok {
		t.Error("a set naming somebody else was offered as a candidate")
	}
	if item := seen[mine.ID]; item.Approvals != 0 || item.Submitted {
		t.Errorf("an untouched challenge reports %d approvals, submitted=%v", item.Approvals, item.Submitted)
	}

	// After bob votes, the row stays — with the collection state moved.
	if _, err := w.RecordApproval(ctx, store.NewApproval{
		DecisionID: mine.ID, ChallengeOrdinal: 0, ApproverID: "bob", Verdict: store.VerdictApprove,
	}); err != nil {
		t.Fatalf("record approval: %v", err)
	}
	got, err = store.OpenQuorumChallenges(ctx, s.Pool(), "bob", now, 0)
	if err != nil {
		t.Fatalf("list open quorums: %v", err)
	}
	var after store.OpenQuorumChallenge
	for _, item := range got {
		if item.Decision.ID == mine.ID {
			after = item
		}
	}
	if after.Decision.ID == "" {
		t.Fatal("a challenge the approver voted on vanished from the inbox")
	}
	if after.Approvals != 1 || !after.Submitted {
		t.Errorf("after voting the row reports %d approvals, submitted=%v", after.Approvals, after.Submitted)
	}

	approvals, err := store.ApprovalsFor(ctx, s.Pool(), mine.ID)
	if err != nil {
		t.Fatalf("read approvals: %v", err)
	}
	if len(approvals) != 1 || approvals[0].ApproverID != "bob" {
		t.Fatalf("the approval record is %+v", approvals)
	}
}

// An expired decision is not waiting on anybody, and neither is a satisfied
// challenge. The inbox is a to-do list, not a history.
func TestOpenQuorumChallengesExcludesWhatCannotBeActedOn(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	detail := map[string]any{"threshold": 1, "mode": "members", "issuer": "https://idp.test",
		"members": []string{"bob"}, "binding_hash": "aa"}

	live := seedDecision(t, s, w, "wire", "alice", time.Time{}, store.NewChallenge{
		Ordinal: 0, Kind: policy.ChallengeQuorum, Detail: detail,
	})
	done := seedDecision(t, s, w, "card", "alice", time.Time{}, store.NewChallenge{
		Ordinal: 0, Kind: policy.ChallengeQuorum, Detail: detail,
	})
	if err := w.SetChallengeState(ctx, done.ID, 0, store.ChallengeSatisfied, detail); err != nil {
		t.Fatalf("satisfy challenge: %v", err)
	}

	got, err := store.OpenQuorumChallenges(ctx, s.Pool(), "bob", s.Now(), 0)
	if err != nil {
		t.Fatalf("list open quorums: %v", err)
	}
	if len(got) != 1 || got[0].Decision.ID != live.ID {
		t.Fatalf("the inbox is %v, want only the live challenge", ids(store.DecisionPage{
			Decisions: func() []store.Decision {
				out := make([]store.Decision, 0, len(got))
				for _, item := range got {
					out = append(out, item.Decision)
				}
				return out
			}(),
		}))
	}

	// The list also has to survive a decision whose expiry has passed.
	if _, err := s.Pool().Exec(ctx, `
		UPDATE decisions
		SET expires_at = now() - interval '1 hour',
			next_deadline = least(next_deadline, now() - interval '1 hour')
		WHERE id = $1`, live.ID); err != nil {
		t.Fatalf("expire decision: %v", err)
	}
	got, err = store.OpenQuorumChallenges(ctx, s.Pool(), "bob", s.Now(), 0)
	if err != nil {
		t.Fatalf("list open quorums: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("an expired decision is still in the inbox: %+v", got)
	}
}

// The store's read view is the same queries behind an interface, so the audit
// console can be tested without a database and still be wired to this.
func TestHistoryViewReadsWhatTheFunctionsRead(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	d := seedDecision(t, s, w, "wire", "alice", time.Time{})

	h := store.NewHistory(s.Pool())
	page, err := h.ListDecisions(ctx, store.DecisionQuery{})
	if err != nil || len(page.Decisions) != 1 {
		t.Fatalf("list through the view: %v %+v", err, page)
	}
	got, err := h.Decision(ctx, d.ID)
	if err != nil || got.ID != d.ID {
		t.Fatalf("read through the view: %v %+v", err, got)
	}
	record, err := h.PolicyVersion(ctx, d.PolicyID, d.PolicyVersion)
	if err != nil {
		t.Fatalf("policy version through the view: %v", err)
	}
	if record.Version != d.PolicyVersion {
		t.Errorf("the view returned version %d, want the frozen %d", record.Version, d.PolicyVersion)
	}
	var facts map[string]any
	if err := json.Unmarshal(got.FactSnapshot, &facts); err != nil {
		t.Fatalf("the frozen fact snapshot does not decode: %v", err)
	}
}
