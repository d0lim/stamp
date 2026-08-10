package challenge_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

var testNow = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

// quorumFixture is a migrated database with one pending decision carrying one
// quorum challenge, and the handler that opened it.
type quorumFixture struct {
	t        *testing.T
	store    *store.Store
	writer   *store.AuditWriter
	handler  *challenge.Quorum
	idp      *mockIdP
	decision store.Decision
	context  challenge.DecisionContext
	detail   json.RawMessage
	instance challenge.Instance
}

func newQuorumFixture(t *testing.T, spec policy.Quorum) *quorumFixture {
	t.Helper()
	ctx := context.Background()
	s := openStore(t, func() time.Time { return testNow })
	w := claimWriter(t, s, "quorum-1")
	policyVersion := seedPolicy(t, s, "high-value-transfer")

	handler, err := challenge.NewQuorum(challenge.QuorumConfig{Audit: w, DB: s.Pool()})
	if err != nil {
		t.Fatalf("new quorum handler: %v", err)
	}

	id, err := store.NewDecisionID()
	if err != nil {
		t.Fatalf("new decision id: %v", err)
	}
	decisionCtx := challenge.DecisionContext{
		DecisionID:   id,
		CallerID:     "workload:https://idp.test#payments",
		SubjectID:    "alice",
		ResourceID:   "acct-1",
		Action:       "transfer",
		PolicyID:     "high-value-transfer",
		Request:      json.RawMessage(`{"action":"transfer","subject":{"id":"alice","type":"user"}}`),
		FactSnapshot: json.RawMessage(`{"risk_score(alice)":72}`),
		Obligations:  json.RawMessage(`[{"type":"notify","attributes":{"channel":"#sec"}}]`),
		CreatedAt:    testNow,
		ExpiresAt:    testNow.Add(time.Hour),
	}
	instance := challenge.Instance{DecisionID: id, Ordinal: 0, Kind: policy.ChallengeQuorum}

	issued, err := handler.Issue(ctx, challenge.IssueRequest{
		Instance: instance,
		Spec:     spec,
		Decision: decisionCtx,
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("issue quorum: %v", err)
	}

	created, err := w.CreateDecision(ctx, store.NewDecision{
		ID:            id,
		CallerID:      decisionCtx.CallerID,
		PolicyID:      decisionCtx.PolicyID,
		PolicyVersion: policyVersion,
		SubjectID:     decisionCtx.SubjectID,
		ResourceID:    decisionCtx.ResourceID,
		Action:        decisionCtx.Action,
		Request:       decisionCtx.Request,
		FactSnapshot:  decisionCtx.FactSnapshot,
		Obligations:   decisionCtx.Obligations,
		ExpiresAt:     decisionCtx.ExpiresAt,
		Challenges: []store.NewChallenge{{
			Ordinal:  0,
			Kind:     policy.ChallengeQuorum,
			Deadline: issued.Deadline,
			Detail:   issued.Detail,
		}},
	})
	if err != nil {
		t.Fatalf("create decision: %v", err)
	}

	progress, err := store.ChallengeProgressFor(ctx, s.Pool(), id)
	if err != nil {
		t.Fatalf("read challenge progress: %v", err)
	}
	if len(progress) != 1 {
		t.Fatalf("expected one challenge, got %d", len(progress))
	}

	// The frozen context is re-read from the row rather than reused, because
	// that is what the lifecycle hands a handler at submit time: the JSON has
	// been through the database, and a hash computed over the bytes as issued
	// would not be the hash computed over the bytes as stored.
	stored := challenge.DecisionContext{
		DecisionID:   created.ID,
		CallerID:     created.CallerID,
		SubjectID:    created.SubjectID,
		ResourceID:   created.ResourceID,
		Action:       created.Action,
		PolicyID:     created.PolicyID,
		Request:      created.Request,
		FactSnapshot: created.FactSnapshot,
		Obligations:  created.Obligations,
		CreatedAt:    created.CreatedAt,
		ExpiresAt:    created.ExpiresAt,
	}

	return &quorumFixture{
		t:        t,
		store:    s,
		writer:   w,
		handler:  handler,
		idp:      newMockIdP(t),
		decision: created,
		context:  stored,
		detail:   progress[0].Detail,
		instance: instance,
	}
}

func (f *quorumFixture) submit(submitter *identity.Subject, payload string) (challenge.SubmitResult, error) {
	f.t.Helper()
	var raw json.RawMessage
	if payload != "" {
		raw = json.RawMessage(payload)
	}
	return f.handler.Submit(context.Background(), challenge.SubmitRequest{
		Instance:  f.instance,
		Decision:  f.context,
		Detail:    f.detail,
		Submitter: submitter,
		Payload:   raw,
		Now:       testNow,
	})
}

func (f *quorumFixture) status() challenge.Status {
	f.t.Helper()
	st, err := f.handler.Status(context.Background(), challenge.StatusRequest{
		Instance: f.instance,
		Decision: f.context,
		Detail:   f.detail,
		Stored:   challenge.StatePending,
		Now:      testNow,
	})
	if err != nil {
		f.t.Fatalf("status: %v", err)
	}
	return st
}

func (f *quorumFixture) storedDetail() challenge.QuorumDetail {
	f.t.Helper()
	var d challenge.QuorumDetail
	if err := json.Unmarshal(f.detail, &d); err != nil {
		f.t.Fatalf("decode stored detail %s: %v", f.detail, err)
	}
	return d
}

// approvals reads the rows the handler wrote, which is the only place a binding
// hash is durable.
func (f *quorumFixture) approvals() []store.Approval {
	f.t.Helper()
	rows, err := f.store.Pool().Query(context.Background(), `
		SELECT id, decision_id, challenge_ordinal, approver_id, verdict, binding_hash, detail::text, submitted_at
		FROM approvals WHERE decision_id = $1 ORDER BY submitted_at, approver_id`, f.instance.DecisionID)
	if err != nil {
		f.t.Fatalf("read approvals: %v", err)
	}
	defer rows.Close()
	var out []store.Approval
	for rows.Next() {
		var (
			a       store.Approval
			hash    []byte
			detail  string
			verdict string
		)
		if err := rows.Scan(&a.ID, &a.DecisionID, &a.ChallengeOrdinal, &a.ApproverID, &verdict,
			&hash, &detail, &a.SubmittedAt); err != nil {
			f.t.Fatalf("scan approval: %v", err)
		}
		a.Verdict = verdict
		a.Detail = json.RawMessage(detail)
		copy(a.BindingHash[:], hash)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatalf("read approvals: %v", err)
	}
	return out
}

func membersQuorum(threshold int, members ...string) policy.Quorum {
	return policy.Quorum{Threshold: threshold, Approvers: policy.ApproverSet{Members: members}}
}

func claimQuorum(threshold int, claim string) policy.Quorum {
	return policy.Quorum{Threshold: threshold, Approvers: policy.ApproverSet{Claim: claim}}
}

// ---------------------------------------------------------------------------
// the four scenarios the unit fixes
// ---------------------------------------------------------------------------

// A quorum a single approver can meet by submitting twice is not a quorum.
func TestDuplicateApprovalCountsOnce(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(2, "bob", "carol"))
	bob := f.idp.user(t, "bob", nil)

	first, err := f.submit(bob, "")
	if err != nil {
		t.Fatalf("first submission: %v", err)
	}
	if first.Have != 1 || first.Need != 2 || first.State != challenge.StatePending {
		t.Fatalf("first submission reported %d/%d %s, want 1/2 pending", first.Have, first.Need, first.State)
	}

	second, err := f.submit(bob, "")
	if err != nil {
		t.Fatalf("second submission from the same approver must be idempotent, got: %v", err)
	}
	if second.Have != 1 {
		t.Fatalf("second submission from bob counted %d approvals, want 1", second.Have)
	}
	if second.State != challenge.StatePending {
		t.Fatalf("bob alone moved the challenge to %s, want it to stay pending", second.State)
	}
	if got := f.status().Have; got != 1 {
		t.Fatalf("status recomputed %d approvals, want 1", got)
	}
	if got := len(f.approvals()); got != 1 {
		t.Fatalf("stored %d approval rows for one approver, want 1", got)
	}

	// A second, distinct approver is what actually closes it.
	carol := f.idp.user(t, "carol", nil)
	third, err := f.submit(carol, "")
	if err != nil {
		t.Fatalf("carol's submission: %v", err)
	}
	if third.Have != 2 || third.State != challenge.StateSatisfied {
		t.Fatalf("two distinct approvers reported %d/%d %s, want 2/2 satisfied",
			third.Have, third.Need, third.State)
	}
}

// Under claim resolution the token has to carry the claim. A token that does
// not is refused, and refused as ErrNotTarget so the lifecycle audits it.
func TestClaimResolutionRefusesATokenWithoutTheClaim(t *testing.T) {
	f := newQuorumFixture(t, claimQuorum(1, "stamp_approver"))

	member := f.idp.user(t, "bob", map[string]any{"stamp_approver": true})
	if _, err := f.submit(member, ""); err != nil {
		t.Fatalf("a token carrying the claim must be accepted, got: %v", err)
	}

	for _, tc := range []struct {
		name  string
		extra map[string]any
	}{
		{name: "claim absent", extra: nil},
		{name: "claim present but false", extra: map[string]any{"stamp_approver": false}},
		{name: "claim present but empty", extra: map[string]any{"stamp_approver": []any{}}},
		{name: "claim present but null", extra: map[string]any{"stamp_approver": nil}},
		{name: "a different claim", extra: map[string]any{"stamp_reader": true}},
	} {
		outsider := f.idp.user(t, "mallory-"+tc.name, tc.extra)
		if _, err := f.submit(outsider, ""); !errors.Is(err, challenge.ErrNotTarget) {
			t.Fatalf("%s: want ErrNotTarget, got %v", tc.name, err)
		}
	}

	if got := len(f.approvals()); got != 1 {
		t.Fatalf("stored %d approval rows, want only the one from the token carrying the claim", got)
	}
}

// A submission from outside the resolved set is refused, and refused with the
// sentinel the lifecycle turns into an audited access refusal.
func TestSubmissionFromANonTargetIsRefusedAndAuditable(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(1, "bob", "carol"))

	mallory := f.idp.user(t, "mallory", nil)
	_, err := f.submit(mallory, "")
	if !errors.Is(err, challenge.ErrNotTarget) {
		t.Fatalf("submission from outside the approver set: want ErrNotTarget, got %v", err)
	}
	if got := len(f.approvals()); got != 0 {
		t.Fatalf("a refused submission wrote %d approval rows, want none", got)
	}
	if got := f.status().Have; got != 0 {
		t.Fatalf("a refused submission moved the count to %d, want 0", got)
	}

	// A workload credential is never an approver, even when its subject
	// identifier happens to be spelled like a listed one.
	svc := f.idp.workload(t, "bob")
	if _, err := f.submit(svc, ""); !errors.Is(err, challenge.ErrNotTarget) {
		t.Fatalf("workload credential named like an approver: want ErrNotTarget, got %v", err)
	}
	if got := len(f.approvals()); got != 0 {
		t.Fatalf("a workload submission wrote %d approval rows, want none", got)
	}
}

// The approver identity is the token's `sub`, never a request body field.
func TestApproverIdentityComesFromTheTokenNotTheBody(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(1, "bob"))

	mallory := f.idp.user(t, "mallory", nil)
	if _, err := f.submit(mallory, `{"approver":"bob"}`); err == nil {
		t.Fatal("a submission naming another approver in its body was accepted")
	} else if !errors.Is(err, challenge.ErrInvalidPayload) && !errors.Is(err, challenge.ErrNotTarget) {
		t.Fatalf("want ErrInvalidPayload or ErrNotTarget, got %v", err)
	}
	if got := len(f.approvals()); got != 0 {
		t.Fatalf("stored %d approval rows, want none", got)
	}

	bob := f.idp.user(t, "bob", nil)
	if _, err := f.submit(bob, ""); err != nil {
		t.Fatalf("bob's own submission: %v", err)
	}
	rows := f.approvals()
	if len(rows) != 1 {
		t.Fatalf("stored %d approval rows, want 1", len(rows))
	}
	if rows[0].ApproverID != "bob" {
		t.Fatalf("approval recorded approver %q, want the token's sub %q", rows[0].ApproverID, "bob")
	}
}

// R31: the hash stored with the approval is the hash the server handed the
// approver to review.
func TestStoredBindingHashIsTheHashHandedToTheApprover(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(1, "bob"))
	bob := f.idp.user(t, "bob", nil)

	review, err := f.handler.Review(context.Background(), challenge.QuorumReviewRequest{
		DecisionID: f.instance.DecisionID,
		Ordinal:    f.instance.Ordinal,
		Subject:    bob,
		Now:        testNow,
	})
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	if review.BindingHash == "" {
		t.Fatal("the review handed the approver no binding hash")
	}
	if review.BindingHash != f.storedDetail().BindingHash {
		t.Fatalf("review hash %q differs from the hash frozen at issue %q",
			review.BindingHash, f.storedDetail().BindingHash)
	}

	if _, err := f.submit(bob, ""); err != nil {
		t.Fatalf("submit: %v", err)
	}
	rows := f.approvals()
	if len(rows) != 1 {
		t.Fatalf("stored %d approval rows, want 1", len(rows))
	}
	if got := hex.EncodeToString(rows[0].BindingHash[:]); got != review.BindingHash {
		t.Fatalf("stored binding hash %s, but the approver was handed %s", got, review.BindingHash)
	}
}

// ---------------------------------------------------------------------------
// binding hash composition (R31)
// ---------------------------------------------------------------------------

func baseContext() challenge.DecisionContext {
	return challenge.DecisionContext{
		DecisionID:   "d-1",
		CallerID:     "workload:https://idp.test#payments",
		SubjectID:    "alice",
		ResourceID:   "acct-1",
		Action:       "transfer",
		PolicyID:     "high-value-transfer",
		Request:      json.RawMessage(`{"action":"transfer","subject":{"id":"alice"}}`),
		FactSnapshot: json.RawMessage(`{"risk":72}`),
		Obligations:  json.RawMessage(`[{"type":"notify"}]`),
		CreatedAt:    testNow,
		ExpiresAt:    testNow.Add(time.Hour),
	}
}

func hashOf(t *testing.T, dec challenge.DecisionContext, detail challenge.QuorumDetail) string {
	t.Helper()
	sum, err := challenge.ApprovalBindingHash(dec, detail)
	if err != nil {
		t.Fatalf("binding hash: %v", err)
	}
	return hex.EncodeToString(sum[:])
}

func membersDetail(threshold int, members ...string) challenge.QuorumDetail {
	return challenge.QuorumDetail{
		Threshold: threshold,
		Mode:      challenge.ResolveMembers,
		Members:   members,
	}
}

// The threshold is excluded so that a revision raising only the quorum number
// does not evaporate the approvals already collected (R31).
func TestBindingHashIgnoresTheThreshold(t *testing.T) {
	t.Parallel()
	dec := baseContext()
	if hashOf(t, dec, membersDetail(2, "bob", "carol")) != hashOf(t, dec, membersDetail(3, "bob", "carol")) {
		t.Fatal("raising the threshold changed the binding hash")
	}
}

// The approver set is a set: its order is not part of the material.
func TestBindingHashIgnoresApproverOrder(t *testing.T) {
	t.Parallel()
	dec := baseContext()
	if hashOf(t, dec, membersDetail(2, "bob", "carol")) != hashOf(t, dec, membersDetail(2, "carol", "bob")) {
		t.Fatal("reordering the approver list changed the binding hash")
	}
}

// The lifetime of a decision is not a term of the authorization, and expires_at
// is still moving while challenges are being issued.
func TestBindingHashIgnoresTheDecisionLifetime(t *testing.T) {
	t.Parallel()
	dec := baseContext()
	longer := baseContext()
	longer.ExpiresAt = longer.ExpiresAt.Add(24 * time.Hour)
	longer.CreatedAt = longer.CreatedAt.Add(-time.Minute)
	if hashOf(t, dec, membersDetail(2, "bob")) != hashOf(t, longer, membersDetail(2, "bob")) {
		t.Fatal("a different decision lifetime changed the binding hash")
	}
}

// Everything R31 does list changes it.
func TestBindingHashCoversTheReviewedMaterial(t *testing.T) {
	t.Parallel()
	base := hashOf(t, baseContext(), membersDetail(2, "bob", "carol"))

	for _, tc := range []struct {
		name   string
		mutate func(*challenge.DecisionContext)
		detail challenge.QuorumDetail
	}{
		{name: "decision id", mutate: func(d *challenge.DecisionContext) { d.DecisionID = "d-2" }},
		{name: "caller", mutate: func(d *challenge.DecisionContext) { d.CallerID = "workload:https://idp.test#other" }},
		{name: "subject", mutate: func(d *challenge.DecisionContext) { d.SubjectID = "eve" }},
		{name: "resource", mutate: func(d *challenge.DecisionContext) { d.ResourceID = "acct-2" }},
		{name: "action", mutate: func(d *challenge.DecisionContext) { d.Action = "close" }},
		{name: "policy", mutate: func(d *challenge.DecisionContext) { d.PolicyID = "other-policy" }},
		{name: "request", mutate: func(d *challenge.DecisionContext) {
			d.Request = json.RawMessage(`{"action":"transfer","subject":{"id":"eve"}}`)
		}},
		{name: "fact snapshot", mutate: func(d *challenge.DecisionContext) {
			d.FactSnapshot = json.RawMessage(`{"risk":91}`)
		}},
		{name: "obligations", mutate: func(d *challenge.DecisionContext) {
			d.Obligations = json.RawMessage(`[{"type":"notify"},{"type":"log"}]`)
		}},
		{name: "approver set", detail: membersDetail(2, "bob", "dave")},
		{name: "resolution mode", detail: challenge.QuorumDetail{
			Threshold: 2, Mode: challenge.ResolveClaim, Claim: "stamp_approver",
		}},
	} {
		dec := baseContext()
		detail := tc.detail
		if detail.Mode == "" {
			detail = membersDetail(2, "bob", "carol")
		}
		if tc.mutate != nil {
			tc.mutate(&dec)
		}
		if got := hashOf(t, dec, detail); got == base {
			t.Errorf("changing the %s left the binding hash unchanged", tc.name)
		}
	}
}

// The hash must survive a round trip through the database, because that is the
// only way the hash computed at issue and the hash computed at submit are the
// same number.
func TestBindingHashSurvivesJSONCanonicalization(t *testing.T) {
	t.Parallel()
	dec := baseContext()
	reordered := baseContext()
	reordered.Request = json.RawMessage("{\n  \"subject\": {\"id\": \"alice\"},\n  \"action\": \"transfer\"\n}")
	if hashOf(t, dec, membersDetail(2, "bob")) != hashOf(t, reordered, membersDetail(2, "bob")) {
		t.Fatal("re-serialized JSON with the same content produced a different binding hash")
	}
}

// ---------------------------------------------------------------------------
// issue, status and the group-source seam
// ---------------------------------------------------------------------------

func TestIssueFreezesTheResolvedTermsAndTheHash(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(2, "carol", "bob", "bob"))

	detail := f.storedDetail()
	if detail.Threshold != 2 {
		t.Fatalf("frozen threshold %d, want 2", detail.Threshold)
	}
	if detail.Mode != challenge.ResolveMembers {
		t.Fatalf("frozen mode %q, want %q", detail.Mode, challenge.ResolveMembers)
	}
	if len(detail.Members) != 2 || detail.Members[0] != "bob" || detail.Members[1] != "carol" {
		t.Fatalf("frozen members %v, want the deduplicated set in a stable order", detail.Members)
	}
	if _, err := hex.DecodeString(detail.BindingHash); err != nil || detail.BindingHash == "" {
		t.Fatalf("frozen binding hash %q is not a hex digest: %v", detail.BindingHash, err)
	}
}

// R18's third mode is a seam, not an implementation. A policy that reaches for
// it must fail at issue rather than open a challenge nothing can satisfy.
func TestGroupSourceApproverSetIsRefusedUntilItsResolverArrives(t *testing.T) {
	t.Parallel()
	handler, err := challenge.NewQuorum(challenge.QuorumConfig{})
	if err != nil {
		t.Fatalf("new quorum handler: %v", err)
	}
	_, err = handler.Issue(context.Background(), challenge.IssueRequest{
		Instance: challenge.Instance{DecisionID: "d-1", Kind: policy.ChallengeQuorum},
		Spec: policy.Quorum{Threshold: 2, Approvers: policy.ApproverSet{
			Source: &policy.SourceRef{Name: "finance_approvers"},
		}},
		Decision: baseContext(),
		Now:      testNow,
	})
	if !errors.Is(err, challenge.ErrGroupSourceUnsupported) {
		t.Fatalf("want ErrGroupSourceUnsupported, got %v", err)
	}
	if !errors.Is(err, challenge.ErrUnsupportedSpec) {
		t.Fatalf("a group-source approver set must also read as an unsupported spec, got %v", err)
	}
}

// An approver set that cannot reach the threshold is a decision that can never
// resolve, so it is refused where it is declared rather than where it stalls.
func TestIssueRefusesAnUnreachableThreshold(t *testing.T) {
	t.Parallel()
	handler, err := challenge.NewQuorum(challenge.QuorumConfig{})
	if err != nil {
		t.Fatalf("new quorum handler: %v", err)
	}
	for _, spec := range []policy.Quorum{
		membersQuorum(3, "bob", "carol"),
		membersQuorum(0, "bob"),
	} {
		_, err := handler.Issue(context.Background(), challenge.IssueRequest{
			Instance: challenge.Instance{DecisionID: "d-1", Kind: policy.ChallengeQuorum},
			Spec:     spec,
			Decision: baseContext(),
			Now:      testNow,
		})
		if !errors.Is(err, challenge.ErrUnsupportedSpec) {
			t.Fatalf("threshold %d over %v: want ErrUnsupportedSpec, got %v",
				spec.Threshold, spec.Approvers.Members, err)
		}
	}
}

// A quorum issues no timer of its own — it ends when its decision does — but if
// one is set, its passing means the collection failed. That is the half of the
// contract a delay gets the other way round.
func TestElapsedQuorumDeadlineMeansFailedNotSatisfied(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(2, "bob", "carol"))

	if _, err := f.submit(f.idp.user(t, "bob", nil), ""); err != nil {
		t.Fatalf("bob's submission: %v", err)
	}

	deadline := testNow.Add(-time.Minute)
	st, err := f.handler.Status(context.Background(), challenge.StatusRequest{
		Instance: f.instance,
		Decision: f.context,
		Detail:   f.detail,
		Stored:   challenge.StatePending,
		Deadline: &deadline,
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.State != challenge.StateFailed {
		t.Fatalf("an unmet quorum past its deadline reported %s, want failed", st.State)
	}
	if st.Have != 1 || st.Need != 2 {
		t.Fatalf("status reported %d/%d, want 1/2", st.Have, st.Need)
	}
}

// Status is a read that recomputes from the approval rows, so a crash between
// the approval row and the challenge row leaves the truth recoverable.
func TestStatusRecomputesFromStoredApprovals(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(2, "bob", "carol"))

	for _, who := range []string{"bob", "carol"} {
		if _, err := f.submit(f.idp.user(t, who, nil), ""); err != nil {
			t.Fatalf("%s's submission: %v", who, err)
		}
	}
	st := f.status()
	if st.State != challenge.StateSatisfied || st.Have != 2 || st.Need != 2 {
		t.Fatalf("status recomputed %d/%d %s, want 2/2 satisfied", st.Have, st.Need, st.State)
	}

	// A terminal stored state is never walked back by a recount.
	cancelled, err := f.handler.Status(context.Background(), challenge.StatusRequest{
		Instance: f.instance,
		Decision: f.context,
		Detail:   f.detail,
		Stored:   challenge.StateCancelled,
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if cancelled.State != challenge.StateCancelled {
		t.Fatalf("a cancelled challenge recomputed to %s", cancelled.State)
	}
}

// R40's read rule: the handler answers for its own targets and nobody else's.
func TestIsTargetAnswersForTheResolvedSet(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(1, "bob"))

	for _, tc := range []struct {
		name    string
		subject *identity.Subject
		want    bool
	}{
		{name: "listed approver", subject: f.idp.user(t, "bob", nil), want: true},
		{name: "outsider", subject: f.idp.user(t, "mallory", nil), want: false},
		{name: "workload with a listed name", subject: f.idp.workload(t, "bob"), want: false},
		{name: "nobody", subject: nil, want: false},
	} {
		got, err := f.handler.IsTarget(context.Background(), challenge.TargetRequest{
			Instance: f.instance,
			Decision: f.context,
			Detail:   f.detail,
			Subject:  tc.subject,
		})
		if err != nil {
			t.Fatalf("%s: is target: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: IsTarget = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A submission whose echoed hash is not the one the server froze is refused:
// the approver reviewed something else.
func TestSubmissionEchoingAStaleHashIsRefused(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(1, "bob"))
	bob := f.idp.user(t, "bob", nil)

	stale := "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := f.submit(bob, `{"binding_hash":"`+stale+`"}`); !errors.Is(err, challenge.ErrBindingChanged) {
		t.Fatalf("want ErrBindingChanged, got %v", err)
	}
	if got := len(f.approvals()); got != 0 {
		t.Fatalf("a refused submission wrote %d approval rows, want none", got)
	}

	if _, err := f.submit(bob, `{"binding_hash":"`+f.storedDetail().BindingHash+`"}`); err != nil {
		t.Fatalf("a submission echoing the frozen hash: %v", err)
	}
}

// A decision whose frozen material no longer hashes to the value the challenge
// was issued under can collect nothing: the approvals belong to other material.
func TestSubmissionAgainstAlteredMaterialIsRefused(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(1, "bob"))
	bob := f.idp.user(t, "bob", nil)

	altered := f.context
	altered.Obligations = json.RawMessage(`[{"type":"notify"},{"type":"wire-anywhere"}]`)
	_, err := f.handler.Submit(context.Background(), challenge.SubmitRequest{
		Instance:  f.instance,
		Decision:  altered,
		Detail:    f.detail,
		Submitter: bob,
		Now:       testNow,
	})
	if !errors.Is(err, challenge.ErrBindingChanged) {
		t.Fatalf("want ErrBindingChanged, got %v", err)
	}
	if got := len(f.approvals()); got != 0 {
		t.Fatalf("a refused submission wrote %d approval rows, want none", got)
	}
}

// v1 collects approvals. A rejection verdict is named by the store but has no
// lifecycle meaning yet, so it is refused rather than silently counted as one.
func TestRejectionVerdictIsRefusedInV1(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(1, "bob"))
	bob := f.idp.user(t, "bob", nil)

	if _, err := f.submit(bob, `{"verdict":"reject"}`); !errors.Is(err, challenge.ErrVerdictUnsupported) {
		t.Fatalf("want ErrVerdictUnsupported, got %v", err)
	}
	if got := len(f.approvals()); got != 0 {
		t.Fatalf("a refused verdict wrote %d approval rows, want none", got)
	}
	if _, err := f.submit(bob, `{"verdict":"approve"}`); err != nil {
		t.Fatalf("an explicit approve verdict: %v", err)
	}
}

// The review is the approval screen's read, so it obeys the same target rule
// the submission does.
func TestReviewIsRefusedToANonTarget(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(1, "bob"))

	_, err := f.handler.Review(context.Background(), challenge.QuorumReviewRequest{
		DecisionID: f.instance.DecisionID,
		Ordinal:    f.instance.Ordinal,
		Subject:    f.idp.user(t, "mallory", nil),
		Now:        testNow,
	})
	if !errors.Is(err, challenge.ErrNotTarget) {
		t.Fatalf("want ErrNotTarget, got %v", err)
	}
}

// The review carries what the approver is being asked to judge, frozen.
func TestReviewCarriesTheFrozenMaterial(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(2, "bob", "carol"))

	review, err := f.handler.Review(context.Background(), challenge.QuorumReviewRequest{
		DecisionID: f.instance.DecisionID,
		Ordinal:    f.instance.Ordinal,
		Subject:    f.idp.user(t, "bob", nil),
		Now:        testNow,
	})
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	switch {
	case review.Need != 2:
		t.Fatalf("review reports need %d, want 2", review.Need)
	case review.Have != 0:
		t.Fatalf("review reports have %d, want 0", review.Have)
	case review.State != challenge.StatePending:
		t.Fatalf("review reports state %s, want pending", review.State)
	case review.Decision.PolicyID != "high-value-transfer":
		t.Fatalf("review names policy %q", review.Decision.PolicyID)
	case string(review.Decision.Obligations) == "":
		t.Fatal("review carries no obligations")
	case len(review.Approvers) != 2:
		t.Fatalf("review lists %d approvers, want 2", len(review.Approvers))
	}
}

// An expired decision collects nothing, and the review says so rather than
// rendering a screen whose submission would be refused.
func TestReviewRefusesAnExpiredDecision(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(1, "bob"))

	_, err := f.handler.Review(context.Background(), challenge.QuorumReviewRequest{
		DecisionID: f.instance.DecisionID,
		Ordinal:    f.instance.Ordinal,
		Subject:    f.idp.user(t, "bob", nil),
		Now:        f.context.ExpiresAt.Add(time.Second),
	})
	if !errors.Is(err, store.ErrDecisionExpired) {
		t.Fatalf("want ErrDecisionExpired, got %v", err)
	}
}
