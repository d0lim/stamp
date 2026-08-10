package idpgroup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/policy"
)

// resolverFunc adapts a function to engine.SourceResolver, so the delegation
// test does not need a second fact plane standing up behind it.
type resolverFunc func(context.Context, []engine.SourceCall) (*engine.Facts, error)

func (f resolverFunc) ResolveSources(ctx context.Context, calls []engine.SourceCall) (*engine.Facts, error) {
	return f(ctx, calls)
}

// frozenDecision is the decision a quorum is issued against: the shape the
// decide lifecycle freezes a request in, which is what a field reference in an
// approver source is read out of.
func frozenDecision(t *testing.T, attrs map[string]any) challenge.DecisionContext {
	t.Helper()
	request := map[string]any{
		"action":   "release",
		"subject":  map[string]any{"type": "user", "id": "u-1"},
		"resource": map[string]any{"type": "service", "id": "payments", "attributes": attrs},
		"context":  map[string]any{"type": "ctx", "id": "c-1"},
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return challenge.DecisionContext{
		DecisionID:   "dec-1",
		CallerID:     "workload:https://idp.example.test#svc",
		SubjectID:    "u-1",
		ResourceID:   "payments",
		Action:       "release",
		PolicyID:     "release-policy",
		Request:      raw,
		FactSnapshot: json.RawMessage(`{}`),
		Obligations:  json.RawMessage(`[]`),
		CreatedAt:    time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		ExpiresAt:    time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC),
	}
}

func quorumFor(t *testing.T, s *Sources) *challenge.Quorum {
	t.Helper()
	q, err := challenge.NewQuorum(challenge.QuorumConfig{Groups: s})
	if err != nil {
		t.Fatalf("NewQuorum: %v", err)
	}
	return q
}

func issue(t *testing.T, q *challenge.Quorum, spec policy.Quorum, dec challenge.DecisionContext) (challenge.IssueResult, error) {
	t.Helper()
	return q.Issue(context.Background(), challenge.IssueRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Ordinal: 0, Kind: policy.ChallengeQuorum},
		Spec:     spec,
		Decision: dec,
		Now:      dec.CreatedAt,
	})
}

func detailOf(t *testing.T, res challenge.IssueResult) challenge.QuorumDetail {
	t.Helper()
	detail, ok := res.Detail.(challenge.QuorumDetail)
	if !ok {
		t.Fatalf("detail is %T, not a QuorumDetail", res.Detail)
	}
	return detail
}

// --- U13's first scenario ----------------------------------------------------

// R18's third mode, end to end through the handler U20 left the seam in: a
// quorum names a group, the group is resolved at issue, and the members it
// resolved to are frozen into the challenge.
func TestAQuorumResolvesItsApproversFromAGroup(t *testing.T) {
	d := newDirectory(t)
	d.answer(`{"members": [{"value": "bob"}, {"value": "alice"}, {"value": "bob"}]}`)
	s, _, _ := sourcesFor(t, d)
	q := quorumFor(t, s)

	spec := policy.Quorum{
		Threshold: 2,
		Approvers: policy.ApproverSet{
			Source: &policy.SourceRef{Name: "release_approvers", Args: []policy.Operand{policy.String("sre-oncall")}},
		},
	}
	res, err := issue(t, q, spec, frozenDecision(t, nil))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res.State != challenge.StatePending {
		t.Fatalf("state = %q, want %q", res.State, challenge.StatePending)
	}
	detail := detailOf(t, res)
	if detail.Mode != challenge.ResolveGroupSource {
		t.Fatalf("mode = %q, want %q", detail.Mode, challenge.ResolveGroupSource)
	}
	if detail.Source != "release_approvers" {
		t.Fatalf("source = %q", detail.Source)
	}
	if len(detail.Members) != 2 || detail.Members[0] != "alice" || detail.Members[1] != "bob" {
		t.Fatalf("members = %#v, want the deduplicated pair", detail.Members)
	}
	// The issuer the operator bound this source to is frozen with the members.
	// A member identifier is a `sub`, and a `sub` names somebody only inside one
	// issuer — so a set frozen without it would admit the same name from any
	// trusted IdP.
	if detail.Issuer != testIssuer {
		t.Fatalf("frozen issuer = %q, want the source's own %q", detail.Issuer, testIssuer)
	}
	if detail.BindingHash == "" {
		t.Fatal("the challenge was issued with no binding hash")
	}
}

// The group can be named by an attribute of the decision, and it is read out of
// the frozen request rather than out of anything read now.
func TestAGroupNamedByARequestAttributeIsReadFromTheFrozenRequest(t *testing.T) {
	d := newDirectory(t)
	s, _, _ := sourcesFor(t, d)
	q := quorumFor(t, s)

	spec := policy.Quorum{
		Threshold: 1,
		Approvers: policy.ApproverSet{
			Source: &policy.SourceRef{
				Name: "release_approvers",
				Args: []policy.Operand{policy.Field(policy.RoleResource, "owner_group")},
			},
		},
	}
	dec := frozenDecision(t, map[string]any{"owner_group": "payments-oncall"})
	if _, err := issue(t, q, spec, dec); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got := d.lastReq.Load().URL.Query().Get("group"); got != "payments-oncall" {
		t.Fatalf("group = %q, want the frozen attribute", got)
	}
}

func TestABadGroupArgumentRefusesTheIssue(t *testing.T) {
	tests := []struct {
		name string
		args []policy.Operand
		want string
	}{
		{"no argument", nil, "expected 1 argument"},
		{"two arguments", []policy.Operand{policy.String("a"), policy.String("b")}, "expected 1 argument"},
		{"a non-string literal", []policy.Operand{policy.Int(7)}, "not a string"},
		{"a blank group", []policy.Operand{policy.String("   ")}, "blank"},
		{"an attribute the frozen request does not carry", []policy.Operand{policy.Field(policy.RoleResource, "missing")}, "carries no resource.missing"},
		{"an attribute that is not a string", []policy.Operand{policy.Field(policy.RoleResource, "owner_group")}, "not a group identifier"},
		{"a nested source call", []policy.Operand{policy.Source("release_approvers", policy.String("x"))}, "a literal or a request attribute"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := newDirectory(t)
			s, _, _ := sourcesFor(t, d)
			q := quorumFor(t, s)

			spec := policy.Quorum{
				Threshold: 1,
				Approvers: policy.ApproverSet{
					Source: &policy.SourceRef{Name: "release_approvers", Args: tc.args},
				},
			}
			dec := frozenDecision(t, map[string]any{"owner_group": 7})
			_, err := issue(t, q, spec, dec)
			if err == nil {
				t.Fatal("the challenge was issued")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
			if d.calls.Load() != 0 {
				t.Fatal("a directory call went out for an argument that was never valid")
			}
		})
	}
}

// --- U13's second scenario ---------------------------------------------------

// An IdP that cannot answer denies. There is no fail-open shape for "who may
// approve this", so the challenge is not issued and the decision is left with
// nothing to satisfy.
func TestADirectoryOutageRefusesToIssueTheQuorum(t *testing.T) {
	d := newDirectory(t)
	d.status.Store(http.StatusInternalServerError)
	s, _, auditor := sourcesFor(t, d)
	q := quorumFor(t, s)

	spec := policy.Quorum{
		Threshold: 2,
		Approvers: policy.ApproverSet{
			Source: &policy.SourceRef{Name: "release_approvers", Args: []policy.Operand{policy.String("sre-oncall")}},
		},
	}
	_, err := issue(t, q, spec, frozenDecision(t, nil))
	if err == nil {
		t.Fatal("a quorum was issued against a directory that could not answer it")
	}
	f := mustFailure(t, err)
	if !f.FailsClosed() {
		t.Fatal("the failure must be fail-closed")
	}
	if len(auditor.all()) != 1 {
		t.Fatalf("expected the failure to be audited, got %d records", len(auditor.all()))
	}
}

// The operator flag can admit a fail-open group source for condition use — and
// it still cannot produce an approver set out of an outage. This is the whole
// argument for not consulting the failure behaviour on this path: "allow"
// answers a different question than "who may approve".
func TestAFailOpenGroupSourceStillRefusesToResolveApprovers(t *testing.T) {
	d := newDirectory(t)
	d.status.Store(http.StatusInternalServerError)
	decl := groupDecl(d.url())
	decl.OnError = policy.OnErrorAllow
	s, err := NewSources([]Declaration{decl}, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{
			Allow:         []string{originOfURL(t, d.url())},
			AllowLoopback: true,
			Resolve:       newFakeResolver().resolve,
		}),
		Issuers:       trustedIssuers(),
		AllowFailOpen: true,
	})
	if err != nil {
		t.Fatalf("NewSources: %v", err)
	}
	t.Cleanup(s.Close)

	// Asserted at this level and not only through the handler. A resolver that
	// answered an outage with an empty set would also be refused by the
	// handler's threshold check, so an issue-level assertion alone would pass
	// whether or not this path consults the failure behaviour.
	ref := policy.SourceRef{Name: "release_approvers", Args: []policy.Operand{policy.String("sre-oncall")}}
	got, err := s.ResolveApprovers(context.Background(), ref, frozenDecision(t, nil))
	if err == nil {
		t.Fatalf("a fail-open declaration resolved an approver set out of an outage: %#v", got)
	}
	f := mustFailure(t, err)
	if f.FailsClosed() {
		t.Fatal("the audited record should still carry the declaration's fail-open behaviour")
	}

	// And the handler refuses the issue on the back of it.
	q := quorumFor(t, s)
	spec := policy.Quorum{
		Threshold: 1,
		Approvers: policy.ApproverSet{Source: &ref},
	}
	if _, err := issue(t, q, spec, frozenDecision(t, nil)); err == nil {
		t.Fatal("a challenge was issued with an approver set nothing could produce")
	}
}

// A group too small for the quorum it gates is a decision that could never
// resolve. The handler counts the resolved set and refuses; this test pins that
// the two units agree about it.
func TestAGroupSmallerThanItsQuorumRefusesTheIssue(t *testing.T) {
	d := newDirectory(t)
	d.answer(`{"members": ["alice"]}`)
	s, _, _ := sourcesFor(t, d)
	q := quorumFor(t, s)

	spec := policy.Quorum{
		Threshold: 3,
		Approvers: policy.ApproverSet{
			Source: &policy.SourceRef{Name: "release_approvers", Args: []policy.Operand{policy.String("sre-oncall")}},
		},
	}
	_, err := issue(t, q, spec, frozenDecision(t, nil))
	if err == nil {
		t.Fatal("a quorum of 3 was issued against a group of 1")
	}
	if !errors.Is(err, challenge.ErrUnsupportedSpec) {
		t.Fatalf("error = %v, want an unsupported-spec refusal", err)
	}
}

// --- U13's third scenario, through the quorum --------------------------------

// Two challenges issued inside the TTL resolve from one directory call. The
// resolution is frozen into each challenge, so what the TTL bounds is how stale
// the membership may be at the moment it is frozen.
func TestTwoIssuesInsideTheTTLShareOneDirectoryCall(t *testing.T) {
	d := newDirectory(t)
	s, clock, _ := sourcesFor(t, d)
	q := quorumFor(t, s)
	spec := policy.Quorum{
		Threshold: 2,
		Approvers: policy.ApproverSet{
			Source: &policy.SourceRef{Name: "release_approvers", Args: []policy.Operand{policy.String("sre-oncall")}},
		},
	}

	if _, err := issue(t, q, spec, frozenDecision(t, nil)); err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	clock.advance(30 * time.Second)
	if _, err := issue(t, q, spec, frozenDecision(t, nil)); err != nil {
		t.Fatalf("second Issue: %v", err)
	}
	if got := d.calls.Load(); got != 1 {
		t.Fatalf("directory calls = %d, want 1", got)
	}

	// Past the TTL the membership is asked for again, and a member who has
	// since left the group is gone from the next resolution.
	clock.advance(time.Minute)
	d.answer(`{"members": ["alice", "carol"]}`)
	res, err := issue(t, q, spec, frozenDecision(t, nil))
	if err != nil {
		t.Fatalf("third Issue: %v", err)
	}
	detail := detailOf(t, res)
	if len(detail.Members) != 2 || detail.Members[1] != "carol" {
		t.Fatalf("members = %#v, want the refreshed membership", detail.Members)
	}
	if got := d.calls.Load(); got != 2 {
		t.Fatalf("directory calls = %d, want 2", got)
	}
}

// --- the resolver contract ---------------------------------------------------

func TestResolveApproversRefusesAnUnconfiguredSource(t *testing.T) {
	d := newDirectory(t)
	s, _, _ := sourcesFor(t, d)
	_, err := s.ResolveApprovers(context.Background(),
		policy.SourceRef{Name: "finance_approvers", Args: []policy.Operand{policy.String("g")}},
		frozenDecision(t, nil))
	f := mustFailure(t, err)
	if f.Reason != fact.ReasonUnknownSource {
		t.Fatalf("reason = %q", f.Reason)
	}
}

// A decision with no frozen request cannot answer a field reference, and a
// group identifier that resolved to nothing would be a lookup for whatever the
// directory returns for the empty group.
func TestAnEmptyFrozenRequestRefusesAFieldReference(t *testing.T) {
	d := newDirectory(t)
	s, _, _ := sourcesFor(t, d)
	dec := frozenDecision(t, nil)
	dec.Request = nil

	_, err := s.ResolveApprovers(context.Background(),
		policy.SourceRef{Name: "release_approvers", Args: []policy.Operand{policy.Field(policy.RoleResource, "owner_group")}},
		dec)
	f := mustFailure(t, err)
	if f.Reason != fact.ReasonBadArgument {
		t.Fatalf("reason = %q, want %q", f.Reason, fact.ReasonBadArgument)
	}
}

// A group source needs no deployment-wide approver-issuer designation, because
// the operator already bound it to one. This is the payoff of returning the
// issuer with the members: a deployment whose approvers live in a second IdP can
// name them, which a bare member list deliberately cannot.
func TestAGroupSourceCarriesItsOwnIssuer(t *testing.T) {
	d := newDirectory(t)
	s, _, _ := sourcesFor(t, d)

	group, err := s.ResolveApprovers(context.Background(),
		policy.SourceRef{Name: "release_approvers", Args: []policy.Operand{policy.String("sre-oncall")}},
		frozenDecision(t, nil))
	if err != nil {
		t.Fatalf("ResolveApprovers: %v", err)
	}
	if group.Issuer != testIssuer {
		t.Fatalf("issuer = %q, want the declaration's %q", group.Issuer, testIssuer)
	}
	if len(group.Members) != 2 {
		t.Fatalf("members = %#v", group.Members)
	}

	// And a handler that designates nothing still issues a group-resolved
	// quorum, where a bare member list would be refused.
	q, err := challenge.NewQuorum(challenge.QuorumConfig{Groups: s})
	if err != nil {
		t.Fatalf("NewQuorum: %v", err)
	}
	res, err := issue(t, q, policy.Quorum{
		Threshold: 2,
		Approvers: policy.ApproverSet{
			Source: &policy.SourceRef{Name: "release_approvers", Args: []policy.Operand{policy.String("sre-oncall")}},
		},
	}, frozenDecision(t, nil))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got := detailOf(t, res).Issuer; got != testIssuer {
		t.Fatalf("frozen issuer = %q, want %q", got, testIssuer)
	}
}
