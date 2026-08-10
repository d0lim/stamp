package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// The authoring surface owns three things and no more: it puts every endpoint on
// the console listener behind an end-user credential, it names the author from
// the verified token rather than from the body, and it turns the governance
// path's sentinels into statuses a console can act on. What a revision costs and
// whether it may take effect is tested where the database is.

// recordingGovernor stands in for the governance service.
type recordingGovernor struct {
	mu sync.Mutex

	proposals []revision.ProposeRequest
	previews  []revision.PreviewRequest
	locks     []revision.LockRequest
	withdrawn []string

	mode        revision.Mode
	preview     revision.Preview
	proposal    revision.Proposal
	proposeErr  error
	previewErr  error
	getErr      error
	withdrawErr error
	lockErr     error
}

func (g *recordingGovernor) Mode(context.Context) (revision.Mode, error) {
	return g.mode, nil
}

func (g *recordingGovernor) Preview(_ context.Context, req revision.PreviewRequest) (revision.Preview, error) {
	g.mu.Lock()
	g.previews = append(g.previews, req)
	g.mu.Unlock()
	return g.preview, g.previewErr
}

func (g *recordingGovernor) Propose(_ context.Context, req revision.ProposeRequest) (revision.Proposal, error) {
	g.mu.Lock()
	g.proposals = append(g.proposals, req)
	g.mu.Unlock()
	if g.proposeErr != nil {
		return revision.Proposal{}, g.proposeErr
	}
	return g.proposal, nil
}

func (g *recordingGovernor) Get(_ context.Context, _ string) (revision.Proposal, error) {
	if g.getErr != nil {
		return revision.Proposal{}, g.getErr
	}
	return g.proposal, nil
}

func (g *recordingGovernor) Withdraw(_ context.Context, _ *identity.Subject, id string) (revision.Proposal, error) {
	g.mu.Lock()
	g.withdrawn = append(g.withdrawn, id)
	g.mu.Unlock()
	if g.withdrawErr != nil {
		return revision.Proposal{}, g.withdrawErr
	}
	return g.proposal, nil
}

func (g *recordingGovernor) Lock(_ context.Context, req revision.LockRequest) error {
	g.mu.Lock()
	g.locks = append(g.locks, req)
	g.mu.Unlock()
	return g.lockErr
}

func (g *recordingGovernor) lastProposal(t *testing.T) revision.ProposeRequest {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.proposals) == 0 {
		t.Fatal("nothing reached the governance service")
	}
	return g.proposals[len(g.proposals)-1]
}

func (g *recordingGovernor) proposed() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.proposals)
}

type policyFixture struct {
	server *api.Server
	idp    *mockIdP
	gov    *recordingGovernor
}

func newPolicyFixture(t *testing.T, gov *recordingGovernor, records []store.PolicyRecord) *policyFixture {
	t.Helper()
	idp := newMockIdP(t)
	sink := identity.AuditSinkFunc(func(context.Context, identity.AuthRecord) {})
	server, err := api.New(api.Config{
		Identity: idp.middleware(t, sink, func() time.Time { return fixedNow }),
		Addresses: map[api.Surface]string{
			api.SurfacePEP:     "127.0.0.1:0",
			api.SurfaceConsole: "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	policies, err := api.NewPolicies(api.PoliciesConfig{
		Governance: gov,
		Policies: api.PolicyListerFunc(func(context.Context) ([]store.PolicyRecord, error) {
			return records, nil
		}),
	})
	if err != nil {
		t.Fatalf("build policy surface: %v", err)
	}
	if err := server.Mount(policies); err != nil {
		t.Fatalf("mount policy surface: %v", err)
	}
	return &policyFixture{server: server, idp: idp, gov: gov}
}

func (f *policyFixture) do(t *testing.T, surface api.Surface, method, path, token, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	f.server.Handler(surface).ServeHTTP(rec, req)
	return rec
}

func (f *policyFixture) userToken(t *testing.T, subject string) string {
	t.Helper()
	return f.idp.token(t, subject, "console")
}

// deltaBody renders a one-element delta the way a console would send it.
func deltaBody(t *testing.T, mode string) string {
	t.Helper()
	d := revision.Single(nil, &policy.Policy{
		ID:        "high-value",
		Subject:   "user",
		Resource:  "account",
		Actions:   []string{"transfer"},
		Condition: policy.Compare{Op: policy.OpGe, Left: policy.Field(policy.RoleResource, "amount"), Right: policy.Int(1000)},
	})
	raw, err := d.MarshalJSON()
	if err != nil {
		t.Fatalf("encode delta: %v", err)
	}
	body := map[string]any{"delta": json.RawMessage(raw)}
	if mode != "" {
		body["application_mode"] = mode
	}
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}
	return string(out)
}

// Policy administration is a console endpoint behind an end-user credential.
// The mount table is what makes that true, so the assertion is on the routes.
func TestPolicyRoutesAreConsoleOnlyAndUserAuthenticated(t *testing.T) {
	t.Parallel()
	policies, err := api.NewPolicies(api.PoliciesConfig{
		Governance: &recordingGovernor{},
		Policies:   api.PolicyListerFunc(func(context.Context) ([]store.PolicyRecord, error) { return nil, nil }),
	})
	if err != nil {
		t.Fatalf("build policy surface: %v", err)
	}
	routes := policies.Routes()
	if len(routes) == 0 {
		t.Fatal("the policy surface offers no routes")
	}
	for _, route := range routes {
		if route.Surface != api.SurfaceConsole {
			t.Errorf("route %q is on the %s surface, want console", route.Name, route.Surface)
		}
		if route.Auth != api.AuthUser {
			t.Errorf("route %q asks for %q, want an end-user credential", route.Name, route.Auth)
		}
	}
}

// R40 at the door: no credential, no revision.
func TestUnauthenticatedRevisionIsRefusedBeforeTheGovernanceService(t *testing.T) {
	t.Parallel()
	f := newPolicyFixture(t, &recordingGovernor{}, nil)
	rec := f.do(t, api.SurfaceConsole, http.MethodPost, "/policies/revisions", "", deltaBody(t, ""), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if f.gov.proposed() != 0 {
		t.Fatal("an unauthenticated request reached the governance service")
	}
}

// The author is the token's subject, and the bootstrap token rides in a header
// rather than in the body a console might log.
func TestProposalCarriesTheTokenSubjectAndTheBootstrapHeader(t *testing.T) {
	t.Parallel()
	gov := &recordingGovernor{proposal: revision.Proposal{ID: "rev-1", State: revision.StatePending}}
	f := newPolicyFixture(t, gov, nil)

	rec := f.do(t, api.SurfaceConsole, http.MethodPost, "/policies/revisions",
		f.userToken(t, "alice"), deltaBody(t, "grandfather"),
		map[string]string{api.BootstrapTokenHeader: "the-token"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}

	got := gov.lastProposal(t)
	if got.Proposer == nil || got.Proposer.ID != "alice" {
		t.Fatalf("proposer = %+v, want the token subject alice", got.Proposer)
	}
	if got.BootstrapToken != "the-token" {
		t.Fatalf("bootstrap token = %q, want the header value", got.BootstrapToken)
	}
	if got.Mode != "grandfather" {
		t.Fatalf("application mode = %q, want grandfather", got.Mode)
	}
	if got.Delta.Len() != 1 {
		t.Fatalf("delta holds %d changes, want 1", got.Delta.Len())
	}
}

// A body naming its own author is refused rather than ignored: a field that is
// ignored today is a field somebody reads tomorrow.
func TestProposalBodyCannotNameItsOwnAuthor(t *testing.T) {
	t.Parallel()
	f := newPolicyFixture(t, &recordingGovernor{}, nil)
	body := `{"delta":{"changes":[]},"proposer_id":"root"}`
	rec := f.do(t, api.SurfaceConsole, http.MethodPost, "/policies/revisions",
		f.userToken(t, "mallory"), body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown field", rec.Code)
	}
	if f.gov.proposed() != 0 {
		t.Fatal("a body with an unknown field reached the governance service")
	}
}

// R23: the preview reports the classification and the floors a revision would
// break, and it does so with a 200 rather than an error — the author is being
// told the cost, not refused.
func TestPreviewReportsClassificationAndViolations(t *testing.T) {
	t.Parallel()
	gov := &recordingGovernor{preview: revision.Preview{
		Mode:      revision.ModeQuorum,
		Weakening: true,
		Findings: []revision.Finding{
			{Subject: "high-value", Reason: revision.ReasonPolicyDeleted, Detail: "removed"},
		},
		Threshold:         3,
		AffectedDecisions: 7,
		Violations:        []string{"revision: the approver set cannot satisfy the quorum"},
	}}
	f := newPolicyFixture(t, gov, nil)

	rec := f.do(t, api.SurfaceConsole, http.MethodPost, "/policies/revisions/preview",
		f.userToken(t, "alice"), deltaBody(t, ""), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var out revision.Preview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if !out.Weakening || len(out.Findings) != 1 {
		t.Fatalf("preview = %+v, want the weakening finding", out)
	}
	if out.AffectedDecisions != 7 {
		t.Fatalf("affected decisions = %d, want 7", out.AffectedDecisions)
	}
	if out.Admissible() {
		t.Fatal("a preview carrying a violation reports itself admissible")
	}
}

// Every refusal an author has to tell apart from an outage has its own status.
func TestGovernanceRefusalsMapToStatuses(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		err  error
		code int
	}{
		"no bootstrap token": {revision.ErrBootstrapRequired, http.StatusForbidden},
		"wrong token":        {revision.ErrBootstrapInvalid, http.StatusForbidden},
		"spent token":        {revision.ErrBootstrapSpent, http.StatusForbidden},
		"already locked":     {revision.ErrAlreadyLocked, http.StatusConflict},
		"revision pending":   {revision.ErrRevisionPending, http.StatusConflict},
		"unsatisfiable":      {revision.ErrUnsatisfiable, http.StatusUnprocessableEntity},
		"floor violated":     {revision.ErrFloorViolated, http.StatusUnprocessableEntity},
		"invalid delta":      {revision.ErrInvalidDelta, http.StatusBadRequest},
		"invalid revision":   {revision.ErrInvalidRevision, http.StatusBadRequest},
		"not installed":      {revision.ErrNotInstalled, http.StatusServiceUnavailable},
		"not found":          {store.ErrNotFound, http.StatusNotFound},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPolicyFixture(t, &recordingGovernor{proposeErr: tc.err}, nil)
			rec := f.do(t, api.SurfaceConsole, http.MethodPost, "/policies/revisions",
				f.userToken(t, "alice"), deltaBody(t, ""), nil)
			if rec.Code != tc.code {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.code, rec.Body.String())
			}
		})
	}
}

// A refused token tells the caller nothing about which of the three ways it was
// wrong.
func TestBootstrapRefusalsAreOneAnswer(t *testing.T) {
	t.Parallel()
	bodies := map[string]string{}
	for name, err := range map[string]error{
		"missing": revision.ErrBootstrapRequired,
		"invalid": revision.ErrBootstrapInvalid,
		"spent":   revision.ErrBootstrapSpent,
	} {
		f := newPolicyFixture(t, &recordingGovernor{proposeErr: err}, nil)
		rec := f.do(t, api.SurfaceConsole, http.MethodPost, "/policies/revisions",
			f.userToken(t, "alice"), deltaBody(t, ""), nil)
		bodies[name] = rec.Body.String()
	}
	if bodies["missing"] != bodies["invalid"] || bodies["invalid"] != bodies["spent"] {
		t.Fatalf("the three token failures answer differently: %v", bodies)
	}
}

// The lock endpoint hands the quorum and the header token straight through; it
// decides nothing itself.
func TestLockForwardsTheQuorumAndTheToken(t *testing.T) {
	t.Parallel()
	gov := &recordingGovernor{mode: revision.ModeSolo}
	f := newPolicyFixture(t, gov, nil)

	rec := f.do(t, api.SurfaceConsole, http.MethodPost, "/governance/lock",
		f.userToken(t, "root"), `{"threshold":2,"approvers":["a","b","c"]}`,
		map[string]string{api.BootstrapTokenHeader: "the-token"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	gov.mu.Lock()
	defer gov.mu.Unlock()
	if len(gov.locks) != 1 {
		t.Fatalf("the governance service saw %d lock requests, want 1", len(gov.locks))
	}
	got := gov.locks[0]
	if got.Token != "the-token" {
		t.Fatalf("token = %q, want the header value", got.Token)
	}
	if got.Actor == nil || got.Actor.ID != "root" {
		t.Fatalf("actor = %+v, want the token subject", got.Actor)
	}
	if got.Quorum.Threshold != 2 || len(got.Quorum.Approvers.Members) != 3 {
		t.Fatalf("quorum = %+v, want 2 of three named approvers", got.Quorum)
	}
}

// The listing ships the exchange-format document and flags the reserved policy,
// so a console never renders the governance rule as an ordinary editable one.
func TestPolicyListingMarksTheReservedPolicy(t *testing.T) {
	t.Parallel()
	records := []store.PolicyRecord{
		{ID: revision.GovernancePolicyID, Version: 3, Origin: store.OriginForm, Document: "id: stamp.governance\n"},
		{ID: "high-value", Version: 1, Origin: store.OriginFile, Document: "id: high-value\n"},
	}
	f := newPolicyFixture(t, &recordingGovernor{}, records)

	rec := f.do(t, api.SurfaceConsole, http.MethodGet, "/policies", f.userToken(t, "alice"), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var out api.PolicyListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode listing: %v", err)
	}
	if len(out.Policies) != 2 {
		t.Fatalf("listing holds %d policies, want 2", len(out.Policies))
	}
	if !out.Policies[0].Reserved {
		t.Fatal("the governance policy is not flagged as reserved")
	}
	if out.Policies[1].Reserved {
		t.Fatal("an ordinary policy is flagged as reserved")
	}
}

// A console path is not reachable on the PEP listener: another router has never
// heard of it.
func TestPolicyPathsAreNotReachableOnThePEPSurface(t *testing.T) {
	t.Parallel()
	f := newPolicyFixture(t, &recordingGovernor{}, nil)
	rec := f.do(t, api.SurfacePEP, http.MethodPost, "/policies/revisions",
		f.userToken(t, "alice"), deltaBody(t, ""), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("the PEP surface answered %d for a console path, want 404", rec.Code)
	}
	if f.gov.proposed() != 0 {
		t.Fatal("a request to the wrong surface reached the governance service")
	}
}
