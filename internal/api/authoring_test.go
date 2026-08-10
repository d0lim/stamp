package api_test

// authoring_test.go covers the file authoring surface: who may call it, what a
// refusal looks like, and that the surface decides none of it.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// recordingApplier stands in for the file authoring half of the governance
// service.
type recordingApplier struct {
	result    revision.FileApplyResult
	applyErr  error
	export    revision.Export
	exportErr error

	lastApply  revision.FileApplyRequest
	lastExport revision.ExportRequest
}

func (a *recordingApplier) ApplyFiles(_ context.Context, req revision.FileApplyRequest) (revision.FileApplyResult, error) {
	a.lastApply = req
	return a.result, a.applyErr
}

func (a *recordingApplier) Export(_ context.Context, req revision.ExportRequest) (revision.Export, error) {
	a.lastExport = req
	return a.export, a.exportErr
}

func newAuthoringFixture(t *testing.T, files api.FileApplier) *policyFixture {
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
	gov := &recordingGovernor{}
	policies, err := api.NewPolicies(api.PoliciesConfig{
		Governance: gov,
		Policies: api.PolicyListerFunc(func(context.Context) ([]store.PolicyRecord, error) {
			return nil, nil
		}),
		Files: files,
	})
	if err != nil {
		t.Fatalf("build policy surface: %v", err)
	}
	if err := server.Mount(policies); err != nil {
		t.Fatalf("mount policy surface: %v", err)
	}
	return &policyFixture{server: server, idp: idp, gov: gov}
}

const applyBody = `{"documents":[{"name":"a.yaml","content":"YXBpVmVyc2lvbjogc3RhbXAvdjEK"}]}`

// TestApplyPassesTheCallerAndThePayloadThrough is the surface's whole job: the
// caller comes from the verified token and never from the body, and the
// documents arrive unexamined.
func TestApplyPassesTheCallerAndThePayloadThrough(t *testing.T) {
	t.Parallel()
	files := &recordingApplier{result: revision.FileApplyResult{
		Proposal: revision.Proposal{ID: "rev-1", State: revision.StatePending, Origin: store.OriginFile},
	}}
	f := newAuthoringFixture(t, files)

	rec := f.do(t, api.SurfaceConsole, http.MethodPost, api.PolicyApplyPath,
		f.userToken(t, "ci"), applyBody, map[string]string{api.BootstrapTokenHeader: "token-1"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("apply = %d, want 202: %s", rec.Code, rec.Body)
	}
	if files.lastApply.Proposer == nil || files.lastApply.Proposer.ID != "ci" {
		t.Errorf("the proposer is %v, want the token's subject", files.lastApply.Proposer)
	}
	if files.lastApply.BootstrapToken != "token-1" {
		t.Errorf("the bootstrap token is %q, want it read from the header", files.lastApply.BootstrapToken)
	}
	if len(files.lastApply.Payload.Documents) != 1 || files.lastApply.Payload.Documents[0].Name != "a.yaml" {
		t.Errorf("the payload arrived as %v", files.lastApply.Payload.Documents)
	}
}

// TestApplyWithNoChangeIsNotAnAcceptance separates "there is a revision to wait
// for" from "there was nothing to do", which is the distinction a CI reports on.
func TestApplyWithNoChangeIsNotAnAcceptance(t *testing.T) {
	t.Parallel()
	f := newAuthoringFixture(t, &recordingApplier{result: revision.FileApplyResult{NoChange: true}})
	rec := f.do(t, api.SurfaceConsole, http.MethodPost, api.PolicyApplyPath, f.userToken(t, "ci"), applyBody, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply = %d, want 200: %s", rec.Code, rec.Body)
	}
	var body revision.FileApplyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	if !body.NoChange {
		t.Error("the response does not report that there was no change")
	}
}

// TestApplyRefusalsCarryTheOpenRevision is R47 at the surface: the refusal is
// actionable without a second request.
func TestApplyRefusalsCarryTheOpenRevision(t *testing.T) {
	t.Parallel()
	files := &recordingApplier{applyErr: &revision.PendingError{Pending: revision.PendingRevision{
		ID: "rev-open", Origin: store.OriginForm, Threshold: 3, Collected: 2,
	}}}
	f := newAuthoringFixture(t, files)

	rec := f.do(t, api.SurfaceConsole, http.MethodPost, api.PolicyApplyPath, f.userToken(t, "ci"), applyBody, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("apply = %d, want 409: %s", rec.Code, rec.Body)
	}
	var body api.PendingRevisionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode the refusal: %v", err)
	}
	if body.Pending.ID != "rev-open" || body.Pending.Collected != 2 || body.Pending.Threshold != 3 {
		t.Errorf("the refusal reports %+v, want rev-open at 2 of 3", body.Pending)
	}
}

func TestAuthoringRefusalsMapToStatuses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want int
		code string
	}{
		{"payload too large", revision.ErrPayloadTooLarge, http.StatusRequestEntityTooLarge, "payload_too_large"},
		{"rate limited", revision.ErrRateLimited, http.StatusTooManyRequests, "rate_limited"},
		{"authoring locked", revision.ErrAuthoringLocked, http.StatusForbidden, "authoring_locked"},
		{"origin conflict", revision.ErrOriginConflict, http.StatusConflict, "origin_conflict"},
		{"invalid payload", revision.ErrInvalidPayload, http.StatusBadRequest, "invalid_payload"},
		{"not authenticated", errors.New("boom"), http.StatusInternalServerError, "internal_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthoringFixture(t, &recordingApplier{applyErr: tc.err})
			rec := f.do(t, api.SurfaceConsole, http.MethodPost, api.PolicyApplyPath,
				f.userToken(t, "ci"), applyBody, nil)
			if rec.Code != tc.want {
				t.Fatalf("apply = %d, want %d: %s", rec.Code, tc.want, rec.Body)
			}
			var body api.ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode the refusal: %v", err)
			}
			if body.Error != tc.code {
				t.Errorf("the refusal code is %q, want %q", body.Error, tc.code)
			}
		})
	}
}

func TestExportIsUserAuthenticatedAndRefusesWithoutACapability(t *testing.T) {
	t.Parallel()
	files := &recordingApplier{export: revision.Export{
		Files:       []revision.ExportFile{{Name: "schema.yaml", Content: "apiVersion: stamp/v1\n"}},
		PolicyCount: 1,
	}}
	f := newAuthoringFixture(t, files)

	rec := f.do(t, api.SurfaceConsole, http.MethodGet, api.PolicyExportPath, f.userToken(t, "ann"), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d, want 200: %s", rec.Code, rec.Body)
	}
	if files.lastExport.Caller == nil || files.lastExport.Caller.ID != "ann" {
		t.Errorf("the export caller is %v, want the token's subject", files.lastExport.Caller)
	}

	// No credential at all never reaches the handler: the mount table decides
	// that, and the capability check is the layer behind it.
	if rec := f.do(t, api.SurfaceConsole, http.MethodGet, api.PolicyExportPath, "", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("an unauthenticated export = %d, want 401", rec.Code)
	}

	refused := newAuthoringFixture(t, &recordingApplier{exportErr: revision.ErrExportForbidden})
	rec = refused.do(t, api.SurfaceConsole, http.MethodGet, api.PolicyExportPath, refused.userToken(t, "nobody"), "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("an export without a capability = %d, want 403: %s", rec.Code, rec.Body)
	}
}

// TestAuthoringRoutesAreAbsentWithoutTheFilePath is what a deployment that
// deferred R45–R49 looks like from outside: the route answers, and says it is
// not configured, rather than 404ing as if the URL were a typo.
func TestAuthoringRoutesAreAbsentWithoutTheFilePath(t *testing.T) {
	t.Parallel()
	f := newAuthoringFixture(t, nil)
	rec := f.do(t, api.SurfaceConsole, http.MethodGet, api.PolicyExportPath, f.userToken(t, "ann"), "", nil)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("export with no file path = %d, want 501", rec.Code)
	}
}

// TestAuthoringRoutesAreConsoleOnly keeps the pair every authoring endpoint
// takes: the console surface and an end-user credential.
func TestAuthoringRoutesAreConsoleOnly(t *testing.T) {
	t.Parallel()
	f := newAuthoringFixture(t, &recordingApplier{})
	for _, r := range f.server.Mounted(api.SurfaceConsole) {
		if r.Name != "policy-apply" && r.Name != "policy-export" {
			continue
		}
		if r.Auth != api.AuthUser {
			t.Errorf("%s is mounted with %q auth, want %q", r.Name, r.Auth, api.AuthUser)
		}
	}
	if rec := f.do(t, api.SurfacePEP, http.MethodGet, api.PolicyExportPath,
		f.userToken(t, "ann"), "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("the export is reachable on the PEP surface: %d", rec.Code)
	}
}
