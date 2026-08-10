package api

// policies.go is the authoring surface: read the policy set, ask what a change
// would cost, propose it, and — once — lock governance.
//
// Three things about it are the point rather than the plumbing.
//
// Every endpoint is a console endpoint behind an end-user credential, which is
// the only pair the mount table admits there. A policy-authoring route a
// workload could call is not a bug review has to catch; it is a route that does
// not mount.
//
// Nothing here decides anything. The surface reads a body, names the caller from
// the verified token, and hands both to the governance service — which turns the
// change into a decision. R6's "policy changes pass through STAMP's own decide"
// would be worth nothing if this layer could write a policy directly, so it
// cannot: it holds no store handle at all.
//
// The preview endpoint exists because R23 requires an author to see the
// weakening classification, the operator floors a change would break, and how
// many open decisions it would touch, *before* submitting. A revision that
// breaks a floor is refused at submission, so the preview is the only place an
// author finds out cheaply.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// The authoring endpoints.
const (
	// PolicyListPattern lists the effective policy set.
	PolicyListPattern = "GET /policies"
	// SchemaReadPath is where the schema in force is read.
	SchemaReadPath = "/policies/schema"
	// SchemaReadPattern reads the schema in force.
	SchemaReadPattern = "GET " + SchemaReadPath
	// RevisionPreviewPattern answers R23's pre-submission question.
	RevisionPreviewPattern = "POST /policies/revisions/preview"
	// RevisionSubmitPattern submits a revision.
	RevisionSubmitPattern = "POST /policies/revisions"
	// RevisionReadPattern reads one revision.
	RevisionReadPattern = "GET /policies/revisions/{id}"
	// RevisionWithdrawPattern withdraws a pending revision.
	RevisionWithdrawPattern = "POST /policies/revisions/{id}/withdrawal"
	// GovernanceReadPattern reports the governance mode.
	GovernanceReadPattern = "GET /governance"
	// GovernanceLockPattern installs quorum governance, once.
	GovernanceLockPattern = "POST /governance/lock"
)

// BootstrapTokenHeader carries the one-time token that authorizes governance
// before the lock.
//
// It is a header rather than a body field so that the same token authorizes
// every pre-lock action without each request shape having to make room for it,
// and so that it never lands in a body a console might log.
const BootstrapTokenHeader = "X-Stamp-Bootstrap-Token" //nolint:gosec // a header name, not a credential

// DefaultMaxRevisionBytes bounds a revision body. A revision carries policy
// documents, so it is generous — and still bounded, because an unbounded
// authoring surface is an allocation primitive.
const DefaultMaxRevisionBytes = 1 << 20

// Governor is the governance service this surface delegates to.
//
// It is an interface so the surface can be exercised without a database, and so
// that nothing here can reach past the governance path into the policy store:
// there is no method on it that writes a policy.
type Governor interface {
	Mode(ctx context.Context) (revision.Mode, error)
	Preview(ctx context.Context, req revision.PreviewRequest) (revision.Preview, error)
	Propose(ctx context.Context, req revision.ProposeRequest) (revision.Proposal, error)
	Get(ctx context.Context, id string) (revision.Proposal, error)
	Withdraw(ctx context.Context, caller *identity.Subject, id string) (revision.Proposal, error)
	Lock(ctx context.Context, req revision.LockRequest) error
}

// BootstrapReporter reports whether the one-time token is still live, without
// revealing it.
type BootstrapReporter interface {
	Status(ctx context.Context) (revision.BootstrapStatus, error)
}

// PolicyLister reads the effective policy set.
type PolicyLister interface {
	EffectivePolicies(ctx context.Context) ([]store.PolicyRecord, error)
}

// PolicyListerFunc adapts a function to [PolicyLister].
type PolicyListerFunc func(ctx context.Context) ([]store.PolicyRecord, error)

// EffectivePolicies calls f.
func (f PolicyListerFunc) EffectivePolicies(ctx context.Context) ([]store.PolicyRecord, error) {
	return f(ctx)
}

// SchemaReader reads the schema in force.
//
// It is a separate reader from [PolicyLister] because the schema is a separate
// document with its own version line: a policy list carries policy documents and
// no schema at all, which is why an author could see every policy in the
// deployment and still not be able to render the form that edits one (U15).
type SchemaReader interface {
	EffectiveSchema(ctx context.Context) (store.SchemaRecord, error)
}

// SchemaReaderFunc adapts a function to [SchemaReader].
type SchemaReaderFunc func(ctx context.Context) (store.SchemaRecord, error)

// EffectiveSchema calls f.
func (f SchemaReaderFunc) EffectiveSchema(ctx context.Context) (store.SchemaRecord, error) {
	return f(ctx)
}

// PoliciesConfig configures a [Policies].
type PoliciesConfig struct {
	// Governance turns a revision into a decision. Required.
	Governance Governor
	// Policies reads the effective set. Required.
	Policies PolicyLister
	// Schema reads the schema in force. Required: an authoring surface that
	// cannot say what vocabulary a policy is written in can only author the
	// first policy of a deployment.
	Schema SchemaReader
	// Bootstrap reports the token's status. Optional; without it the governance
	// read omits the token's state.
	Bootstrap BootstrapReporter
	// Files is the file authoring path. Optional; without it the apply and
	// export routes answer that this deployment serves no such path, which is
	// what a deployment that has deferred R45-R49 looks like from outside.
	Files FileApplier
	// MaxRequestBytes bounds a revision body. Zero selects
	// [DefaultMaxRevisionBytes].
	MaxRequestBytes int64
	// MaxApplyBytes bounds an apply body. Zero selects [DefaultMaxApplyBytes].
	MaxApplyBytes int64
}

// Policies serves the authoring endpoints.
type Policies struct {
	governance    Governor
	policies      PolicyLister
	schema        SchemaReader
	bootstrap     BootstrapReporter
	files         FileApplier
	maxBytes      int64
	maxApplyBytes int64
}

var _ Provider = (*Policies)(nil)

// NewPolicies builds the authoring surface.
func NewPolicies(cfg PoliciesConfig) (*Policies, error) {
	if cfg.Governance == nil {
		return nil, errors.New("api: the policy surface requires a governance service")
	}
	if cfg.Policies == nil {
		return nil, errors.New("api: the policy surface requires a policy reader")
	}
	if cfg.Schema == nil {
		return nil, errors.New("api: the policy surface requires a schema reader")
	}
	p := &Policies{
		governance:    cfg.Governance,
		policies:      cfg.Policies,
		schema:        cfg.Schema,
		bootstrap:     cfg.Bootstrap,
		files:         cfg.Files,
		maxBytes:      cfg.MaxRequestBytes,
		maxApplyBytes: cfg.MaxApplyBytes,
	}
	if p.maxBytes <= 0 {
		p.maxBytes = DefaultMaxRevisionBytes
	}
	if p.maxApplyBytes <= 0 {
		p.maxApplyBytes = DefaultMaxApplyBytes
	}
	return p, nil
}

// Routes implements [Provider].
func (p *Policies) Routes() []Route {
	return []Route{
		{Name: "policy-list", Surface: SurfaceConsole, Pattern: PolicyListPattern,
			Auth: AuthUser, Handler: http.HandlerFunc(p.list)},
		{Name: "schema-read", Surface: SurfaceConsole, Pattern: SchemaReadPattern,
			Auth: AuthUser, Handler: http.HandlerFunc(p.readSchema)},
		{Name: "revision-preview", Surface: SurfaceConsole, Pattern: RevisionPreviewPattern,
			Auth: AuthUser, Handler: http.HandlerFunc(p.preview)},
		{Name: "revision-submit", Surface: SurfaceConsole, Pattern: RevisionSubmitPattern,
			Auth: AuthUser, Handler: http.HandlerFunc(p.propose)},
		{Name: "revision-read", Surface: SurfaceConsole, Pattern: RevisionReadPattern,
			Auth: AuthUser, Handler: http.HandlerFunc(p.read)},
		{Name: "revision-withdraw", Surface: SurfaceConsole, Pattern: RevisionWithdrawPattern,
			Auth: AuthUser, Handler: http.HandlerFunc(p.withdraw)},
		{Name: "policy-apply", Surface: SurfaceConsole, Pattern: PolicyApplyPattern,
			Auth: AuthUser, Handler: http.HandlerFunc(p.apply)},
		{Name: "policy-export", Surface: SurfaceConsole, Pattern: PolicyExportPattern,
			Auth: AuthUser, Handler: http.HandlerFunc(p.export)},
		{Name: "governance-read", Surface: SurfaceConsole, Pattern: GovernanceReadPattern,
			Auth: AuthUser, Handler: http.HandlerFunc(p.readGovernance)},
		{Name: "governance-lock", Surface: SurfaceConsole, Pattern: GovernanceLockPattern,
			Auth: AuthUser, Handler: http.HandlerFunc(p.lock)},
	}
}

// PolicyView is one effective policy as the console sees it.
//
// The document is the exchange-format text, not a struct dump. It is what an
// author reads in a diff and what the file path round-trips, and shipping
// anything else would give the console a second idea of what a policy is.
type PolicyView struct {
	ID       string       `json:"id"`
	Version  int64        `json:"version"`
	Origin   store.Origin `json:"origin"`
	Reserved bool         `json:"reserved"`
	Document string       `json:"document"`
}

// PolicyListResponse is the effective set.
type PolicyListResponse struct {
	Policies []PolicyView `json:"policies"`
}

func (p *Policies) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := callerOf(w, r); !ok {
		return
	}
	records, err := p.policies.EffectivePolicies(r.Context())
	if err != nil {
		writeRevisionError(w, err)
		return
	}
	out := PolicyListResponse{Policies: make([]PolicyView, 0, len(records))}
	for _, rec := range records {
		out.Policies = append(out.Policies, PolicyView{
			ID:       rec.ID,
			Version:  rec.Version,
			Origin:   rec.Origin,
			Reserved: revision.IsReserved(rec.ID),
			Document: rec.Document,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// SchemaView is the schema in force, as its exchange-format document and the
// version line that names it.
//
// It is a capability and not a control. A revision's classification is computed
// against the schema the store holds whatever the submitter sends, so nothing
// here is load-bearing for R33; what it is load-bearing for is the form. A
// console that cannot read the entity types, actions and fact sources a
// deployment declares can render a blank policy and nothing else, which is what
// made editing an existing policy impossible (U15).
type SchemaView struct {
	Version  int64  `json:"version"`
	Document string `json:"document"`
}

func (p *Policies) readSchema(w http.ResponseWriter, r *http.Request) {
	if _, ok := callerOf(w, r); !ok {
		return
	}
	rec, err := p.schema.EffectiveSchema(r.Context())
	if errors.Is(err, store.ErrNotFound) {
		// Answered here rather than through the revision table, which reads a
		// missing row as a missing revision. Before installation there is no
		// schema, and that is a deployment state and not a bad request.
		writeError(w, http.StatusServiceUnavailable, "not_installed", "no policy schema is in force yet")
		return
	}
	if err != nil {
		writeRevisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, SchemaView{Version: rec.Version, Document: rec.Document})
}

// RevisionRequest is the body of a preview or a submission.
type RevisionRequest struct {
	Delta revision.Delta           `json:"delta"`
	Mode  decision.ApplicationMode `json:"application_mode,omitempty"`
}

func (p *Policies) preview(w http.ResponseWriter, r *http.Request) {
	caller, ok := callerOf(w, r)
	if !ok {
		return
	}
	body, ok := readRevisionBody(w, r, p.maxBytes)
	if !ok {
		return
	}
	view, err := p.governance.Preview(r.Context(), revision.PreviewRequest{
		Proposer: caller, Delta: body.Delta,
	})
	if err != nil {
		writeRevisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (p *Policies) propose(w http.ResponseWriter, r *http.Request) {
	caller, ok := callerOf(w, r)
	if !ok {
		return
	}
	body, ok := readRevisionBody(w, r, p.maxBytes)
	if !ok {
		return
	}
	proposal, err := p.governance.Propose(r.Context(), revision.ProposeRequest{
		Proposer: caller,
		Delta:    body.Delta,
		Mode:     body.Mode,
		// The token authorizes the caller before the lock and is ignored after
		// it. It is read from the header on every submission rather than only
		// when the mode is known, so this layer never has to ask which mode the
		// installation is in.
		BootstrapToken: r.Header.Get(BootstrapTokenHeader),
	})
	if err != nil {
		writeRevisionError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, proposal)
}

func (p *Policies) read(w http.ResponseWriter, r *http.Request) {
	if _, ok := callerOf(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "the path names no revision")
		return
	}
	proposal, err := p.governance.Get(r.Context(), id)
	if err != nil {
		writeRevisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proposal)
}

func (p *Policies) withdraw(w http.ResponseWriter, r *http.Request) {
	caller, ok := callerOf(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "the path names no revision")
		return
	}
	proposal, err := p.governance.Withdraw(r.Context(), caller, id)
	if err != nil {
		writeRevisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proposal)
}

// GovernanceView reports which regime the installation is in.
type GovernanceView struct {
	Mode      revision.Mode             `json:"mode"`
	Bootstrap *revision.BootstrapStatus `json:"bootstrap,omitempty"`
	Pending   *revision.Proposal        `json:"pending_revision,omitempty"`
}

func (p *Policies) readGovernance(w http.ResponseWriter, r *http.Request) {
	if _, ok := callerOf(w, r); !ok {
		return
	}
	mode, err := p.governance.Mode(r.Context())
	if err != nil {
		writeRevisionError(w, err)
		return
	}
	out := GovernanceView{Mode: mode}
	if p.bootstrap != nil {
		status, serr := p.bootstrap.Status(r.Context())
		if serr != nil {
			writeRevisionError(w, serr)
			return
		}
		out.Bootstrap = &status
	}
	writeJSON(w, http.StatusOK, out)
}

// LockRequest is the body of the lock endpoint.
type LockRequest struct {
	Threshold int      `json:"threshold"`
	Approvers []string `json:"approvers,omitempty"`
	Claim     string   `json:"claim,omitempty"`
}

func (p *Policies) lock(w http.ResponseWriter, r *http.Request) {
	caller, ok := callerOf(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.maxBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "the request body is too large")
		return
	}
	var body LockRequest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "the lock request could not be read: "+err.Error())
		return
	}
	err = p.governance.Lock(r.Context(), revision.LockRequest{
		Actor: caller,
		Token: r.Header.Get(BootstrapTokenHeader),
		Quorum: policy.Quorum{
			Threshold: body.Threshold,
			Approvers: policy.ApproverSet{Members: body.Approvers, Claim: body.Claim},
		},
	})
	if err != nil {
		writeRevisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"mode": string(revision.ModeQuorum)})
}

// ---------------------------------------------------------------------------
// plumbing
// ---------------------------------------------------------------------------

func callerOf(w http.ResponseWriter, r *http.Request) (*identity.Subject, bool) {
	caller, ok := identity.SubjectFromContext(r.Context())
	if !ok || caller == nil {
		// Unreachable behind RequireUser, and still checked: the day one of
		// these routes is mounted somewhere else, the failure should be a 401
		// and not a policy change attributed to nobody.
		writeError(w, http.StatusUnauthorized, "unauthenticated", "this endpoint requires an end-user credential")
		return nil, false
	}
	return caller, true
}

func readRevisionBody(w http.ResponseWriter, r *http.Request, maxBytes int64) (RevisionRequest, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "the revision body is too large")
		return RevisionRequest{}, false
	}
	var body RevisionRequest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "the revision could not be read: "+err.Error())
		return RevisionRequest{}, false
	}
	return body, true
}

// writeRevisionError maps a governance failure to a status a console can act
// on.
//
// It is a table for the same reason the mount table is: each of these is a
// refusal an author has to be able to tell apart from an outage, and a handler
// deciding case by case is how "you are not the proposer" becomes a 500 that
// pages somebody.
func writeRevisionError(w http.ResponseWriter, err error) {
	// The file authoring refusals are consulted first because one of them --
	// the gate's -- is a richer body than ErrorResponse, and because
	// PendingError unwraps to ErrRevisionPending, which the table below would
	// otherwise answer without the collection status R47 requires.
	if writeAuthoringError(w, err) {
		return
	}
	switch {
	case errors.Is(err, decision.ErrUnauthenticated):
		writeError(w, http.StatusUnauthorized, "unauthenticated", "this endpoint requires an end-user credential")
	case errors.Is(err, revision.ErrBootstrapRequired), errors.Is(err, revision.ErrBootstrapInvalid),
		errors.Is(err, revision.ErrBootstrapSpent), errors.Is(err, revision.ErrBootstrapMissing):
		// One answer for a missing, wrong and spent token. The three are
		// different errors internally because an operator has to tell "I lost
		// it" from "somebody is guessing"; a caller learns only that it is not
		// authorized.
		writeError(w, http.StatusForbidden, "bootstrap_token_required",
			"governance before the lock requires the bootstrap token printed at first start")
	case errors.Is(err, revision.ErrAlreadyLocked):
		writeError(w, http.StatusConflict, "governance_locked",
			"governance is locked, and the lock cannot be undone from inside the running system")
	case errors.Is(err, revision.ErrRevisionPending):
		writeError(w, http.StatusConflict, "revision_pending",
			"another revision is open; approvers review one diff at a time")
	case errors.Is(err, revision.ErrNotProposer):
		writeError(w, http.StatusForbidden, "not_the_proposer", "only the proposer may withdraw a revision")
	case errors.Is(err, revision.ErrUnsatisfiable):
		writeError(w, http.StatusUnprocessableEntity, "unsatisfiable_quorum", err.Error())
	case errors.Is(err, revision.ErrFloorViolated):
		writeError(w, http.StatusUnprocessableEntity, "floor_violated", err.Error())
	case errors.Is(err, revision.ErrInvalidRevision), errors.Is(err, revision.ErrInvalidDelta),
		errors.Is(err, revision.ErrDecodeDelta):
		writeError(w, http.StatusBadRequest, "invalid_revision", err.Error())
	case errors.Is(err, revision.ErrNotInstalled):
		writeError(w, http.StatusServiceUnavailable, "not_installed", "governance is not installed yet")
	case errors.Is(err, revision.ErrNotApproved), errors.Is(err, decision.ErrNotPending):
		writeError(w, http.StatusConflict, "not_pending", err.Error())
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such revision")
	default:
		// The error itself is not narrated: a console user is not the audience
		// for a database failure, and the audit chain is where it belongs.
		writeError(w, http.StatusInternalServerError, "internal_error", "the request could not be processed")
	}
}
