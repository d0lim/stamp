package api

// decisions.go is the decide half of the PEP surface: the call that creates a
// decision object (R2), and the read its creator does afterwards (R40).
//
// Four things about it are the point rather than the plumbing.
//
// The request body is the AuthZEN evaluation body plus a lifetime, and the
// response is not an AuthZEN response at all (KTD1). decide is not a call the
// specification has, and its answer is a decision object: a pending decision is
// neither an allow nor a deny, and the boolean the specification's response
// carries cannot say so. Sharing the request shape is what lets a PEP ask the
// two questions with one value; inventing a second response shape for the
// standard's endpoint is what would break a standard consumer.
//
// Both routes are on the PEP surface behind a workload credential, which is the
// only pair the mount table admits there. That is also why the approver's read
// is not here: an approver holds an end-user token and is served by the console
// surface's `GET /audit/decisions/{id}`, and one route cannot serve both
// populations (KTD2).
//
// The read is [decision.Service.Get] and nothing else. R40's rule — the creator
// or a targeted approver, and its refusal audited — lives there, and a second
// copy of it here would be a second rule to keep in step.
//
// A refused read is answered exactly as a read of a decision that does not
// exist is. A workload that is not the creator must not be able to learn from
// this surface whether an identifier names anything, so "no" is one answer with
// one status and one message, and the three ways of earning it — the identifier
// is not a decision identifier, no decision has it, the decision is not yours —
// are indistinguishable from outside.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
	"github.com/d0lim/stamp/internal/stream"
)

// The decide endpoints.
//
// The path is ours to choose — unlike [EvaluationPath], which the AuthZEN
// specification fixes — and it names the thing rather than the operation,
// because the identifier a create returns is the one the read, the approval and
// the audit row all carry.
const (
	// DecisionsPath is where a PEP creates a decision.
	DecisionsPath = "/decisions"
	// DecisionReadPattern is the creator's read of one decision.
	DecisionReadPattern = "GET " + DecisionsPath + "/{id}"
)

// CodeNotInstalled is the `error` code for the one server state several
// surfaces have to describe: this deployment holds no policy set yet.
//
// It is a constant because it was two words before it was one. decide answered
// `policy_set_stale` and the policy surface answered `not_installed`, which made
// one state two states to anyone writing a client against both — and the split
// happened by each handler reaching for whatever word was nearest, which is what
// a shared name prevents from happening again.
//
// `error` and `reason` are different vocabularies and this is why they must not
// be confused: engine.ReasonPolicySetStale is the ground a *decision* was
// reached on, carried inside a decision object that exists. This is what a
// surface says when it produced no decision at all. A client reading the two as
// one word would treat "no answer" and "answered, on this ground" as the same
// event.
const CodeNotInstalled = "not_installed"

// DefaultMaxDecisionTTL bounds the lifetime a caller may ask for.
//
// The cap is not about the request body's size but about what a request can
// leave behind: an unresolved decision holds one of its subject's outstanding
// slots (R43) until it expires, so a lifetime nobody bounded is a slot nobody
// gets back. A caller that asks for more is refused rather than quietly given
// less — a decision that expires at a different time than the caller was told
// is worse than a decision that was not created.
const DefaultMaxDecisionTTL = 24 * time.Hour

// IdempotencyKeyHeader is where a PEP names the decide attempt it is making, so
// that a retry of that attempt answers with the decision the attempt created
// rather than creating a second one (#47(a)).
//
// It is a header rather than a body field, and the choice is not arbitrary: the
// decide body is the AuthZEN evaluation request plus `ttl`, and it is that shape
// so a PEP can send one value to both `POST /decisions` and
// `POST /access/v1/evaluation` (KTD1). A retry name is a property of the HTTP
// attempt and not of the access request being judged — check has no decisions to
// deduplicate — so putting it in the body would put a field into the shared shape
// that only one of the two endpoints reads. The name is the one the industry
// already uses for this, so a client library that has an idempotency setting can
// be pointed at this endpoint without a translation layer.
const IdempotencyKeyHeader = "Idempotency-Key"

// MaxIdempotencyKeyBytes bounds a key. It is a caller-chosen string that lands
// in a column and an index, so it is bounded here and again by a CHECK in
// migration 000008 — a bound that lives only at the surface is a bound that the
// next write path does not have.
const MaxIdempotencyKeyBytes = 255

// DecisionCreator creates decisions.
//
// It is an interface rather than *decision.Service so that this surface can be
// exercised without a database, and because the composition root hands it the
// plane rather than a service: the decide path rebuilds its service when the
// policy set moves, and a surface holding the service it booted with would keep
// issuing challenges from a revision that is no longer in force.
type DecisionCreator interface {
	Decide(ctx context.Context, req decision.Request) (decision.Result, error)
}

// PolicySchemaSource reports the schema the decide path is judging against, so
// that a request's properties are interpreted against the same declarations the
// evaluation will read. Nil means this instance holds no policy set yet.
type PolicySchemaSource interface {
	Schema() *policy.Schema
}

// DecisionRequest is the decide request body: the AuthZEN evaluation request,
// plus the one thing a decision has that a check does not.
type DecisionRequest struct {
	EvaluationRequest
	// TTL is how long the decision may stay open, as a Go duration string such
	// as "30m". Empty leaves the deployment's default in place. It is a string
	// rather than a number because a number would need a unit stated somewhere
	// other than in the value, and every other duration this API takes — a
	// declared source timeout, a delay challenge — is spelled the same way.
	TTL string `json:"ttl,omitempty"`
}

// DecisionsConfig configures a [Decisions].
type DecisionsConfig struct {
	// Decisions creates decisions. Required.
	Decisions DecisionCreator
	// Access answers R40's read rule. Required: a create endpoint with no read
	// hands a PEP an identifier and no way to follow it.
	Access DecisionAccess
	// Schema reports the declarations a request is interpreted against.
	// Required.
	Schema PolicySchemaSource
	// ContextEntity is the entity type a request context binds to, as on the
	// check surface. Empty means requests carry no context entity.
	ContextEntity string
	// PropertyAliases renames incoming property keys before they are looked up
	// against the schema, as on the check surface.
	PropertyAliases map[string]string
	// MaxRequestBytes bounds the request body. Zero selects
	// DefaultMaxRequestBytes.
	MaxRequestBytes int64
	// MaxTTL bounds the lifetime a caller may ask for. Zero selects
	// DefaultMaxDecisionTTL.
	MaxTTL time.Duration
	// Audit records rate-limit refusals. Required: R43 asks for the refusal to be
	// audited, and a surface that cannot record one would be shedding load
	// invisibly — which is indistinguishable, from outside, from not being asked.
	Audit EventRecorder
	// Rate and SubjectRate are R43's rate limits (see ratelimit.go). A zero field
	// selects the default for that field; a negative rate removes the limit,
	// which is how an operator says they mean it.
	Rate        stream.RateLimit
	SubjectRate stream.RateLimit
	// MaxRateEntries bounds the limiter's table. Zero selects
	// [stream.DefaultMaxRateEntries]. It is not on the deployment surface: it is
	// a memory bound rather than a policy, and the sweep-or-refuse behaviour when
	// it fills is what makes leaving it alone safe.
	MaxRateEntries int
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Decisions serves the decide endpoints.
type Decisions struct {
	decisions DecisionCreator
	access    DecisionAccess
	schemas   PolicySchemaSource
	ctxType   string
	aliases   map[string]string
	maxBytes  int64
	maxTTL    time.Duration
	audit     EventRecorder
	limits    *decideLimiter
	now       func() time.Time
}

var _ Provider = (*Decisions)(nil)

// NewDecisions builds the decide surface.
func NewDecisions(cfg DecisionsConfig) (*Decisions, error) {
	if cfg.Decisions == nil {
		return nil, errors.New("api: the decide surface requires a decision service")
	}
	if cfg.Access == nil {
		return nil, errors.New("api: the decide surface requires a decision access rule")
	}
	if cfg.Schema == nil {
		return nil, errors.New("api: the decide surface requires a policy schema source")
	}
	if cfg.Audit == nil {
		return nil, errors.New("api: the decide surface requires an audit event recorder")
	}
	d := &Decisions{
		decisions: cfg.Decisions,
		access:    cfg.Access,
		schemas:   cfg.Schema,
		ctxType:   cfg.ContextEntity,
		aliases:   maps.Clone(cfg.PropertyAliases),
		maxBytes:  cfg.MaxRequestBytes,
		maxTTL:    cfg.MaxTTL,
		audit:     cfg.Audit,
		now:       cfg.Now,
	}
	if d.maxBytes <= 0 {
		d.maxBytes = DefaultMaxRequestBytes
	}
	if d.maxTTL <= 0 {
		d.maxTTL = DefaultMaxDecisionTTL
	}
	if d.now == nil {
		d.now = time.Now
	}
	maxEntries := cfg.MaxRateEntries
	if maxEntries <= 0 {
		maxEntries = stream.DefaultMaxRateEntries
	}
	d.limits = newDecideLimiter(cfg.Rate, cfg.SubjectRate, maxEntries, d.now)
	return d, nil
}

// Routes implements [Provider]. Both endpoints are on the PEP surface with a
// workload credential, which is the only combination the mount table admits
// there — and the reason R40's "refuse before evaluating" is not something
// these handlers have to remember.
func (d *Decisions) Routes() []Route {
	return []Route{
		{
			Name:    "decision-create",
			Surface: SurfacePEP,
			Pattern: "POST " + DecisionsPath,
			Auth:    AuthWorkload,
			Handler: http.HandlerFunc(d.create),
		},
		{
			Name:    "decision-read",
			Surface: SurfacePEP,
			Pattern: DecisionReadPattern,
			Auth:    AuthWorkload,
			Handler: http.HandlerFunc(d.read),
		},
	}
}

func (d *Decisions) create(w http.ResponseWriter, r *http.Request) {
	caller, ok := identity.SubjectFromContext(r.Context())
	if !ok || caller == nil {
		// Unreachable behind RequireWorkload, and still checked: the day this
		// route is mounted somewhere else, the failure should be a 401 and not a
		// decision attributed to nobody.
		writeError(w, http.StatusUnauthorized, "unauthenticated", "this endpoint requires a workload credential")
		return
	}

	// The caller's budget is charged before the body is read, because reading a
	// bounded body is still work and the caller is the one thing already known
	// at this point. A caller that trips here never reaches the decoder.
	callerID := caller.CallerID()
	if !d.limits.allowCaller(callerID) {
		d.refuseRate(w, r, callerID, rateRefusal{scope: rateScopeCaller, limit: d.limits.caller})
		return
	}

	req, err := decodeDecisionRequest(w, r, d.maxBytes)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "the request body is too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// The subject's budget is charged as soon as the subject is known, which is
	// the earliest this charge can happen, and still ahead of every expensive
	// thing below: the schema resolution, the evaluation, the fact lookups the
	// evaluation makes and the outstanding-cap query the lifecycle runs. Neither
	// charge is refunded when something further down refuses the request — a
	// refused request that costs nothing is a request that can be sent forever.
	if !d.limits.allowSubject(req.Subject.ID) {
		d.refuseRate(w, r, callerID, rateRefusal{
			scope: rateScopeSubject,
			limit: d.limits.subject,
			req:   req.EvaluationRequest,
		})
		return
	}

	ttl, err := req.ttl(d.maxTTL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// A key that this deployment cannot store is refused rather than dropped. A
	// caller that sent one believes its retries are safe, and silently ignoring
	// the header would leave it believing that while every retry opened another
	// decision — the failure it asked to be protected from, arriving without a
	// word.
	key, err := idempotencyKey(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	schema := d.schemas.Schema()
	if schema == nil {
		// An instance with no policy set cannot judge, and unlike the check
		// surface it has nothing honest to answer with: an AuthZEN response can
		// carry a deny with a reason, but a decision object that was never
		// created and never audited would be a record of something that did not
		// happen. So this is a refusal with a status, not a decision.
		//
		// And because it is a refusal rather than a decision, the code is
		// [CodeNotInstalled] and not the engine's reason for the same state.
		// This once answered `policy_set_stale`, which is what a *decision*
		// carries as its ground; borrowing it here made one server state look
		// like two to a client that also reads the policy surface.
		writeError(w, http.StatusServiceUnavailable, CodeNotInstalled,
			"this instance holds no policy set yet")
		return
	}
	in, err := evaluationInput(schema, req.EvaluationRequest, d.ctxType, d.aliases)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_property", err.Error())
		return
	}

	result, err := d.decisions.Decide(r.Context(), decision.Request{
		Caller: caller, Input: in, TTL: ttl, IdempotencyKey: key,
	})
	if err != nil {
		status, code, message := decisionError(err)
		writeError(w, status, code, message)
		return
	}
	if result.ID == "" {
		// A deny creates no decision row — there is no policy version to pin one
		// to — and the service has already recorded it in the audit chain. The
		// response says exactly that: a denied state, its ground, and no
		// identifier to follow, because there is nothing to follow.
		writeJSON(w, http.StatusOK, result)
		return
	}
	w.Header().Set("Location", DecisionsPath+"/"+result.ID)
	writeJSON(w, http.StatusCreated, result)
}

func (d *Decisions) read(w http.ResponseWriter, r *http.Request) {
	caller, ok := identity.SubjectFromContext(r.Context())
	if !ok || caller == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "this endpoint requires a workload credential")
		return
	}
	id := r.PathValue("id")
	if !isDecisionID(id) {
		// Answered as a missing decision rather than as a malformed request. The
		// three refusals this endpoint can give have to be one answer, and an
		// identifier that could not name a decision is the cheapest of the three
		// to tell apart if it is allowed to look different.
		writeNoSuchDecision(w)
		return
	}
	result, err := d.access.Get(r.Context(), caller, id)
	if err != nil {
		status, code, message := decisionError(err)
		writeError(w, status, code, message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ttl reads the requested lifetime, bounded.
func (req DecisionRequest) ttl(maxTTL time.Duration) (time.Duration, error) {
	if req.TTL == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(req.TTL)
	if err != nil {
		return 0, fmt.Errorf("ttl is not a duration: %w", err)
	}
	if d <= 0 {
		return 0, errors.New("ttl must be positive")
	}
	if d > maxTTL {
		return 0, fmt.Errorf("ttl %s is longer than this deployment allows (%s)", d, maxTTL)
	}
	return d, nil
}

// idempotencyKey reads and validates the retry name a request carries. An absent
// header is the empty string and no error: a caller that names nothing is
// retrying nothing, and every caller did that before this header existed.
//
// The accepted shape is deliberately narrow — printable, no spaces, bounded —
// because the value is chosen by the caller and ends up in an index, in error
// messages and in an audit trail an operator reads. A key is an opaque token the
// caller generates, so nothing legitimate needs a control character in it, and
// refusing them here is cheaper than discovering later which log line was
// forged. Whitespace is refused rather than trimmed: `"k"` and `"k "` would
// otherwise be one key on the way in and two keys in anything that echoed them.
func idempotencyKey(r *http.Request) (string, error) {
	key := r.Header.Get(IdempotencyKeyHeader)
	if key == "" {
		return "", nil
	}
	if len(key) > MaxIdempotencyKeyBytes {
		return "", fmt.Errorf("%s is longer than %d bytes", IdempotencyKeyHeader, MaxIdempotencyKeyBytes)
	}
	for i := 0; i < len(key); i++ {
		if c := key[i]; c <= ' ' || c > '~' {
			return "", fmt.Errorf("%s must be printable ascii without spaces", IdempotencyKeyHeader)
		}
	}
	return key, nil
}

// decodeDecisionRequest reads the decide body, bounded, and holds it to the same
// shape the check surface holds an evaluation request to.
func decodeDecisionRequest(w http.ResponseWriter, r *http.Request, maxBytes int64) (DecisionRequest, error) {
	var req DecisionRequest
	dec := jsonDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	if err := dec.Decode(&req); err != nil {
		return DecisionRequest{}, fmt.Errorf("request body is not a valid decide request: %w", err)
	}
	if err := req.validate(); err != nil {
		return DecisionRequest{}, err
	}
	return req, nil
}

// decisionError maps a lifecycle failure to a status a PEP can act on.
//
// It is a table for the same reason [approvalError] is, and it differs from that
// one in a single deliberate place: there, a caller who may not act is told so
// with a 403, because the caller is a named person on the console surface who
// has to be able to tell "not yours" from "gone". Here the caller is any
// workload holding a valid credential, and telling it apart is exactly what must
// not be possible — so refusal and absence are one answer.
func decisionError(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, decision.ErrUnauthenticated):
		return http.StatusUnauthorized, "unauthenticated", "this endpoint requires a workload credential"
	case errors.Is(err, decision.ErrNotAuthorized), errors.Is(err, store.ErrNotFound):
		return noSuchDecision()
	case errors.Is(err, challenge.ErrNoHandler), errors.Is(err, challenge.ErrUnsupportedSpec),
		errors.Is(err, challenge.ErrGroupSourceUnsupported):
		// The policy demands a challenge kind this build cannot issue. It is not
		// the caller's mistake and it is not a fault either: it is a deployment
		// that has not configured what its policies ask for.
		return http.StatusNotImplemented, "unsupported_challenge",
			"this build cannot issue a challenge that policy demands"
	default:
		// The error itself is not narrated: a PEP is not the audience for a
		// database failure, and the audit chain is where it belongs.
		return http.StatusInternalServerError, "internal_error", "the decision could not be processed"
	}
}

// noSuchDecision is the single answer this surface gives to every reason a
// caller may not have a decision. It is one function so that the three call
// sites cannot drift into three answers.
func noSuchDecision() (status int, code, message string) {
	return http.StatusNotFound, "not_found", "no such decision"
}

func writeNoSuchDecision(w http.ResponseWriter) {
	status, code, message := noSuchDecision()
	writeError(w, status, code, message)
}

// isDecisionID reports whether an identifier could name a decision at all.
//
// The decisions table keys on a uuid, so an identifier that is not one is a
// query error rather than an empty result — a 500 for what is a caller's typo,
// and a third distinguishable answer on an endpoint whose refusals must all look
// alike. The shape checked here is the one [store.NewDecisionID] writes.
func isDecisionID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
