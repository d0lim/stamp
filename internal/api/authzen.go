package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strconv"
	"time"

	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
)

// EvaluationPath is the AuthZEN Access Evaluation endpoint. The path is fixed
// by the specification, not by us.
const EvaluationPath = "/access/v1/evaluation"

// The namespaced keys STAMP puts in an AuthZEN response context.
//
// Everything STAMP knows that AuthZEN does not goes here and nowhere else. The
// verdict itself is the specification's boolean, so a standard consumer that
// drops the context reads exactly the same allow or deny — which is the whole
// of what compatibility with a standard buys, and is worth more than a richer
// top-level response that only our own clients could read.
const (
	// ContextKeyReason carries the machine-readable ground for the verdict.
	ContextKeyReason = "stamp.reason"
	// ContextKeyPolicyID names the policy the verdict is attributed to.
	ContextKeyPolicyID = "stamp.policy_id"
	// ContextKeyPolicyVersion names the policy set revision that judged.
	ContextKeyPolicyVersion = "stamp.policy_version"
	// ContextKeyObligations carries the obligations attached to the verdict.
	// The check path never produces any — obligations come with a decision —
	// so it is present and empty, because a consumer that has to distinguish
	// "no obligations" from "this server does not report obligations" would
	// have to special-case us.
	ContextKeyObligations = "stamp.obligations"
)

// DefaultMaxRequestBytes bounds a request body. It is generous for an
// evaluation request and small enough that an unauthenticated peer cannot make
// the surface allocate.
const DefaultMaxRequestBytes = 1 << 20

// Entity is an AuthZEN subject or resource.
type Entity struct {
	// Type is the entity type.
	Type string `json:"type"`
	// ID identifies the instance.
	ID string `json:"id"`
	// Properties carries additional attributes. Properties the schema does not
	// declare are ignored rather than refused: the specification allows a PEP
	// to send them, and a policy cannot read one, so refusing them would break
	// interoperability to protect nothing.
	Properties map[string]any `json:"properties,omitempty"`
}

// ActionRef is an AuthZEN action.
type ActionRef struct {
	// Name is the action name.
	Name string `json:"name"`
	// Properties carries additional attributes of the action.
	Properties map[string]any `json:"properties,omitempty"`
}

// EvaluationRequest is the AuthZEN Access Evaluation request body.
//
// It is a package-level type rather than one of [CheckAPI]'s, because the decide
// surface takes the same body (KTD1): a PEP that has asked a check question has
// to be able to ask the decide question with the value it already built.
type EvaluationRequest struct {
	Subject  Entity         `json:"subject"`
	Resource Entity         `json:"resource"`
	Action   ActionRef      `json:"action"`
	Context  map[string]any `json:"context,omitempty"`
}

// validate is the shape check every surface that takes this body runs. It is
// stated once so that check and decide cannot come to disagree about what a
// well-formed access request is.
func (req EvaluationRequest) validate() error {
	switch {
	case req.Subject.Type == "" || req.Subject.ID == "":
		return errors.New("subject needs a type and an id")
	case req.Action.Name == "":
		return errors.New("action needs a name")
	case req.Resource.Type == "" || req.Resource.ID == "":
		return errors.New("resource needs a type and an id")
	}
	return nil
}

// EvaluationResponse is the AuthZEN Access Evaluation response body.
type EvaluationResponse struct {
	// Decision is the specification's boolean verdict.
	Decision bool `json:"decision"`
	// Context carries the namespaced STAMP keys.
	Context map[string]any `json:"context,omitempty"`
}

// ErrorResponse is the body returned for a malformed request.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// CheckAPIConfig configures a [CheckAPI].
type CheckAPIConfig struct {
	// Service evaluates check requests. Required.
	Service *engine.CheckService
	// Audit receives one event per judgment. Required: a PEP surface that
	// records nothing cannot satisfy R40.
	Audit *AuditBuffer
	// ContextEntity is the entity type an AuthZEN request context binds to.
	// Empty means requests carry no context entity, and a policy binding one
	// therefore matches nothing.
	ContextEntity string
	// PropertyAliases renames incoming property keys before they are looked up
	// against the schema.
	//
	// The two vocabularies do not coincide and cannot be made to. An AuthZEN
	// property key is any JSON member name, and callers in the wild write
	// `ownerID`; a STAMP attribute name becomes a CEL identifier and is held to
	// lower_snake_case. Deriving one from the other automatically would be a
	// guess that silently changes decisions when it guesses wrong, so the
	// mapping is operator configuration: an explicit, auditable table.
	PropertyAliases map[string]string
	// MaxRequestBytes bounds the request body. Zero selects
	// DefaultMaxRequestBytes.
	MaxRequestBytes int64
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// CheckAPI serves the AuthZEN Access Evaluation endpoint.
type CheckAPI struct {
	service  *engine.CheckService
	audit    *AuditBuffer
	ctxType  string
	aliases  map[string]string
	maxBytes int64
	now      func() time.Time
}

// NewCheckAPI builds the check surface.
func NewCheckAPI(cfg CheckAPIConfig) (*CheckAPI, error) {
	if cfg.Service == nil {
		return nil, errors.New("api: check surface requires a check service")
	}
	if cfg.Audit == nil {
		return nil, errors.New("api: check surface requires an audit buffer")
	}
	a := &CheckAPI{
		service:  cfg.Service,
		audit:    cfg.Audit,
		ctxType:  cfg.ContextEntity,
		aliases:  maps.Clone(cfg.PropertyAliases),
		maxBytes: cfg.MaxRequestBytes,
		now:      cfg.Now,
	}
	if a.maxBytes <= 0 {
		a.maxBytes = DefaultMaxRequestBytes
	}
	if a.now == nil {
		a.now = time.Now
	}
	return a, nil
}

// Routes implements [Provider]. The endpoint is on the PEP surface with a
// workload credential, which is the only combination the mount table admits
// there.
func (a *CheckAPI) Routes() []Route {
	return []Route{{
		Name:    "authzen-access-evaluation",
		Surface: SurfacePEP,
		Pattern: "POST " + EvaluationPath,
		Auth:    AuthWorkload,
		Handler: http.HandlerFunc(a.evaluate),
	}}
}

func (a *CheckAPI) evaluate(w http.ResponseWriter, r *http.Request) {
	caller, _ := identity.SubjectFromContext(r.Context())
	callerID := caller.CallerID()

	// The buffer gate runs before the body is read. An instance that cannot
	// record what it decided has, in fail-closed mode, nothing to decide.
	if a.audit.FailClosed() {
		a.respond(w, engine.DenyResult(engine.ReasonAuditUnavailable), "")
		return
	}

	req, err := decodeEvaluationRequest(w, r, a.maxBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	schema := a.service.Schema()
	if schema == nil {
		a.record(r, callerID, req, engine.DenyResult(engine.ReasonPolicySetStale))
		a.respond(w, engine.DenyResult(engine.ReasonPolicySetStale), "")
		return
	}
	in, err := a.inputFor(schema, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_property", err.Error())
		return
	}

	result, err := a.service.Evaluate(r.Context(), in)
	if err != nil {
		// An evaluation that could not complete is a deny, never a 500 with no
		// verdict: the caller is a PEP that has to do something, and the only
		// safe something is refusing.
		result = engine.DenyResult(engine.ReasonEvaluationFailed)
	}
	revision := a.service.Revision()
	a.record(r, callerID, req, result)
	a.respond(w, result, revision)
}

func (a *CheckAPI) record(r *http.Request, callerID string, req EvaluationRequest, result engine.CheckResult) {
	a.audit.Record(r.Context(), Event{
		Kind:     EventCheck,
		Time:     a.now(),
		CallerID: callerID,
		Action:   req.Action.Name,
		Subject:  req.Subject.Type + ":" + req.Subject.ID,
		Resource: req.Resource.Type + ":" + req.Resource.ID,
		Decision: result.Decision().String(),
		Reason:   string(result.Reason()),
		PolicyID: result.PolicyID(),
		Revision: string(a.service.Revision()),
		Method:   r.Method,
		Path:     r.URL.Path,
		Allowed:  result.Allowed(),
	})
}

func (a *CheckAPI) respond(w http.ResponseWriter, result engine.CheckResult, revision engine.Revision) {
	resp := EvaluationResponse{
		Decision: result.Allowed(),
		Context: map[string]any{
			ContextKeyReason:      string(result.Reason()),
			ContextKeyObligations: []any{},
		},
	}
	if revision != "" {
		resp.Context[ContextKeyPolicyVersion] = string(revision)
	}
	if id := result.PolicyID(); id != "" {
		resp.Context[ContextKeyPolicyID] = id
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *CheckAPI) inputFor(schema *policy.Schema, req EvaluationRequest) (engine.Input, error) {
	return evaluationInput(schema, req, a.ctxType, a.aliases)
}

// evaluationInput turns an AuthZEN request into an evaluation input.
//
// The mapping is where the two models meet. AuthZEN entities carry an
// identifier in the envelope and everything else in a free-form property bag;
// STAMP conditions read declared, typed attributes. So the identifier becomes
// the declared `id` attribute when the schema has one, declared properties are
// converted to their declared types, and undeclared properties are dropped.
//
// It is one function and not one per surface. check and decide take the same
// body and must reach the same input from it — a decision issued against
// attributes that a check of the same request would not have seen is the
// divergence that makes the two calls untrustworthy as a pair.
func evaluationInput(schema *policy.Schema, req EvaluationRequest,
	ctxType string, aliases map[string]string,
) (engine.Input, error) {
	subject, err := entityInput(schema, req.Subject, aliases)
	if err != nil {
		return engine.Input{}, fmt.Errorf("subject: %w", err)
	}
	resource, err := entityInput(schema, req.Resource, aliases)
	if err != nil {
		return engine.Input{}, fmt.Errorf("resource: %w", err)
	}
	in := engine.Input{Action: req.Action.Name, Subject: subject, Resource: resource}
	if ctxType != "" {
		context, err := entityInput(schema, Entity{Type: ctxType, Properties: req.Context}, aliases)
		if err != nil {
			return engine.Input{}, fmt.Errorf("context: %w", err)
		}
		in.Context = context
	}
	return in, nil
}

func entityInput(schema *policy.Schema, e Entity, aliases map[string]string) (engine.Entity, error) {
	out := engine.Entity{Type: e.Type, ID: e.ID}
	declared, ok := schema.Entity(e.Type)
	if !ok {
		// An entity type this deployment does not declare matches no policy,
		// so the request is answered with no_matching_policy rather than with
		// an error. Filling in attributes for it would be inventing a shape.
		return out, nil
	}
	attributes := make(map[string]any, len(e.Properties)+1)
	for name, raw := range e.Properties {
		if alias, renamed := aliases[name]; renamed {
			name = alias
		}
		attr, declaredAttr := declared.Attribute(name)
		if !declaredAttr {
			continue
		}
		value, err := attributeValue(attr.Type, raw)
		if err != nil {
			return engine.Entity{}, fmt.Errorf("property %q: %w", name, err)
		}
		attributes[name] = value
	}
	// The envelope identifier wins over any property of the same name: `id` is
	// where AuthZEN puts identity, and two spellings of it must not disagree.
	if attr, hasID := declared.Attribute("id"); hasID && attr.Type == policy.TypeString && e.ID != "" {
		attributes["id"] = e.ID
	}
	out.Attributes = attributes
	return out, nil
}

// attributeValue converts one JSON value to the representation a declared type
// uses.
//
// Numbers arrive as [json.Number] rather than float64 so that an int attribute
// is read exactly. A declared attribute whose value cannot be converted is an
// error, not a drop: the policy will read that attribute, and a silently
// missing value would turn a client mistake into a decision.
func attributeValue(t policy.Type, raw any) (any, error) {
	if t.IsList() {
		items, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("expected a list of %s, got %T", t.Elem(), raw)
		}
		out := make([]any, len(items))
		for i, item := range items {
			value, err := attributeValue(t.Elem(), item)
			if err != nil {
				return nil, fmt.Errorf("element %d: %w", i, err)
			}
			out[i] = value
		}
		return out, nil
	}
	switch t {
	case policy.TypeBool:
		if v, ok := raw.(bool); ok {
			return v, nil
		}
	case policy.TypeInt:
		switch v := raw.(type) {
		case json.Number:
			n, err := v.Int64()
			if err != nil {
				return nil, fmt.Errorf("expected an int, got %s", v.String())
			}
			return n, nil
		case float64:
			n := int64(v)
			if float64(n) != v {
				return nil, fmt.Errorf("expected an int, got %s", strconv.FormatFloat(v, 'g', -1, 64))
			}
			return n, nil
		}
	case policy.TypeDouble:
		switch v := raw.(type) {
		case json.Number:
			n, err := v.Float64()
			if err != nil {
				return nil, fmt.Errorf("expected a double, got %s", v.String())
			}
			return n, nil
		case float64:
			return v, nil
		}
	case policy.TypeString:
		if v, ok := raw.(string); ok {
			return v, nil
		}
	case policy.TypeTimestamp:
		if v, ok := raw.(string); ok {
			ts, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return nil, fmt.Errorf("expected an RFC 3339 timestamp: %w", err)
			}
			return ts.UTC(), nil
		}
	case policy.TypeDuration:
		if v, ok := raw.(string); ok {
			d, err := time.ParseDuration(v)
			if err != nil {
				return nil, fmt.Errorf("expected a duration: %w", err)
			}
			return d, nil
		}
	default:
		return nil, fmt.Errorf("unknown declared type %q", t)
	}
	return nil, fmt.Errorf("expected %s, got %T", t, raw)
}

// jsonDecoder is how every body whose values reach [attributeValue] is read.
//
// UseNumber is not a preference: an int attribute read through float64 is an
// attribute a policy can compare wrongly, and a surface that forgot the call
// would fail only on the values large enough to matter. Stating it once is what
// keeps a second surface from forgetting it.
func jsonDecoder(r io.Reader) *json.Decoder {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	return dec
}

func decodeEvaluationRequest(w http.ResponseWriter, r *http.Request, maxBytes int64) (EvaluationRequest, error) {
	var req EvaluationRequest
	dec := jsonDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	if err := dec.Decode(&req); err != nil {
		return EvaluationRequest{}, fmt.Errorf("request body is not a valid evaluation request: %w", err)
	}
	if err := req.validate(); err != nil {
		return EvaluationRequest{}, err
	}
	return req, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorResponse{Error: code, Message: message})
}

var _ Provider = (*CheckAPI)(nil)
