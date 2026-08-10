package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/policy"
)

// DryRunPath is the console endpoint that evaluates an unsaved policy.
//
// It lives on the console surface, never on the PEP one. A dry run answers
// "what would this draft do", which is an authoring question asked by a person;
// serving it beside the check endpoint would let a workload credential ask the
// engine to evaluate a policy nobody approved.
const DryRunPath = "/console/v1/policies/dry-run"

// EntityInput is one bound entity of a dry run's sample request.
//
// Attributes are the filled-in form the entity declaration renders, not a free
// JSON object: every key must be an attribute the schema declares for Type, and
// an undeclared one is refused rather than dropped. That refusal is the
// difference R44 draws between a rendered form and free-form input — on this
// surface an unrecognised field is an authoring mistake worth reporting, where
// on the AuthZEN surface it is a PEP extension worth tolerating.
type EntityInput struct {
	Type       string         `json:"type"`
	ID         string         `json:"id,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// DryRunInput is the sample request a dry run is evaluated against.
type DryRunInput struct {
	Action   string      `json:"action"`
	Subject  EntityInput `json:"subject"`
	Resource EntityInput `json:"resource"`
	Context  EntityInput `json:"context,omitzero"`
}

// DryRunRequest is the dry run request body.
type DryRunRequest struct {
	// Document is the policy set in the exchange format — the same YAML a file
	// would carry. It may include a Schema document; when it does not, the
	// deployment's effective schema is used, so a draft can be tried against
	// what is actually in force.
	Document string `json:"document"`
	// PolicyID selects which policy in the document to evaluate. It may be
	// omitted when the document holds exactly one.
	PolicyID string `json:"policy_id,omitempty"`
	// Input is the sample request.
	Input DryRunInput `json:"input"`
}

// ChallengeSummary describes a challenge that would fire.
type ChallengeSummary struct {
	Type   string         `json:"type"`
	Detail map[string]any `json:"detail,omitempty"`
}

// DryRunResponse is the dry run result.
type DryRunResponse struct {
	// PolicyID is the policy that was evaluated.
	PolicyID string `json:"policy_id"`
	// Matched reports whether the policy applies to the sample at all.
	Matched bool `json:"matched"`
	// Holds reports whether the whole condition held.
	Holds bool `json:"holds"`
	// Decision and Reason are the verdict the check path would have returned.
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	// Conditions are the per-node results, root first.
	Conditions []engine.NodeTrace `json:"conditions"`
	// Challenges are the challenges that would fire.
	Challenges []ChallengeSummary `json:"challenges"`
	// Sources are the fact source calls the condition reached.
	Sources []string `json:"sources,omitempty"`
	// Stored is always false, and is in the response so that the guarantee is
	// something a client can assert on rather than something it has to trust.
	Stored bool `json:"stored"`
	// Error is set when the evaluation could not complete.
	Error string `json:"error,omitempty"`
}

// DiagnosticsResponse returns U2's structured validation failures unchanged.
//
// Unchanged is the contract: the pointer, code and message a form needs to put
// an error next to the field that caused it are the validator's, and rewording
// them here would give the console two different vocabularies for the same
// mistake depending on which door the policy came through.
type DiagnosticsResponse struct {
	Error       string             `json:"error"`
	Diagnostics policy.Diagnostics `json:"diagnostics"`
}

// DryRunAPIConfig configures a [DryRunAPI].
type DryRunAPIConfig struct {
	// Service supplies the effective schema and the fact plane. Required.
	Service *engine.CheckService
	// MaxRequestBytes bounds the request body. Zero selects
	// DefaultMaxRequestBytes.
	MaxRequestBytes int64
	// Timeout bounds one dry run. Zero selects DefaultDryRunTimeout.
	Timeout time.Duration
}

// DefaultDryRunTimeout bounds one dry run, whose fact lookups reach the same
// sources a served request does.
const DefaultDryRunTimeout = 10 * time.Second

// DryRunAPI serves the dry run endpoint.
//
// It holds no writer of any kind. "Stores nothing" is therefore a property of
// what this type can reach rather than a branch someone has to keep taking:
// there is no store handle, no audit chain writer, and no policy repository in
// it to write through.
type DryRunAPI struct {
	service  *engine.CheckService
	maxBytes int64
	timeout  time.Duration
}

// NewDryRunAPI builds the dry run surface.
func NewDryRunAPI(cfg DryRunAPIConfig) (*DryRunAPI, error) {
	if cfg.Service == nil {
		return nil, errors.New("api: dry run surface requires a check service")
	}
	a := &DryRunAPI{service: cfg.Service, maxBytes: cfg.MaxRequestBytes, timeout: cfg.Timeout}
	if a.maxBytes <= 0 {
		a.maxBytes = DefaultMaxRequestBytes
	}
	if a.timeout <= 0 {
		a.timeout = DefaultDryRunTimeout
	}
	return a, nil
}

// Routes implements [Provider].
func (a *DryRunAPI) Routes() []Route {
	return []Route{{
		Name:    "policy-dry-run",
		Surface: SurfaceConsole,
		Pattern: "POST " + DryRunPath,
		Auth:    AuthUser,
		Handler: http.HandlerFunc(a.dryRun),
	}}
}

func (a *DryRunAPI) dryRun(w http.ResponseWriter, r *http.Request) {
	var req DryRunRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, a.maxBytes))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if strings.TrimSpace(req.Document) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "document is required")
		return
	}

	set, diags := a.decodeSet(req.Document)
	if len(diags) > 0 {
		writeJSON(w, http.StatusBadRequest, DiagnosticsResponse{Error: "invalid_policy", Diagnostics: diags})
		return
	}
	target, err := selectPolicy(set, req.PolicyID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	in, err := sampleInput(&set.Schema, req.Input)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), a.timeout)
	defer cancel()
	trace, err := engine.Trace(ctx, &set.Schema, target, in, a.service.Resolver())
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "evaluation_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, DryRunResponse{
		PolicyID:   target.ID,
		Matched:    trace.Matched,
		Holds:      trace.Holds,
		Decision:   trace.Decision.String(),
		Reason:     string(trace.Reason),
		Conditions: trace.Nodes,
		Challenges: summarizeChallenges(trace.Challenges),
		Sources:    renderCalls(trace.SourceCalls),
		Stored:     false,
		Error:      trace.Error,
	})
}

// decodeSet parses the submitted document and completes it with the effective
// schema when it carries none.
//
// The effective schema is deep-copied first. The live one belongs to a snapshot
// that concurrent requests are being judged against, and the policy package's
// normalization sorts declarations in place — so handing it to anything that
// might normalize would let a dry run reorder the schema a served request is
// reading.
func (a *DryRunAPI) decodeSet(document string) (*policy.Set, policy.Diagnostics) {
	set, err := policy.Decode(strings.NewReader(document))
	if err != nil {
		return nil, asDiagnostics(err)
	}
	if schemaEmpty(&set.Schema) {
		effective := a.service.Schema()
		if effective == nil {
			return nil, policy.Diagnostics{{
				Pointer: "",
				Code:    policy.CodeMissingField,
				Message: "the document declares no schema and this instance has no effective schema to borrow",
			}}
		}
		set.Schema = copySchema(effective)
	}
	if diags := policy.Validate(set); len(diags) > 0 {
		return nil, diags
	}
	return set, nil
}

func selectPolicy(set *policy.Set, id string) (*policy.Policy, error) {
	switch {
	case id != "":
		p, ok := set.Policy(id)
		if !ok {
			return nil, fmt.Errorf("the document declares no policy %q", id)
		}
		return p, nil
	case len(set.Policies) == 1:
		return &set.Policies[0], nil
	case len(set.Policies) == 0:
		return nil, errors.New("the document declares no policy to evaluate")
	default:
		return nil, errors.New("the document declares several policies: name one with policy_id")
	}
}

// sampleInput converts the filled form into an evaluation input, refusing any
// attribute the schema does not declare.
func sampleInput(schema *policy.Schema, in DryRunInput) (engine.Input, error) {
	if in.Action == "" {
		return engine.Input{}, errors.New("input needs an action")
	}
	subject, err := formEntity(schema, in.Subject)
	if err != nil {
		return engine.Input{}, fmt.Errorf("subject: %w", err)
	}
	resource, err := formEntity(schema, in.Resource)
	if err != nil {
		return engine.Input{}, fmt.Errorf("resource: %w", err)
	}
	context, err := formEntity(schema, in.Context)
	if err != nil {
		return engine.Input{}, fmt.Errorf("context: %w", err)
	}
	return engine.Input{Action: in.Action, Subject: subject, Resource: resource, Context: context}, nil
}

func formEntity(schema *policy.Schema, e EntityInput) (engine.Entity, error) {
	if e.Type == "" {
		return engine.Entity{}, nil
	}
	declared, ok := schema.Entity(e.Type)
	if !ok {
		return engine.Entity{}, fmt.Errorf("entity type %q is not declared", e.Type)
	}
	attributes := make(map[string]any, len(e.Attributes)+1)
	for name, raw := range e.Attributes {
		attr, isDeclared := declared.Attribute(name)
		if !isDeclared {
			return engine.Entity{}, fmt.Errorf("entity type %q declares no attribute %q", e.Type, name)
		}
		value, err := attributeValue(attr.Type, raw)
		if err != nil {
			return engine.Entity{}, fmt.Errorf("attribute %q: %w", name, err)
		}
		attributes[name] = value
	}
	if attr, hasID := declared.Attribute("id"); hasID && attr.Type == policy.TypeString && e.ID != "" {
		attributes["id"] = e.ID
	}
	return engine.Entity{Type: e.Type, ID: e.ID, Attributes: attributes}, nil
}

func summarizeChallenges(challenges []policy.Challenge) []ChallengeSummary {
	out := make([]ChallengeSummary, 0, len(challenges))
	for _, c := range challenges {
		summary := ChallengeSummary{Type: string(c.ChallengeType()), Detail: map[string]any{}}
		switch v := c.(type) {
		case policy.Quorum:
			summary.Detail["threshold"] = v.Threshold
			summary.Detail["approvers"] = approverSummary(v.Approvers)
		case policy.MFA:
			summary.Detail["mode"] = string(v.Mode)
			if len(v.ACRValues) > 0 {
				summary.Detail["acr_values"] = v.ACRValues
			}
		case policy.Delay:
			summary.Detail["duration"] = v.Duration.String()
			if v.CancellableBy != nil {
				summary.Detail["cancellable_by"] = approverSummary(*v.CancellableBy)
			}
		case policy.External:
			summary.Detail["target"] = v.Target
		}
		out = append(out, summary)
	}
	return out
}

func approverSummary(a policy.ApproverSet) map[string]any {
	switch {
	case len(a.Members) > 0:
		return map[string]any{"members": a.Members}
	case a.Claim != "":
		return map[string]any{"claim": a.Claim}
	case a.Source != nil:
		return map[string]any{"source": a.Source.Name}
	default:
		return map[string]any{}
	}
}

func renderCalls(calls []engine.SourceCall) []string {
	if len(calls) == 0 {
		return nil
	}
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = c.String()
	}
	return out
}

func schemaEmpty(s *policy.Schema) bool {
	return len(s.Entities) == 0 && len(s.Actions) == 0 && len(s.Sources) == 0
}

// copySchema returns a schema that shares no slice with its argument.
func copySchema(s *policy.Schema) policy.Schema {
	out := policy.Schema{
		Entities: make([]policy.EntityType, len(s.Entities)),
		Actions:  append([]policy.Action(nil), s.Actions...),
		Sources:  make([]policy.SourceDecl, len(s.Sources)),
	}
	for i, e := range s.Entities {
		out.Entities[i] = policy.EntityType{
			Name:       e.Name,
			Attributes: append([]policy.Attribute(nil), e.Attributes...),
		}
	}
	for i, src := range s.Sources {
		out.Sources[i] = src
		out.Sources[i].Params = append([]policy.Param(nil), src.Params...)
	}
	return out
}

func asDiagnostics(err error) policy.Diagnostics {
	var diags policy.Diagnostics
	if errors.As(err, &diags) {
		return diags
	}
	return policy.Diagnostics{{Pointer: "", Code: policy.CodeInvalidDocument, Message: err.Error()}}
}

var _ Provider = (*DryRunAPI)(nil)
