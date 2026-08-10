package mfa

// main_test.go holds the fixtures every test in this package builds on.
//
// There is no mock IdP here. U20 stood one up because a Subject carrying claims
// could only be produced by verifying a token, and U10 would have been the third
// copy of that ninety-line fixture; [identity.NewSubject] exists now instead, so
// the completions these tests judge are assembled directly and the JWKS round
// trip is left to the package that owns it.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
)

const (
	testIssuer   = "https://idp.example.test/realms/stamp"
	testClientID = "stamp-console"
	testAudience = "stamp"
	testSubject  = "alice"
	acrGold      = "gold"
	acrSilver    = "silver"
	// acrDowngraded is what U0 watched a real IdP return for an `acr` request
	// it could not satisfy: not an error, just a weaker class.
	acrDowngraded = "1"
)

var testNow = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

// recordingInitiator is an [Initiator] that answers without a network and keeps
// what it was asked, so that "the acr values were carried" and "no second
// request was made" are assertions rather than beliefs.
type recordingInitiator struct {
	method  Method
	calls   []InitiateRequest
	err     error
	failing bool
}

func (r *recordingInitiator) Initiate(_ context.Context, req InitiateRequest) (InitiateResult, error) {
	r.calls = append(r.calls, req)
	if r.failing {
		return InitiateResult{}, r.err
	}
	method := r.method
	if method == "" {
		method = MethodStepUp
	}
	return InitiateResult{
		Method:           method,
		AuthorizationURL: "https://idp.example.test/authorize?state=" + req.Correlator,
		AuthReqID:        "req-" + req.Correlator,
	}, nil
}

func testDecision(t *testing.T) challenge.DecisionContext {
	t.Helper()
	return challenge.DecisionContext{
		DecisionID:   "dec-A",
		CallerID:     "workload:pep#payments",
		SubjectID:    testSubject,
		ResourceID:   "account:9931",
		Action:       "transfer",
		PolicyID:     "high-value-transfer",
		Request:      json.RawMessage(`{"amount":250000,"payee":"acme"}`),
		FactSnapshot: json.RawMessage(`{"velocity.24h":3}`),
		Obligations:  json.RawMessage(`[]`),
		CreatedAt:    testNow,
		ExpiresAt:    testNow.Add(15 * time.Minute),
	}
}

func testConfig(init Initiator) Config {
	return Config{
		Initiator:        init,
		AllowedACRValues: []string{acrGold, acrSilver},
		Issuer:           testIssuer,
		ClientID:         testClientID,
		Audience:         testAudience,
	}
}

func newTestHandler(t *testing.T, cfg Config) *Delegated {
	t.Helper()
	h, err := NewDelegated(cfg)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	return h
}

// issueRequestFor is the plain delegated issue request, for the tests that care
// about what Issue did rather than about what it froze.
func issueRequestFor(dec challenge.DecisionContext) challenge.IssueRequest {
	return challenge.IssueRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
		Spec:     policy.MFA{Mode: policy.MFADelegated},
		Decision: dec,
		Now:      testNow,
	}
}

// issue opens one challenge and returns the frozen detail, encoded the way the
// store would hand it back.
func issue(t *testing.T, h *Delegated, spec policy.MFA, dec challenge.DecisionContext, now time.Time) (Detail, json.RawMessage) {
	t.Helper()
	out, err := h.Issue(t.Context(), challenge.IssueRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Ordinal: 0, Kind: policy.ChallengeMFA},
		Spec:     spec,
		Decision: dec,
		Now:      now,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if out.State != challenge.StatePending {
		t.Fatalf("issue state = %q, want pending", out.State)
	}
	raw, err := json.Marshal(out.Detail)
	if err != nil {
		t.Fatalf("encode detail: %v", err)
	}
	detail, ok := out.Detail.(Detail)
	if !ok {
		t.Fatalf("issue returned detail of type %T, want mfa.Detail", out.Detail)
	}
	return detail, raw
}

// completion assembles the caller a verified step-up would have produced.
type completion struct {
	subject  string
	kind     identity.SubjectKind
	issuer   string
	clientID string
	audience []string
	acr      string
	amr      []string
	authTime time.Time
	nonce    string
}

// caller turns a completion description into the [identity.Subject] the
// callback surface would have handed the lifecycle.
func (c completion) caller(t *testing.T) *identity.Subject {
	t.Helper()
	s := identity.Subject{
		Kind:      c.kind,
		Method:    identity.MethodBearerJWT,
		Issuer:    c.issuer,
		ID:        c.subject,
		ClientID:  c.clientID,
		Audience:  c.audience,
		IssuedAt:  c.authTime,
		ExpiresAt: c.authTime.Add(time.Hour),
		AuthTime:  c.authTime,
		ACR:       c.acr,
		AMR:       c.amr,
	}
	if s.Kind == "" {
		s.Kind = identity.SubjectUser
	}
	claims := map[string]any{
		"iss": s.Issuer,
		"sub": s.ID,
		"azp": s.ClientID,
		"acr": s.ACR,
	}
	if c.nonce != "" {
		claims["nonce"] = c.nonce
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("encode claims: %v", err)
	}
	return identity.NewSubject(s, raw)
}

// goodCompletion is the completion a correctly configured IdP produces for a
// challenge issued under detail: strong enough, fresh enough, and answering
// this request.
func goodCompletion(detail Detail, at time.Time) completion {
	acr := acrGold
	if len(detail.RequiredACRValues) > 0 {
		acr = detail.RequiredACRValues[0]
	}
	return completion{
		subject:  detail.SubjectID,
		kind:     identity.SubjectUser,
		issuer:   detail.Issuer,
		clientID: detail.ClientID,
		audience: []string{detail.Audience},
		acr:      acr,
		authTime: at,
		nonce:    detail.Nonce,
	}
}

func submit(t *testing.T, h *Delegated, detail json.RawMessage, dec challenge.DecisionContext,
	c completion, correlator string, now time.Time,
) (challenge.SubmitResult, error) {
	t.Helper()
	payload, err := json.Marshal(Submission{Correlator: correlator})
	if err != nil {
		t.Fatalf("encode submission: %v", err)
	}
	return h.Submit(t.Context(), challenge.SubmitRequest{
		Instance:  challenge.Instance{DecisionID: dec.DecisionID, Ordinal: 0, Kind: policy.ChallengeMFA},
		Decision:  dec,
		Detail:    detail,
		Submitter: c.caller(t),
		Payload:   payload,
		Now:       now,
	})
}
