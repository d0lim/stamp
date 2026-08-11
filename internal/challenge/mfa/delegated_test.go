package mfa

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/stream"
)

// ---------------------------------------------------------------------------
// the acr allowlist: the check U0 proved is the only defence
// ---------------------------------------------------------------------------

// TestSubmitRefusesACROutsideOperatorAllowlist is the security boundary of this
// unit, and it is deliberately written for a policy that names no acr values at
// all.
//
// U0 established that an IdP answers an unsatisfiable `acr` request with a
// silent downgrade rather than an error — `acr_values=2` came back `acr=1`, and
// so did the OIDC essential-claim form. When the policy names no classes, the
// operator allowlist is the entire requirement, so this is the one test that
// fails if and only if that allowlist check is missing.
func TestSubmitRefusesACROutsideOperatorAllowlist(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	h := newTestHandler(t, testConfig(init))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)

	downgraded := goodCompletion(detail, testNow.Add(time.Minute))
	// Exactly what U0 saw come back from an IdP that could not satisfy the
	// request: a weaker class, no error anywhere in the protocol.
	downgraded.acr = acrDowngraded

	_, err := submit(t, h, raw, dec, downgraded, detail.Correlator, testNow.Add(time.Minute))
	if !errors.Is(err, ErrACRNotAllowed) {
		t.Fatalf("a silently downgraded acr=%q satisfied the challenge; err = %v", acrDowngraded, err)
	}
}

// TestSubmitRefusesACRBelowPolicyRequirement covers the second half: a class the
// operator admits, but not the one the policy asked for.
func TestSubmitRefusesACRBelowPolicyRequirement(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{acrGold}}, dec, testNow)

	weaker := goodCompletion(detail, testNow.Add(time.Minute))
	weaker.acr = acrSilver

	_, err := submit(t, h, raw, dec, weaker, detail.Correlator, testNow.Add(time.Minute))
	if !errors.Is(err, ErrACRUnsatisfied) {
		t.Fatalf("submit err = %v, want ErrACRUnsatisfied", err)
	}
}

// TestSubmitAcceptsAllowedACR is the positive control: without it the two tests
// above would pass against a handler that refuses everything.
func TestSubmitAcceptsAllowedACR(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{acrGold}}, dec, testNow)

	at := testNow.Add(time.Minute)
	out, err := submit(t, h, raw, dec, goodCompletion(detail, at), detail.Correlator, at)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if out.State != challenge.StateSatisfied {
		t.Fatalf("state = %q, want satisfied", out.State)
	}
	if out.Have != 1 || out.Need != 1 {
		t.Fatalf("progress = %d/%d, want 1/1", out.Have, out.Need)
	}
}

// TestIssueRefusesPolicyACROutsideAllowlist keeps a challenge from opening that
// nothing could satisfy: a completion would have to be inside the allowlist and
// equal to a value outside it.
func TestIssueRefusesPolicyACROutsideAllowlist(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	_, err := h.Issue(t.Context(), challenge.IssueRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
		Spec:     policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{"platinum"}},
		Decision: dec,
		Now:      testNow,
	})
	if !errors.Is(err, challenge.ErrUnsupportedSpec) {
		t.Fatalf("issue err = %v, want ErrUnsupportedSpec", err)
	}
}

// TestNewDelegatedRefusesEmptyAllowlist states the configuration rule in the
// same place the reasoning lives: a deployment with no allowlist has no defence
// against a downgrade, so it is a wiring error rather than a permissive default.
func TestNewDelegatedRefusesEmptyAllowlist(t *testing.T) {
	t.Parallel()
	cfg := testConfig(&recordingInitiator{})
	cfg.AllowedACRValues = nil
	if _, err := NewDelegated(cfg); err == nil {
		t.Fatal("a handler with no acr allowlist was built")
	}
}

// ---------------------------------------------------------------------------
// auth_time
// ---------------------------------------------------------------------------

func TestSubmitRefusesAuthenticationOlderThanTheChallenge(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{acrGold}}, dec, testNow)

	// A session that was already open when the question was asked. The class is
	// right, the correlator is right, and it still says nothing about whether
	// the human agreed to this transfer.
	stale := goodCompletion(detail, testNow.Add(-time.Hour))

	_, err := submit(t, h, raw, dec, stale, detail.Correlator, testNow.Add(time.Minute))
	if !errors.Is(err, ErrStaleAuthentication) {
		t.Fatalf("submit err = %v, want ErrStaleAuthentication", err)
	}
}

func TestSubmitRefusesAuthenticationAtTheIssuingInstant(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)

	// The boundary is exclusive: an authentication that happened in the same
	// instant the challenge opened cannot have been caused by it.
	simultaneous := goodCompletion(detail, testNow)

	_, err := submit(t, h, raw, dec, simultaneous, detail.Correlator, testNow.Add(time.Minute))
	if !errors.Is(err, ErrStaleAuthentication) {
		t.Fatalf("submit err = %v, want ErrStaleAuthentication", err)
	}
}

func TestSubmitRefusesTokenWithoutAuthTime(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)

	// `auth_time` is required, unlike `amr`: an IdP that does not report it has
	// not told us the authentication is fresh, and fresh is the whole point.
	none := goodCompletion(detail, testNow.Add(time.Minute))
	none.authTime = time.Time{}

	_, err := submit(t, h, raw, dec, none, detail.Correlator, testNow.Add(time.Minute))
	if !errors.Is(err, ErrStaleAuthentication) {
		t.Fatalf("submit err = %v, want ErrStaleAuthentication", err)
	}
}

// ---------------------------------------------------------------------------
// the correlator: exact match, one consumption
// ---------------------------------------------------------------------------

// TestCompletionForOneDecisionIsRefusedByAnother is AE6's first clause: a token
// that satisfies decision A must do nothing for decision B.
func TestCompletionForOneDecisionIsRefusedByAnother(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))

	decA := testDecision(t)
	detailA, rawA := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, decA, testNow)

	decB := testDecision(t)
	decB.DecisionID = "dec-B"
	decB.ResourceID = "account:1"
	_, rawB := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, decB, testNow)

	at := testNow.Add(time.Minute)
	if _, err := submit(t, h, rawA, decA, goodCompletion(detailA, at), detailA.Correlator, at); err != nil {
		t.Fatalf("the completion did not satisfy the decision it was issued for: %v", err)
	}
	_, err := submit(t, h, rawB, decB, goodCompletion(detailA, at), detailA.Correlator, at)
	if !errors.Is(err, ErrCorrelatorMismatch) {
		t.Fatalf("submit against decision B err = %v, want ErrCorrelatorMismatch", err)
	}
}

// TestSecondSubmissionOfTheSameCompletionIsRefused is AE6's replay clause. The
// lifecycle also refuses a submission to a challenge that is no longer pending,
// but the handler does not lean on that: consumption is recorded in the same
// detail the state is written with, so the handler can answer alone.
func TestSecondSubmissionOfTheSameCompletionIsRefused(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)

	at := testNow.Add(time.Minute)
	first, err := submit(t, h, raw, dec, goodCompletion(detail, at), detail.Correlator, at)
	if err != nil {
		t.Fatalf("first submit: %v", err)
	}
	stored, err := json.Marshal(first.Detail)
	if err != nil {
		t.Fatalf("encode detail: %v", err)
	}

	_, err = submit(t, h, stored, dec, goodCompletion(detail, at), detail.Correlator, at.Add(time.Second))
	if !errors.Is(err, ErrCorrelatorConsumed) {
		t.Fatalf("second submit err = %v, want ErrCorrelatorConsumed", err)
	}
}

func TestSubmitRefusesAWrongCorrelator(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)

	at := testNow.Add(time.Minute)
	_, err := submit(t, h, raw, dec, goodCompletion(detail, at), "not-the-correlator", at)
	if !errors.Is(err, ErrCorrelatorMismatch) {
		t.Fatalf("submit err = %v, want ErrCorrelatorMismatch", err)
	}
}

// ---------------------------------------------------------------------------
// issuer, client and audience
// ---------------------------------------------------------------------------

func TestSubmitRefusesTheWrongParty(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	at := testNow.Add(time.Minute)

	for name, mutate := range map[string]func(*completion){
		"issuer":   func(c *completion) { c.issuer = "https://other.example.test" },
		"client":   func(c *completion) { c.clientID = "some-other-client" },
		"audience": func(c *completion) { c.audience = []string{"another-service"} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := goodCompletion(detail, at)
			mutate(&c)
			_, err := submit(t, h, raw, dec, c, detail.Correlator, at)
			if !errors.Is(err, ErrCredentialMismatch) {
				t.Fatalf("submit err = %v, want ErrCredentialMismatch", err)
			}
		})
	}
}

func TestSubmitRefusesSomebodyElsesAuthentication(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	at := testNow.Add(time.Minute)

	other := goodCompletion(detail, at)
	other.subject = "mallory"
	_, err := submit(t, h, raw, dec, other, detail.Correlator, at)
	if !errors.Is(err, challenge.ErrNotTarget) {
		t.Fatalf("submit err = %v, want ErrNotTarget", err)
	}
}

func TestSubmitRefusesAWorkloadCredential(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	at := testNow.Add(time.Minute)

	machine := goodCompletion(detail, at)
	machine.kind = identity.SubjectWorkload
	_, err := submit(t, h, raw, dec, machine, detail.Correlator, at)
	if !errors.Is(err, challenge.ErrNotTarget) {
		t.Fatalf("submit err = %v, want ErrNotTarget", err)
	}
}

// ---------------------------------------------------------------------------
// amr, matched only when present
// ---------------------------------------------------------------------------

// TestAMRIsOptionalWhenAbsent is the finding that makes this challenge
// satisfiable at all: U0 found `amr` missing by default and `[]` even with the
// mapper attached, so requiring it would be requiring something no default IdP
// deployment produces.
func TestAMRIsOptionalWhenAbsent(t *testing.T) {
	t.Parallel()
	cfg := testConfig(&recordingInitiator{})
	cfg.RequiredAMR = []string{"otp"}
	h := newTestHandler(t, cfg)
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	at := testNow.Add(time.Minute)

	for name, amr := range map[string][]string{"absent": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := goodCompletion(detail, at)
			c.amr = amr
			out, err := submit(t, h, raw, dec, c, detail.Correlator, at)
			if err != nil {
				t.Fatalf("an %s amr made the challenge unsatisfiable: %v", name, err)
			}
			if out.State != challenge.StateSatisfied {
				t.Fatalf("state = %q, want satisfied", out.State)
			}
		})
	}
}

func TestAMRIsMatchedWhenPresent(t *testing.T) {
	t.Parallel()
	cfg := testConfig(&recordingInitiator{})
	cfg.RequiredAMR = []string{"otp", "hwk"}
	h := newTestHandler(t, cfg)
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	at := testNow.Add(time.Minute)

	wrong := goodCompletion(detail, at)
	wrong.amr = []string{"pwd"}
	if _, err := submit(t, h, raw, dec, wrong, detail.Correlator, at); !errors.Is(err, ErrAMRMismatch) {
		t.Fatalf("submit err = %v, want ErrAMRMismatch", err)
	}

	right := goodCompletion(detail, at)
	right.amr = []string{"pwd", "otp"}
	if _, err := submit(t, h, raw, dec, right, detail.Correlator, at); err != nil {
		t.Fatalf("a matching amr was refused: %v", err)
	}
}

// ---------------------------------------------------------------------------
// nonce, matched only when present
// ---------------------------------------------------------------------------

func TestSubmitRefusesAnotherRequestsNonce(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	at := testNow.Add(time.Minute)

	c := goodCompletion(detail, at)
	c.nonce = NonceFor("some-other-correlator")
	if _, err := submit(t, h, raw, dec, c, detail.Correlator, at); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("submit err = %v, want ErrNonceMismatch", err)
	}
}

func TestNonceIsOptionalWhenTheIdPOmitsIt(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	at := testNow.Add(time.Minute)

	c := goodCompletion(detail, at)
	c.nonce = ""
	if _, err := submit(t, h, raw, dec, c, detail.Correlator, at); err != nil {
		t.Fatalf("a token without a nonce was refused: %v", err)
	}
}

// ---------------------------------------------------------------------------
// the context hash
// ---------------------------------------------------------------------------

func TestSubmitRefusesAChangedDecisionContext(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	at := testNow.Add(time.Minute)

	moved := dec
	moved.Request = json.RawMessage(`{"amount":9000000,"payee":"acme"}`)
	_, err := submit(t, h, raw, moved, goodCompletion(detail, at), detail.Correlator, at)
	if !errors.Is(err, ErrContextChanged) {
		t.Fatalf("submit err = %v, want ErrContextChanged", err)
	}
}

// TestContextHashIgnoresTimestampsAndSerialization states the two exclusions
// this hash shares with the approval binding hash: a decision whose expiry moved
// while sibling challenges were being issued is the same decision, and JSON that
// round-tripped through a database is the same JSON.
func TestContextHashIgnoresTimestampsAndSerialization(t *testing.T) {
	t.Parallel()
	base := testDecision(t)
	moved := base
	moved.CreatedAt = base.CreatedAt.Add(time.Hour)
	moved.ExpiresAt = base.ExpiresAt.Add(time.Hour)
	moved.Request = json.RawMessage("{\n  \"payee\"  : \"acme\",\n  \"amount\": 250000\n}")

	a, err := ContextHash(base)
	if err != nil {
		t.Fatalf("hash base: %v", err)
	}
	b, err := ContextHash(moved)
	if err != nil {
		t.Fatalf("hash moved: %v", err)
	}
	if a != b {
		t.Fatal("the context hash moved when only the timestamps and the json formatting did")
	}
}

func TestPreservesCompletion(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	_, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)

	same, err := PreservesCompletion(raw, dec)
	if err != nil {
		t.Fatalf("preserves: %v", err)
	}
	if !same {
		t.Fatal("an unchanged decision did not preserve the challenge")
	}

	moved := dec
	moved.Action = "close-account"
	changed, err := PreservesCompletion(raw, moved)
	if err != nil {
		t.Fatalf("preserves: %v", err)
	}
	if changed {
		t.Fatal("a changed decision preserved the challenge")
	}

	// Fail-closed: an unreadable detail is not a preserved challenge.
	if _, err := PreservesCompletion(json.RawMessage(`{"correlator":"c"}`), dec); err == nil {
		t.Fatal("an undecodable detail was accepted")
	}
}

// ---------------------------------------------------------------------------
// issue: mode, binding message, re-issue suppression
// ---------------------------------------------------------------------------

// TestIssueRefusesDirectMode is D16 restated in the second of the two places it
// has to hold. Policy validation already refuses it at load; a mode refused in
// only one of the two places is a mode that arrives through the other.
func TestIssueRefusesDirectMode(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	_, err := h.Issue(t.Context(), challenge.IssueRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
		Spec:     policy.MFA{Mode: policy.MFADirect},
		Decision: dec,
		Now:      testNow,
	})
	if !errors.Is(err, ErrDirectModeUnimplemented) {
		t.Fatalf("issue err = %v, want ErrDirectModeUnimplemented", err)
	}
	if !errors.Is(err, challenge.ErrUnsupportedSpec) {
		t.Fatalf("issue err = %v, want it to wrap ErrUnsupportedSpec", err)
	}
}

func TestIssueRefusesAnotherKindsSpec(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	_, err := h.Issue(t.Context(), challenge.IssueRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
		Spec:     policy.Quorum{Threshold: 2},
		Decision: dec,
		Now:      testNow,
	})
	if !errors.Is(err, challenge.ErrUnsupportedSpec) {
		t.Fatalf("issue err = %v, want ErrUnsupportedSpec", err)
	}
}

// TestIssueCarriesTheACRValuesAndAReferenceCode covers the two halves of what
// leaves the process: the request asks for the classes the policy named, and the
// display code it carries is one an IdP will accept.
func TestIssueCarriesTheACRValuesAndAReferenceCode(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	h := newTestHandler(t, testConfig(init))
	dec := testDecision(t)
	detail, _ := issue(t, h, policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{acrGold, acrSilver}}, dec, testNow)

	if len(init.calls) != 1 {
		t.Fatalf("initiator called %d times, want 1", len(init.calls))
	}
	call := init.calls[0]
	if got, want := strings.Join(call.ACRValues, " "), acrGold+" "+acrSilver; got != want {
		t.Fatalf("acr_values = %q, want %q", got, want)
	}
	if call.Correlator != detail.Correlator {
		t.Fatal("the initiator was given a different correlator than the one frozen in the detail")
	}
	if call.Reference != detail.Reference || call.Reference != ReferenceCode(detail.Correlator) {
		t.Fatalf("reference = %q, want the code derived from the correlator", call.Reference)
	}
	if err := ValidateBindingMessage(detail.Reference); err != nil {
		t.Fatalf("the reference code is not one an idp will accept: %v", err)
	}
	// The value that binds must not be the value printed on a phone screen.
	if strings.Contains(detail.Reference, detail.Correlator) {
		t.Fatal("the reference code leaks the correlator")
	}
	if call.Nonce != detail.Nonce || detail.Nonce != NonceFor(detail.Correlator) {
		t.Fatal("the nonce is not the one derived from the correlator")
	}
}

// TestReissueWithinTheMinimumIntervalMakesNoNewIdPRequest is the plan's
// re-issue scenario. Two things are asserted, not one: no second request went
// out, and the correlator did not rotate — a rotated correlator would strand
// whatever step-up the subject already has open.
func TestReissueWithinTheMinimumIntervalMakesNoNewIdPRequest(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	h := newTestHandler(t, testConfig(init))
	dec := testDecision(t)
	spec := policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{acrGold}}

	first, _ := issue(t, h, spec, dec, testNow)
	second, _ := issue(t, h, spec, dec, testNow.Add(time.Second))

	if len(init.calls) != 1 {
		t.Fatalf("initiator called %d times within the minimum interval, want 1", len(init.calls))
	}
	if h.Initiations() != 1 {
		t.Fatalf("Initiations() = %d, want 1", h.Initiations())
	}
	if second.Correlator != first.Correlator {
		t.Fatal("the correlator rotated on re-issue, stranding an in-flight step-up")
	}
	if !second.IssuedAt.Equal(first.IssuedAt) {
		t.Fatal("the issuing instant moved on re-issue, moving the auth_time lower bound with it")
	}
}

func TestReissueAfterTheMinimumIntervalOpensAFreshChallenge(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	h := newTestHandler(t, testConfig(init))
	dec := testDecision(t)
	spec := policy.MFA{Mode: policy.MFADelegated}

	first, _ := issue(t, h, spec, dec, testNow)
	second, _ := issue(t, h, spec, dec, testNow.Add(DefaultMinReissueInterval))

	if len(init.calls) != 2 {
		t.Fatalf("initiator called %d times, want 2", len(init.calls))
	}
	if second.Correlator == first.Correlator {
		t.Fatal("a fresh challenge reused the old correlator")
	}
}

// TestReissueForADifferentDecisionIsNotSuppressed guards the suppression key:
// it is the decision content, so two decisions never share a correlator however
// close together they are opened.
func TestReissueForADifferentDecisionIsNotSuppressed(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	h := newTestHandler(t, testConfig(init))
	spec := policy.MFA{Mode: policy.MFADelegated}

	decA := testDecision(t)
	a, _ := issue(t, h, spec, decA, testNow)
	decB := testDecision(t)
	decB.DecisionID = "dec-B"
	b, _ := issue(t, h, spec, decB, testNow)

	if len(init.calls) != 2 {
		t.Fatalf("initiator called %d times for two decisions, want 2", len(init.calls))
	}
	if a.Correlator == b.Correlator {
		t.Fatal("two decisions were issued the same correlator")
	}
}

// TestReissueIsNotSuppressedWhenTheRequirementChanged covers the case the
// context hash cannot see: a revision that changed only which classes are
// demanded leaves the decision content untouched.
func TestReissueIsNotSuppressedWhenTheRequirementChanged(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	h := newTestHandler(t, testConfig(init))
	dec := testDecision(t)

	issue(t, h, policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{acrSilver}}, dec, testNow)
	second, _ := issue(t, h, policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{acrGold}}, dec, testNow.Add(time.Second))

	if len(init.calls) != 2 {
		t.Fatalf("initiator called %d times, want 2", len(init.calls))
	}
	if got := strings.Join(second.RequiredACRValues, " "); got != acrGold {
		t.Fatalf("required acr = %q, want %q", got, acrGold)
	}
}

func TestIssueRefusesADecisionWithNoSubject(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	dec.SubjectID = "  "
	_, err := h.Issue(t.Context(), challenge.IssueRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
		Spec:     policy.MFA{Mode: policy.MFADelegated},
		Decision: dec,
		Now:      testNow,
	})
	if !errors.Is(err, challenge.ErrUnsupportedSpec) {
		t.Fatalf("issue err = %v, want ErrUnsupportedSpec", err)
	}
}

// ---------------------------------------------------------------------------
// status and targeting
// ---------------------------------------------------------------------------

func TestStatusReportsPendingUntilConsumedAndFailsAnElapsedDeadline(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)

	status, err := h.Status(t.Context(), challenge.StatusRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
		Decision: dec, Detail: raw, Stored: challenge.StatePending, Now: testNow.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.State != challenge.StatePending || status.Have != 0 || status.Need != 1 {
		t.Fatalf("status = %q %d/%d, want pending 0/1", status.State, status.Have, status.Need)
	}

	// An elapsed deadline means failed here, the opposite of what it will mean
	// for a delay — which is the asymmetry the contract answers timers through
	// Status for rather than through a callback.
	deadline := testNow.Add(5 * time.Minute)
	elapsed, err := h.Status(t.Context(), challenge.StatusRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
		Decision: dec, Detail: raw, Stored: challenge.StatePending,
		Deadline: &deadline, Now: deadline,
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if elapsed.State != challenge.StateFailed {
		t.Fatalf("state = %q at the deadline, want failed", elapsed.State)
	}

	at := testNow.Add(time.Minute)
	out, err := submit(t, h, raw, dec, goodCompletion(detail, at), detail.Correlator, at)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	consumed, err := json.Marshal(out.Detail)
	if err != nil {
		t.Fatalf("encode detail: %v", err)
	}
	after, err := h.Status(t.Context(), challenge.StatusRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
		Decision: dec, Detail: consumed, Stored: challenge.StatePending, Now: at,
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if after.State != challenge.StateSatisfied || after.Have != 1 {
		t.Fatalf("status = %q %d/1, want satisfied 1/1", after.State, after.Have)
	}
}

// TestStatusNeverWalksBackATerminalState mirrors the quorum rule: a cancelled
// challenge does not become satisfied because its detail says it was consumed.
func TestStatusNeverWalksBackATerminalState(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	at := testNow.Add(time.Minute)
	out, err := submit(t, h, raw, dec, goodCompletion(detail, at), detail.Correlator, at)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	consumed, err := json.Marshal(out.Detail)
	if err != nil {
		t.Fatalf("encode detail: %v", err)
	}
	status, err := h.Status(t.Context(), challenge.StatusRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
		Decision: dec, Detail: consumed, Stored: challenge.StateCancelled, Now: at,
	})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.State != challenge.StateCancelled {
		t.Fatalf("state = %q, want cancelled", status.State)
	}
}

func TestIsTargetIsTheSubjectAndNobodyElse(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	at := testNow.Add(time.Minute)

	subject := goodCompletion(detail, at).caller(t)
	yes, err := h.IsTarget(t.Context(), challenge.TargetRequest{Detail: raw, Subject: subject, Decision: dec})
	if err != nil {
		t.Fatalf("is target: %v", err)
	}
	if !yes {
		t.Fatal("the decision's subject is not a target of its own step-up")
	}

	other := goodCompletion(detail, at)
	other.subject = "mallory"
	no, err := h.IsTarget(t.Context(), challenge.TargetRequest{Detail: raw, Subject: other.caller(t), Decision: dec})
	if err != nil {
		t.Fatalf("is target: %v", err)
	}
	if no {
		t.Fatal("somebody else is a target of this step-up")
	}

	// Fail-closed: no credential is no target, and that is an answer rather
	// than a failure.
	nobody, err := h.IsTarget(t.Context(), challenge.TargetRequest{Detail: raw, Subject: nil, Decision: dec})
	if err != nil {
		t.Fatalf("is target: %v", err)
	}
	if nobody {
		t.Fatal("an absent credential is a target")
	}
}

// ---------------------------------------------------------------------------
// payload handling
// ---------------------------------------------------------------------------

func TestSubmitRefusesAPayloadThatNamesTheSubject(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	at := testNow.Add(time.Minute)

	// Unknown members are refused rather than ignored, for the reason the
	// quorum handler refuses an approver field: an ignored claim about who
	// authenticated is a client that believes it worked.
	_, err := h.Submit(t.Context(), challenge.SubmitRequest{
		Instance:  challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
		Decision:  dec,
		Detail:    raw,
		Submitter: goodCompletion(detail, at).caller(t),
		Payload:   json.RawMessage(`{"correlator":"` + detail.Correlator + `","subject":"mallory"}`),
		Now:       at,
	})
	if !errors.Is(err, challenge.ErrInvalidPayload) {
		t.Fatalf("submit err = %v, want ErrInvalidPayload", err)
	}
}

func TestSubmitRefusesAnEmptyPayload(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated}, dec, testNow)
	at := testNow.Add(time.Minute)

	for name, payload := range map[string]json.RawMessage{
		"absent": nil,
		"null":   json.RawMessage(`null`),
		"blank":  json.RawMessage(`{"correlator":"  "}`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := h.Submit(t.Context(), challenge.SubmitRequest{
				Instance:  challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
				Decision:  dec,
				Detail:    raw,
				Submitter: goodCompletion(detail, at).caller(t),
				Payload:   payload,
				Now:       at,
			})
			if !errors.Is(err, challenge.ErrInvalidPayload) {
				t.Fatalf("submit err = %v, want ErrInvalidPayload", err)
			}
		})
	}
}

func TestDecodeDetailIsFailClosed(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]json.RawMessage{
		"not json":       json.RawMessage(`{`),
		"no correlator":  json.RawMessage(`{"method":"step_up"}`),
		"unknown method": json.RawMessage(`{"correlator":"c","method":"telepathy"}`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeDetail(raw); !errors.Is(err, challenge.ErrInvalidPayload) {
				t.Fatalf("decode err = %v, want ErrInvalidPayload", err)
			}
		})
	}
}

// TestHandlerServesTheContract keeps the registry honest: the handler declares
// the kind it is registered under.
func TestHandlerServesTheContract(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	if h.Kind() != policy.ChallengeMFA {
		t.Fatalf("Kind() = %q, want %q", h.Kind(), policy.ChallengeMFA)
	}
	reg, err := challenge.NewRegistry(h)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := reg.Handler(policy.ChallengeMFA); err != nil {
		t.Fatalf("look up the mfa handler: %v", err)
	}
}

// ---------------------------------------------------------------------------
// what a caller may be told (R2, R28, KTD1)
//
// The lifecycle cannot read this detail — it must not import this package — so
// the handler names what leaves. Everything not named stays on the row.
// ---------------------------------------------------------------------------

// viewableDetail is a frozen challenge with every field populated, so that a
// view that copied more than it was supposed to has something to copy.
//
// Its authorization URL deliberately carries no secret of its own: what this
// test judges is the handler's choice of fields, and a URL that happened to
// contain a correlator would confuse that question with the separate one
// TestTheStepUpURLStillCarriesTheCorrelator asks.
func viewableDetail() Detail {
	consumedBy := "alice"
	return Detail{
		Mode:              policy.MFADelegated,
		Method:            MethodStepUp,
		Correlator:        "correlator-3f9c1d2b4a6e8f0c1d2b4a6e8f0c1d2b",
		Reference:         "STAMP-ABCDEFGHIJ",
		Nonce:             "nonce-9a8b7c6d5e4f0011223344556677889900",
		SubjectID:         testSubject,
		RequiredACRValues: []string{acrGold},
		AllowedACRValues:  []string{acrGold, acrSilver},
		Issuer:            testIssuer,
		ClientID:          testClientID,
		Audience:          testAudience,
		IssuedAt:          testNow,
		ContextHash:       "ff00ff00ff00ff00",
		AuthorizationURL:  "https://idp.example.test/authorize?client_id=stamp-stepup&state=csrf-0f0f0f",
		AuthReqID:         "auth-req-7788990011",
		ConsumedBy:        consumedBy,
	}
}

// TestViewPublishesTheAuthorizationURLAndNothingElse is this handler's half of
// KTD1: one field crosses, chosen by name.
func TestViewPublishesTheAuthorizationURLAndNothingElse(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	detail := viewableDetail()
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("encode detail: %v", err)
	}

	view, err := h.View(t.Context(), challenge.ViewRequest{
		Instance: challenge.Instance{DecisionID: "dec-A", Ordinal: 0, Kind: policy.ChallengeMFA},
		Decision: testDecision(t),
		Detail:   raw,
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if view.AuthorizationURL != detail.AuthorizationURL {
		t.Fatalf("authorization url = %q, want %q", view.AuthorizationURL, detail.AuthorizationURL)
	}

	// Scanned by value, not by field name: a secret copied into a field with an
	// innocent name has leaked exactly as much.
	published, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("encode view: %v", err)
	}
	for name, secret := range map[string]string{
		"correlator":  detail.Correlator,
		"nonce":       detail.Nonce,
		"reference":   detail.Reference,
		"auth_req_id": detail.AuthReqID,
		"subject":     detail.SubjectID,
		"client id":   detail.ClientID,
		"consumer":    detail.ConsumedBy,
	} {
		if secret != "" && strings.Contains(string(published), secret) {
			t.Errorf("the published view carries the challenge's %s: %s", name, published)
		}
	}
}

// TestViewOfAChallengeWithNoDestinationPublishesNothing: a CIBA challenge is
// answered on the subject's phone, so there is nowhere to send anybody. The
// backchannel request identifier is not a substitute — it is a value the token
// exchange uses and a caller has no business holding.
func TestViewOfAChallengeWithNoDestinationPublishesNothing(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{method: MethodCIBA}))
	detail := viewableDetail()
	detail.Method = MethodCIBA
	detail.AuthorizationURL = ""
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("encode detail: %v", err)
	}

	view, err := h.View(t.Context(), challenge.ViewRequest{
		Instance: challenge.Instance{DecisionID: "dec-A", Ordinal: 0, Kind: policy.ChallengeMFA},
		Decision: testDecision(t),
		Detail:   raw,
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if view != (challenge.View{}) {
		t.Fatalf("view = %+v, want nothing published", view)
	}
}

// TestViewRefusesAnUnreadableDetail: the view path decodes the same row Status
// and Submit decode, and answers a corrupt one the same way rather than
// publishing a zero value that would read as "no destination".
func TestViewRefusesAnUnreadableDetail(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, testConfig(&recordingInitiator{}))
	_, err := h.View(t.Context(), challenge.ViewRequest{
		Instance: challenge.Instance{DecisionID: "dec-A", Ordinal: 0, Kind: policy.ChallengeMFA},
		Decision: testDecision(t),
		Detail:   json.RawMessage(`{"mode":`),
		Now:      testNow,
	})
	if !errors.Is(err, challenge.ErrInvalidPayload) {
		t.Fatalf("view err = %v, want ErrInvalidPayload", err)
	}
}

// TestTheCorrelatorReachesACallerOnlyAsTheOAuthState is U1's test, and its name
// is now a statement about the past.
//
// U1 made the authorization URL travel in a decision response for the first
// time, and at that moment [StepUp.Initiate] still sent the correlator as
// `state` — so a 32-byte binding value began travelling in a response and, once
// the subject opened the link, in an address bar, a referrer and a history
// entry. U1 recorded that as a KNOWN GAP owned by U2 and held the exposure to
// one query parameter. U2 closed it: `state` is a fresh CSRF token, the
// per-challenge callback path is what identifies the challenge (KTD2), and the
// assertion below no longer needs its exemption.
//
// The test is kept rather than renamed away because what it bounds is still
// worth bounding: nothing derived from the correlator may reach a caller except
// the `nonce`, which is a one-way digest and belongs in the request by protocol.
// The PKCE verifier joins it — minted at issue, stored on the row, and never
// published.
func TestTheCorrelatorReachesACallerOnlyAsTheOAuthState(t *testing.T) {
	t.Parallel()
	// The real step-up initiator, not the recording one: the question is what
	// the URL a deployment actually builds carries.
	h := newTestHandler(t, testConfig(testStepUpInitiator(t)))
	dec := testDecision(t)
	detail, raw := issue(t, h, policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{acrGold}}, dec, testNow)

	view, err := h.View(t.Context(), challenge.ViewRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Ordinal: 0, Kind: policy.ChallengeMFA},
		Decision: dec,
		Detail:   raw,
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	u, err := url.Parse(view.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse the published authorization url %q: %v", view.AuthorizationURL, err)
	}
	q := u.Query()
	// No exemption. `state` is a value of its own now, and it is the frozen one.
	if got := q.Get("state"); got == detail.Correlator {
		t.Errorf("the published authorization url carries the correlator as `state` (KTD2): %s",
			view.AuthorizationURL)
	} else if got != detail.State {
		t.Errorf("state = %q, want the value frozen on the challenge row (%q)", got, detail.State)
	}
	if strings.Contains(view.AuthorizationURL, detail.Correlator) {
		t.Errorf("the correlator reaches a caller in the published url: %s", view.AuthorizationURL)
	}
	if detail.CodeVerifier == "" {
		t.Fatal("no pkce verifier was frozen on the challenge row")
	}
	if strings.Contains(view.AuthorizationURL, detail.CodeVerifier) {
		t.Errorf("the pkce verifier reaches a caller in the published url: %s", view.AuthorizationURL)
	}
	// The nonce is a one-way derivation of the correlator and belongs in an
	// authorization request by protocol, so its presence is not a leak of the
	// correlator — but it must be the derived value and never the raw one.
	if got := q.Get("nonce"); got != NonceFor(detail.Correlator) {
		t.Errorf("nonce = %q, want the derived %q", got, NonceFor(detail.Correlator))
	}
	// The view publishes one field, and it must stay one field: a `state` or a
	// verifier appearing here later would be a leak with no owner.
	if view != (challenge.View{AuthorizationURL: view.AuthorizationURL}) {
		t.Errorf("view = %+v, want only an authorization url", view)
	}
}

// ---------------------------------------------------------------------------
// the per-subject issue budget (R43)
// ---------------------------------------------------------------------------

// TestIssueStopsAtTheSubjectBudgetAcrossDifferentDecisions is the path re-issue
// suppression cannot close, and it is written for exactly that path.
//
// The suppression key is the subject plus the context hash, and the context hash
// covers the decision identifier — so N calls that create N decisions for one
// person are N different keys, N initiations, and N prompts on one phone.
// Nothing about that is a re-issue, which is why the interval never sees it.
func TestIssueStopsAtTheSubjectBudgetAcrossDifferentDecisions(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	h := newTestHandler(t, testConfig(init))
	spec := policy.MFA{Mode: policy.MFADelegated}

	const attempts = 20
	refused := 0
	for i := range attempts {
		dec := testDecision(t)
		dec.DecisionID = fmt.Sprintf("dec-%02d", i)
		out, err := h.Issue(t.Context(), challenge.IssueRequest{
			Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
			Spec:     spec,
			Decision: dec,
			Now:      testNow,
		})
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		if out.State == challenge.StateFailed {
			refused++
		}
	}
	if refused == 0 {
		t.Fatalf("all %d issuances for one subject passed: %d prompts reached %q in one instant",
			attempts, len(init.calls), testSubject)
	}
	// The budget is spent, not merely consulted: what got through is the burst
	// and nothing more, and the initiator — the thing that reaches the human —
	// was called exactly that many times.
	want := int(DefaultSubjectIssueRate.Burst)
	if got := attempts - refused; got != want {
		t.Errorf("%d issuances passed, want the burst of %d", got, want)
	}
	if len(init.calls) != want {
		t.Errorf("the initiator was called %d times, want %d: a refused issue still reached the idp",
			len(init.calls), want)
	}
}

// TestARefusedIssueIsADenyWithItsOwnReason pins the shape of the refusal.
//
// Two things are being asserted, and the second is the one that matters. That it
// is a failed challenge and not an error: an error would leave decide answering
// 500, and R43 says a request over the limit is denied, not broken. And that the
// challenge row names which refusal it was — a reader looking at a denied
// decision has to be able to tell this apart from a policy deny, from the
// outstanding cap, and from the decide path's own rate limit, all three of which
// are different words written somewhere else.
func TestARefusedIssueIsADenyWithItsOwnReason(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	h := newTestHandler(t, testConfig(init))
	spec := policy.MFA{Mode: policy.MFADelegated}

	var refusal challenge.IssueResult
	for i := range int(DefaultSubjectIssueRate.Burst) + 1 {
		dec := testDecision(t)
		dec.DecisionID = fmt.Sprintf("dec-%02d", i)
		out, err := h.Issue(t.Context(), challenge.IssueRequest{
			Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
			Spec:     spec,
			Decision: dec,
			Now:      testNow,
		})
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		refusal = out
	}
	if refusal.State != challenge.StateFailed {
		t.Fatalf("the issue over the budget returned state %q, want failed", refusal.State)
	}
	detail, ok := refusal.Detail.(Detail)
	if !ok {
		t.Fatalf("refused issue returned detail of type %T, want mfa.Detail", refusal.Detail)
	}
	if detail.Failure != FailureIssueRateLimited {
		t.Errorf("failure = %q, want %q", detail.Failure, FailureIssueRateLimited)
	}
	if detail.Correlator != "" {
		t.Error("a challenge that was never opened was given a correlator")
	}
	if detail.SubjectID != testSubject {
		t.Errorf("subject on the refusal = %q, want %q: the row has to name who was shed",
			detail.SubjectID, testSubject)
	}

	// The lifecycle writes every challenge pending and asks Status afterwards, so
	// a refusal that Status could not recompute would leave the challenge open
	// and the decision waiting on a prompt nobody was ever sent.
	dec := testDecision(t)
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("encode detail: %v", err)
	}
	status, err := h.Status(t.Context(), challenge.StatusRequest{
		Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
		Decision: dec, Detail: raw, Stored: challenge.StatePending, Now: testNow.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("status of a refused issue: %v", err)
	}
	if status.State != challenge.StateFailed {
		t.Errorf("status of a refused issue = %q, want failed", status.State)
	}

	// And nothing can be submitted against it: there was no correlator to match
	// and nobody was asked anything.
	_, err = submit(t, h, raw, dec, goodCompletion(detail, testNow.Add(time.Minute)), "anything", testNow.Add(time.Minute))
	if !errors.Is(err, challenge.ErrNotSubmittable) {
		t.Errorf("submit against a refused issue = %v, want ErrNotSubmittable", err)
	}
}

// TestTheIssueBudgetRefillsAfterItsWindow is the other half of a rate limit: a
// subject who was shed is not shed forever, and the budget comes back on the
// operator's schedule rather than on a restart.
func TestTheIssueBudgetRefillsAfterItsWindow(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	h := newTestHandler(t, testConfig(init))
	spec := policy.MFA{Mode: policy.MFADelegated}

	issueAt := func(id string, at time.Time) challenge.State {
		t.Helper()
		dec := testDecision(t)
		dec.DecisionID = id
		out, err := h.Issue(t.Context(), challenge.IssueRequest{
			Instance: challenge.Instance{DecisionID: id, Kind: policy.ChallengeMFA},
			Spec:     spec,
			Decision: dec,
			Now:      at,
		})
		if err != nil {
			t.Fatalf("issue %s: %v", id, err)
		}
		return out.State
	}

	for i := range int(DefaultSubjectIssueRate.Burst) {
		if got := issueAt(fmt.Sprintf("dec-%02d", i), testNow); got != challenge.StatePending {
			t.Fatalf("issue %d within the burst = %q, want pending", i, got)
		}
	}
	if got := issueAt("dec-over", testNow); got != challenge.StateFailed {
		t.Fatalf("the issue past the burst = %q, want failed", got)
	}

	// One token's worth of time, and exactly one more issue gets through.
	window := time.Duration(float64(time.Second) / DefaultSubjectIssueRate.PerSecond)
	later := testNow.Add(window)
	if got := issueAt("dec-after", later); got != challenge.StatePending {
		t.Fatalf("the issue after a full refill window = %q, want pending", got)
	}
	if got := issueAt("dec-after-2", later); got != challenge.StateFailed {
		t.Fatalf("a second issue on one refilled token = %q, want failed", got)
	}
}

// TestTheIssueBudgetIsPerSubject guards the key. A budget that summed across
// people would let one flooded subject deny everybody else their step-up, which
// is the rate limit becoming the outage.
func TestTheIssueBudgetIsPerSubject(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	h := newTestHandler(t, testConfig(init))
	spec := policy.MFA{Mode: policy.MFADelegated}

	for i := range int(DefaultSubjectIssueRate.Burst) + 5 {
		dec := testDecision(t)
		dec.DecisionID = fmt.Sprintf("dec-%02d", i)
		if _, err := h.Issue(t.Context(), challenge.IssueRequest{
			Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
			Spec:     spec, Decision: dec, Now: testNow,
		}); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}

	other := testDecision(t)
	other.DecisionID = "dec-other"
	other.SubjectID = "bob"
	out, err := h.Issue(t.Context(), challenge.IssueRequest{
		Instance: challenge.Instance{DecisionID: other.DecisionID, Kind: policy.ChallengeMFA},
		Spec:     spec, Decision: other, Now: testNow,
	})
	if err != nil {
		t.Fatalf("issue for a second subject: %v", err)
	}
	if out.State != challenge.StatePending {
		t.Fatalf("a second subject's first issue = %q, want pending: one subject exhausted another's budget",
			out.State)
	}
}

// TestANegativeIssueRateRemovesTheBudget is the operator saying out loud that
// they want no limit. Leaving the setting unset is not that statement, and the
// tests above are what say so.
func TestANegativeIssueRateRemovesTheBudget(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	cfg := testConfig(init)
	cfg.SubjectIssueRate = stream.RateLimit{PerSecond: -1}
	h := newTestHandler(t, cfg)
	spec := policy.MFA{Mode: policy.MFADelegated}

	const attempts = 20
	for i := range attempts {
		dec := testDecision(t)
		dec.DecisionID = fmt.Sprintf("dec-%02d", i)
		out, err := h.Issue(t.Context(), challenge.IssueRequest{
			Instance: challenge.Instance{DecisionID: dec.DecisionID, Kind: policy.ChallengeMFA},
			Spec:     spec, Decision: dec, Now: testNow,
		})
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		if out.State != challenge.StatePending {
			t.Fatalf("issue %d = %q under a disabled limit, want pending", i, out.State)
		}
	}
	if len(init.calls) != attempts {
		t.Errorf("the initiator was called %d times, want %d", len(init.calls), attempts)
	}
}

// TestReissueSuppressionIsNotChargedAgainstTheBudget is where the two mechanisms
// meet, and the answer has to be that they do not.
//
// A re-evaluation of one decision opens nothing: no IdP request, no prompt, the
// same correlator handed back. Charging it would let the revalidation loop spend
// a person's budget on a challenge that already exists — the limit would fire on
// exactly the traffic it has no reason to shed.
func TestReissueSuppressionIsNotChargedAgainstTheBudget(t *testing.T) {
	t.Parallel()
	init := &recordingInitiator{}
	h := newTestHandler(t, testConfig(init))
	dec := testDecision(t)
	spec := policy.MFA{Mode: policy.MFADelegated}

	first, _ := issue(t, h, spec, dec, testNow)
	// Far more re-evaluations than the burst, all inside the suppression window.
	for i := range int(DefaultSubjectIssueRate.Burst) * 4 {
		again, _ := issue(t, h, spec, dec, testNow.Add(time.Duration(i+1)*time.Second))
		if again.Correlator != first.Correlator {
			t.Fatalf("re-evaluation %d rotated the correlator", i)
		}
	}
	if len(init.calls) != 1 {
		t.Fatalf("the initiator was called %d times for one decision, want 1", len(init.calls))
	}
	// And the budget is still whole: a different decision for the same subject
	// still gets through, four bursts of re-evaluation later.
	other := testDecision(t)
	other.DecisionID = "dec-B"
	out, err := h.Issue(t.Context(), challenge.IssueRequest{
		Instance: challenge.Instance{DecisionID: other.DecisionID, Kind: policy.ChallengeMFA},
		Spec:     spec, Decision: other, Now: testNow.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("issue for a second decision: %v", err)
	}
	if out.State != challenge.StatePending {
		t.Fatalf("a second decision = %q: re-evaluations were charged against the subject's budget", out.State)
	}
}
