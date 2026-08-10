package mfa

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
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
