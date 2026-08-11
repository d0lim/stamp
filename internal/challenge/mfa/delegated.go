package mfa

// delegated.go is the handler: it opens a delegated authentication, and it
// judges what comes back.
//
// The judging half is deliberately a straight line of independent refusals
// rather than a score. Every check answers a different question, every one of
// them is fail-closed on its own, and none of them is skipped because another
// passed — R38 and AE6 name them as a conjunction and that is how they are
// written.
//
// The opening half is almost nothing: derive a correlator, derive the display
// code and the nonce from it, ask an [Initiator] to reach the human, and freeze
// the terms. It is short because the transport is the seam — see [Initiator].

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
)

// Defaults for the knobs a deployment does not set.
const (
	// DefaultMinReissueInterval is how long a freshly opened challenge is
	// reused for rather than re-opened. It exists because issuing is a call to
	// an IdP and a prompt on somebody's phone: a decision that is re-evaluated
	// twice in the same breath must not buzz the same human twice, and must
	// not rotate the correlator out from under the step-up they already have
	// open.
	DefaultMinReissueInterval = 2 * time.Minute

	// DefaultMaxTrackedIssues bounds the re-issue memory. It is a cache, not a
	// record: losing it costs one extra IdP request, so it is capped rather
	// than grown.
	DefaultMaxTrackedIssues = 4096

	// correlatorBytes is the entropy in a correlator. It is the value a
	// completion has to match exactly, so it is sized as a secret rather than
	// as an identifier.
	correlatorBytes = 32
)

// Config configures a [Delegated] handler.
type Config struct {
	// Initiator starts the authentication. Required: a challenge nobody was
	// asked to complete is a decision that can never resolve.
	Initiator Initiator

	// AllowedACRValues is the operator's allowlist of authentication context
	// classes (R38). Required and non-empty.
	//
	// It is required because it is the only defence there is. U0 established
	// that an IdP silently downgrades an `acr` request it cannot satisfy, so a
	// deployment with no allowlist is a deployment where a password login
	// satisfies a step-up challenge. A handler built without one is an error
	// at wiring time rather than a permissive default.
	AllowedACRValues []string

	// RequiredAMR, when non-empty, is the set of authentication methods a
	// completion should have used. It is checked only against a token that
	// carries `amr` at all: U0 found the claim absent from default IdP
	// configurations and empty even once its mapper was attached, so requiring
	// it would make this challenge structurally unsatisfiable.
	RequiredAMR []string

	// Issuer, ClientID and Audience are the party a completion token must come
	// from. All three are required, and all three are operator configuration —
	// the same pins [identity.Config] holds, restated here because a challenge
	// is satisfied by a specific authentication and not by any token the
	// deployment happens to accept.
	Issuer   string
	ClientID string
	Audience string

	// MinReissueInterval overrides [DefaultMinReissueInterval]. Negative
	// disables re-issue suppression entirely.
	MinReissueInterval time.Duration

	// MaxTrackedIssues overrides [DefaultMaxTrackedIssues].
	MaxTrackedIssues int

	// CallbackURL reports where a completion for one challenge should land.
	//
	// A step-up returns through a browser redirect, so the completion has to
	// arrive somewhere that knows which challenge it answers. Nil means one
	// fixed callback for every challenge, which is what a deployment that
	// resolves the challenge some other way wants. It is a function rather
	// than a template because the route pattern lives in the API layer, and a
	// second copy of it here is a second copy that can drift.
	CallbackURL func(challenge.Instance) string

	// NewCorrelator overrides correlator generation, for tests. Nil selects a
	// crypto/rand source.
	NewCorrelator func() (string, error)
}

// Delegated is the delegated MFA challenge handler.
type Delegated struct {
	initiator  Initiator
	allowedACR []string
	requireAMR []string
	issuer     string
	clientID   string
	audience   string

	minReissue  time.Duration
	maxTracked  int
	callbackURL func(challenge.Instance) string
	correlator  func() (string, error)
	mu          sync.Mutex
	recent      map[string]recentIssue
	initiations int
}

// recentIssue is one challenge this process opened recently.
type recentIssue struct {
	at     time.Time
	detail Detail
}

// Compile-time proof that the handler serves the whole contract, including all
// three optional interfaces: the read rule, the publishable view, and the
// redemption of the redirect the view published.
var (
	_ challenge.Handler  = (*Delegated)(nil)
	_ challenge.Targeter = (*Delegated)(nil)
	_ challenge.Viewer   = (*Delegated)(nil)
	_ challenge.Redeemer = (*Delegated)(nil)
)

// NewDelegated builds the handler, refusing a configuration that would leave
// the `acr` check unable to run.
func NewDelegated(cfg Config) (*Delegated, error) {
	if cfg.Initiator == nil {
		return nil, errors.New("mfa: a delegated handler needs an initiator to reach the subject with")
	}
	allowed := normalizeACR(cfg.AllowedACRValues)
	if len(allowed) == 0 {
		return nil, errors.New("mfa: a delegated handler needs a non-empty acr allowlist: " +
			"an idp downgrades an unsatisfiable acr request silently, so an unchecked response is an unchecked authentication")
	}
	for _, field := range []struct{ name, value string }{
		{"issuer", cfg.Issuer},
		{"client id", cfg.ClientID},
		{"audience", cfg.Audience},
	} {
		if strings.TrimSpace(field.value) == "" {
			return nil, fmt.Errorf("mfa: a delegated handler needs the %s a completion token must carry", field.name)
		}
	}

	d := &Delegated{
		initiator:   cfg.Initiator,
		allowedACR:  allowed,
		requireAMR:  normalizeACR(cfg.RequiredAMR),
		issuer:      cfg.Issuer,
		clientID:    cfg.ClientID,
		audience:    cfg.Audience,
		minReissue:  cfg.MinReissueInterval,
		maxTracked:  cfg.MaxTrackedIssues,
		callbackURL: cfg.CallbackURL,
		correlator:  cfg.NewCorrelator,
		recent:      make(map[string]recentIssue),
	}
	if d.minReissue == 0 {
		d.minReissue = DefaultMinReissueInterval
	}
	if d.maxTracked <= 0 {
		d.maxTracked = DefaultMaxTrackedIssues
	}
	if d.correlator == nil {
		d.correlator = randomCorrelator
	}
	return d, nil
}

// Kind implements [challenge.Handler].
func (d *Delegated) Kind() policy.ChallengeType { return policy.ChallengeMFA }

// Initiations reports how many authentications this handler has actually
// started. It exists so that re-issue suppression can be asserted on rather
// than believed, and so a deployment can export "how often do we buzz people"
// as a number.
func (d *Delegated) Initiations() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.initiations
}

// Issue opens a delegated authentication and freezes its terms.
//
// It sets no deadline. A step-up ends when its decision does, and a second
// expiry here would be one more thing that has to be kept in step with the
// first; the handler still answers a deadline that was set for it, in
// [Delegated.Status].
func (d *Delegated) Issue(ctx context.Context, req challenge.IssueRequest) (challenge.IssueResult, error) {
	spec, ok := req.Spec.(policy.MFA)
	if !ok {
		return challenge.IssueResult{}, fmt.Errorf("%w: %T is not an mfa challenge",
			challenge.ErrUnsupportedSpec, req.Spec)
	}
	mode := spec.Mode
	if mode == "" {
		mode = policy.DefaultMFAMode
	}
	if mode != policy.MFADelegated {
		return challenge.IssueResult{}, fmt.Errorf("%w: %w", challenge.ErrUnsupportedSpec, ErrDirectModeUnimplemented)
	}

	required := normalizeACR(spec.ACRValues)
	// A policy asking for a class the operator does not admit is a challenge
	// nothing could satisfy: the completion would have to be both inside the
	// allowlist and equal to a value outside it. Refusing at issue is the same
	// judgement the quorum handler makes about a set smaller than its own
	// threshold.
	for _, want := range required {
		if !slices.Contains(d.allowedACR, want) {
			return challenge.IssueResult{}, fmt.Errorf(
				"%w: the policy requires acr %q, which the operator allowlist %v does not admit",
				challenge.ErrUnsupportedSpec, want, d.allowedACR)
		}
	}

	sum, err := ContextHash(req.Decision)
	if err != nil {
		return challenge.IssueResult{}, err
	}
	contextHash := hex.EncodeToString(sum[:])
	subjectID := strings.TrimSpace(req.Decision.SubjectID)
	if subjectID == "" {
		return challenge.IssueResult{}, fmt.Errorf(
			"%w: decision %q names no subject to authenticate", challenge.ErrUnsupportedSpec, req.Decision.DecisionID)
	}

	if detail, ok := d.reuse(subjectID, contextHash, required, req.Now); ok {
		return challenge.IssueResult{State: challenge.StatePending, Detail: detail}, nil
	}

	correlator, err := d.correlator()
	if err != nil {
		return challenge.IssueResult{}, fmt.Errorf("mfa: generating a correlator: %w", err)
	}
	reference := ReferenceCode(correlator)
	if err := ValidateBindingMessage(reference); err != nil {
		return challenge.IssueResult{}, err
	}
	nonce := NonceFor(correlator)

	out, err := d.initiate(ctx, InitiateRequest{
		Instance:    req.Instance,
		Decision:    req.Decision,
		SubjectID:   subjectID,
		Correlator:  correlator,
		Reference:   reference,
		Nonce:       nonce,
		ACRValues:   required,
		RedirectURI: d.callbackFor(req.Instance),
		Now:         req.Now,
	})
	if err != nil {
		return challenge.IssueResult{}, err
	}
	if !out.Method.Valid() {
		return challenge.IssueResult{}, fmt.Errorf("mfa: the initiator reported delegation method %q", out.Method)
	}

	detail := Detail{
		Mode:              policy.MFADelegated,
		Method:            out.Method,
		Correlator:        correlator,
		Reference:         reference,
		Nonce:             nonce,
		SubjectID:         subjectID,
		RequiredACRValues: required,
		AllowedACRValues:  slices.Clone(d.allowedACR),
		Issuer:            d.issuer,
		ClientID:          d.clientID,
		Audience:          d.audience,
		IssuedAt:          req.Now.UTC(),
		ContextHash:       contextHash,
		AuthorizationURL:  out.AuthorizationURL,
		AuthReqID:         out.AuthReqID,
		State:             out.State,
		CodeVerifier:      out.CodeVerifier,
	}
	d.remember(subjectID, contextHash, detail, req.Now)
	return challenge.IssueResult{State: challenge.StatePending, Detail: detail}, nil
}

// callbackFor asks where a completion for this challenge should land.
func (d *Delegated) callbackFor(in challenge.Instance) string {
	if d.callbackURL == nil {
		return ""
	}
	return d.callbackURL(in)
}

func (d *Delegated) initiate(ctx context.Context, req InitiateRequest) (InitiateResult, error) {
	d.mu.Lock()
	d.initiations++
	d.mu.Unlock()
	out, err := d.initiator.Initiate(ctx, req)
	if err != nil {
		return InitiateResult{}, fmt.Errorf("mfa: starting authentication for %s: %w", req.Instance, err)
	}
	return out, nil
}

// Submit judges a completion.
//
// Every refusal below is an error rather than a pending result, and the
// challenge is left exactly as it was. AE6 says a completion that fails any of
// these leaves the challenge unsatisfied; returning the reason as well is what
// lets an operator tell a replay apart from an IdP that is misconfigured.
//
// The correlator is checked first and in constant time. It is the binding, it
// is a secret, and everything after it is a statement about a token that has
// already proved it belongs to this challenge.
func (d *Delegated) Submit(_ context.Context, req challenge.SubmitRequest) (challenge.SubmitResult, error) {
	detail, err := DecodeDetail(req.Detail)
	if err != nil {
		return challenge.SubmitResult{}, err
	}
	body, err := decodeSubmission(req.Payload)
	if err != nil {
		return challenge.SubmitResult{}, err
	}

	if subtle.ConstantTimeCompare([]byte(body.Correlator), []byte(detail.Correlator)) != 1 {
		return challenge.SubmitResult{}, fmt.Errorf("%w: %s", ErrCorrelatorMismatch, req.Instance)
	}
	// One consumption, and the record of it lives in the same Detail the
	// lifecycle writes alongside the state, so a crash cannot leave the
	// correlator spent-but-not-recorded or recorded-but-not-spent.
	if detail.Consumed() {
		return challenge.SubmitResult{}, fmt.Errorf("%w: %s was completed at %s",
			ErrCorrelatorConsumed, req.Instance, detail.ConsumedAt.UTC().Format(time.RFC3339Nano))
	}

	subject := req.Submitter
	switch {
	case subject == nil:
		return challenge.SubmitResult{}, fmt.Errorf("%w: no authenticated completion", challenge.ErrNotTarget)
	case subject.Kind != identity.SubjectUser:
		return challenge.SubmitResult{}, fmt.Errorf("%w: %s is a %s credential, and a step-up authenticates a person",
			challenge.ErrNotTarget, subject.CallerID(), subject.Kind)
	case subject.ID != detail.SubjectID:
		return challenge.SubmitResult{}, fmt.Errorf("%w: %s was opened for %q and completed by %q",
			challenge.ErrNotTarget, req.Instance, detail.SubjectID, subject.ID)
	}

	if err := verifyIssuedBy(detail, subject); err != nil {
		return challenge.SubmitResult{}, err
	}
	if err := d.verifyACR(detail, subject); err != nil {
		return challenge.SubmitResult{}, err
	}
	if err := d.verifyAMR(subject); err != nil {
		return challenge.SubmitResult{}, err
	}
	if err := verifyAuthTime(detail, subject); err != nil {
		return challenge.SubmitResult{}, err
	}
	if err := verifyNonce(detail, subject); err != nil {
		return challenge.SubmitResult{}, err
	}
	if err := verifyContext(detail, req.Decision); err != nil {
		return challenge.SubmitResult{}, err
	}

	consumed := req.Now.UTC()
	detail.ConsumedAt = &consumed
	detail.ConsumedBy = subject.CallerID()
	return challenge.SubmitResult{State: challenge.StateSatisfied, Have: 1, Need: 1, Detail: detail}, nil
}

// Status reports where the challenge stands as of req.Now.
//
// It is a read over the frozen detail: consumption is recorded there, so there
// is nothing to recount and nothing to re-verify. A stored terminal state is
// never walked back.
//
// An elapsed deadline means failed, as it does for a quorum and unlike a delay.
// A step-up nobody completed in time is a step-up nobody completed.
func (d *Delegated) Status(_ context.Context, req challenge.StatusRequest) (challenge.Status, error) {
	detail, err := DecodeDetail(req.Detail)
	if err != nil {
		return challenge.Status{}, err
	}
	have := 0
	if detail.Consumed() {
		have = 1
	}
	state := req.Stored
	if !state.Terminal() {
		switch {
		case detail.Consumed():
			state = challenge.StateSatisfied
		case req.Deadline != nil && !req.Now.Before(*req.Deadline):
			state = challenge.StateFailed
		default:
			state = challenge.StatePending
		}
	}
	return challenge.Status{State: state, Have: have, Need: 1, Deadline: req.Deadline}, nil
}

// View implements [challenge.Viewer]: it answers with the step-up destination
// and with nothing else on the row.
//
// A delegated MFA challenge is the one kind a caller cannot make progress on
// without being told something. The other three are completed by other people,
// by waiting, or by a system that was handed its own callback at issue; this one
// needs a browser sent somewhere, and until this seam existed the address was
// stored and never published (#41).
//
// One field crosses. The correlator is a binding value the completion has to
// carry, the nonce ties a token to this request, and neither is a caller's to
// hold — so this is a copy of a named field and never a copy of the detail. A
// CIBA challenge publishes nothing at all: its `auth_req_id` addresses the token
// exchange, not the subject, and there is nowhere to send anybody.
func (d *Delegated) View(_ context.Context, req challenge.ViewRequest) (challenge.View, error) {
	detail, err := DecodeDetail(req.Detail)
	if err != nil {
		return challenge.View{}, err
	}
	return challenge.View{AuthorizationURL: detail.AuthorizationURL}, nil
}

// Redeem implements [challenge.Redeemer]: it turns the IdP's redirect into the
// ID token that redirect was worth, and into the body that completes the
// challenge.
//
// It judges none of the authentication. The token goes back to the surface to
// be verified by [identity.Verifier], and then arrives at [Delegated.Submit] as
// a caller — the same path a CIBA poll and the mock-OP tests take, so there is
// one conjunction of checks and the transport does not get a second one. In
// particular the `acr` check, which U0 proved is the only thing standing between
// a silent downgrade and a satisfied step-up, runs there and only there.
//
// The correlator is put into the payload here rather than being asked of the
// caller. On the redirect path there is no caller to ask: a browser following an
// IdP's `Location` header carries what the IdP put in the query and nothing
// else. The correlator's job on this path is what it always was — to be the
// value the completion is recorded against — and the binding that a redirect
// belongs to this challenge is done by the path, the `state` and the `nonce`.
func (d *Delegated) Redeem(ctx context.Context, req challenge.RedeemRequest) (challenge.Redemption, error) {
	detail, err := DecodeDetail(req.Detail)
	if err != nil {
		return challenge.Redemption{}, err
	}
	// Refused before the token call rather than after it. A spent challenge has
	// nothing a code could add, and redeeming one would spend a real
	// authorization code to reach a refusal that was already certain.
	if detail.Consumed() {
		return challenge.Redemption{}, fmt.Errorf("%w: %s was completed at %s",
			ErrCorrelatorConsumed, req.Instance, detail.ConsumedAt.UTC().Format(time.RFC3339Nano))
	}
	redeemer, ok := d.initiator.(Redeemer)
	if !ok {
		return challenge.Redemption{}, fmt.Errorf("%w: %s was opened by a transport with no redirect",
			challenge.ErrNotRedeemable, req.Instance)
	}

	token, err := redeemer.Redeem(ctx, RedeemRequest{
		Instance:      req.Instance,
		Params:        req.Params,
		ExpectedState: detail.State,
		CodeVerifier:  detail.CodeVerifier,
		RedirectURI:   d.callbackFor(req.Instance),
	})
	if err != nil {
		return challenge.Redemption{}, err
	}
	payload, err := json.Marshal(Submission{Correlator: detail.Correlator})
	if err != nil {
		return challenge.Redemption{}, fmt.Errorf("mfa: encoding the completion for %s: %w", req.Instance, err)
	}
	return challenge.Redemption{Credential: token, Payload: payload}, nil
}

// IsTarget implements [challenge.Targeter] for R40's read rule.
//
// A delegated MFA challenge has exactly one target: the person it is asking to
// authenticate. Anyone else reading the decision would be reading it because
// they are its caller, which the lifecycle judges separately.
func (d *Delegated) IsTarget(_ context.Context, req challenge.TargetRequest) (bool, error) {
	detail, err := DecodeDetail(req.Detail)
	if err != nil {
		return false, err
	}
	s := req.Subject
	if s == nil || s.Kind != identity.SubjectUser || s.ID == "" {
		return false, nil
	}
	return s.ID == detail.SubjectID, nil
}

// ---------------------------------------------------------------------------
// completion checks
// ---------------------------------------------------------------------------

// verifyIssuedBy pins the completion to the party the challenge was opened
// against.
//
// The verifier that produced this Subject already checked the token against the
// deployment's issuer set and audience. This is narrower: a deployment may
// trust several issuers and several clients, and a challenge is satisfied by
// the authentication it asked for, not by any authentication the deployment
// would accept for anything.
func verifyIssuedBy(detail Detail, s *identity.Subject) error {
	if s.Issuer != detail.Issuer {
		return fmt.Errorf("%w: issued by %q, expected %q", ErrCredentialMismatch, s.Issuer, detail.Issuer)
	}
	if s.ClientID != detail.ClientID {
		return fmt.Errorf("%w: issued to client %q, expected %q", ErrCredentialMismatch, s.ClientID, detail.ClientID)
	}
	if !slices.Contains(s.Audience, detail.Audience) {
		return fmt.Errorf("%w: audience %v does not include %q", ErrCredentialMismatch, s.Audience, detail.Audience)
	}
	return nil
}

// verifyACR is the check U0 proved load-bearing.
//
// Two questions, in this order. Is the class one the operator admits at all —
// asked against the deployment's current allowlist, so that tightening it takes
// effect on challenges that are already open. And does it satisfy what the
// policy asked for.
//
// The first question cannot be dropped on the grounds that the second one
// subsumes it, because a policy is allowed to name no classes at all: then the
// allowlist is the entire requirement, and without it `acr=1` from a password
// login satisfies a step-up challenge.
func (d *Delegated) verifyACR(detail Detail, s *identity.Subject) error {
	if !slices.Contains(d.allowedACR, s.ACR) {
		return fmt.Errorf("%w: %q is not one of %v", ErrACRNotAllowed, s.ACR, d.allowedACR)
	}
	if len(detail.RequiredACRValues) > 0 && !slices.Contains(detail.RequiredACRValues, s.ACR) {
		return fmt.Errorf("%w: %q is not one of %v", ErrACRUnsatisfied, s.ACR, detail.RequiredACRValues)
	}
	return nil
}

// verifyAuthTime requires the authentication to have happened after the
// challenge opened.
//
// The bound is strict, and a token that reports no `auth_time` fails it. This
// is the one place the handler is stricter than `amr`: an absent `amr` is an
// IdP that did not classify a method, but an absent `auth_time` is the absence
// of the only evidence that this authentication answers this question rather
// than being a session that was already open when it was asked.
func verifyAuthTime(detail Detail, s *identity.Subject) error {
	if s.AuthTime.IsZero() {
		return fmt.Errorf("%w: the token reports no auth_time", ErrStaleAuthentication)
	}
	if !s.AuthTime.After(detail.IssuedAt) {
		return fmt.Errorf("%w: authenticated at %s, and the challenge opened at %s",
			ErrStaleAuthentication,
			s.AuthTime.UTC().Format(time.RFC3339Nano), detail.IssuedAt.UTC().Format(time.RFC3339Nano))
	}
	return nil
}

// verifyAMR compares the authentication methods, but only against a token that
// reported any.
//
// U0 found `amr` absent by default and `[]` even with the mapper attached, so
// an empty list is treated as "the IdP did not say" rather than as "no methods
// were used". That is a deliberate weakening of a check, and it is the
// difference between an optional comparison and a challenge no deployment could
// ever satisfy.
func (d *Delegated) verifyAMR(s *identity.Subject) error {
	if len(d.requireAMR) == 0 || len(s.AMR) == 0 {
		return nil
	}
	for _, got := range s.AMR {
		if slices.Contains(d.requireAMR, got) {
			return nil
		}
	}
	return fmt.Errorf("%w: token reports %v, none of which is in %v", ErrAMRMismatch, s.AMR, d.requireAMR)
}

// verifyNonce matches the token's `nonce` against the one derived from this
// challenge's correlator, when the token carries one.
//
// It is defence in depth rather than the binding: the correlator is the
// binding, and an IdP that omits `nonce` — as a CIBA flow does — leaves this
// check with nothing to say. What it buys is that somebody who learns a
// correlator still cannot pair it with a token minted for a different
// challenge, because the token itself names which challenge it answers.
func verifyNonce(detail Detail, s *identity.Subject) error {
	if detail.Nonce == "" {
		return nil
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := s.Claims(&claims); err != nil {
		// A subject with no readable claims is a client certificate, which the
		// subject-kind check above has already refused, or a test double. There
		// is no nonce to compare either way.
		return nil //nolint:nilerr // an absent claim set is an absent nonce, not a failure
	}
	if claims.Nonce == "" {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(detail.Nonce)) != 1 {
		return fmt.Errorf("%w: the token answers a different authentication request", ErrNonceMismatch)
	}
	return nil
}

// verifyContext refuses a completion for material the decision no longer holds.
//
// It is the same fail-closed rule the quorum handler applies to its approvals
// (R31): a revision that changed what is being authorized invalidates an
// authentication requested for the old content, rather than being papered over.
func verifyContext(detail Detail, dec challenge.DecisionContext) error {
	sum, err := ContextHash(dec)
	if err != nil {
		return err
	}
	current := hex.EncodeToString(sum[:])
	if !strings.EqualFold(current, detail.ContextHash) {
		return fmt.Errorf("%w: issued over %s and now reads %s", ErrContextChanged, detail.ContextHash, current)
	}
	return nil
}

// ---------------------------------------------------------------------------
// re-issue suppression
// ---------------------------------------------------------------------------

// reuse returns the terms of a challenge this process opened moments ago for
// the same subject over the same decision content.
//
// It is keyed on the context hash, which already covers the decision
// identifier, so this never hands one decision's correlator to another. What it
// prevents is the re-evaluation path opening a second authentication for a
// decision whose content did not change — a second prompt on somebody's phone,
// and a rotated correlator that would strand the step-up they are halfway
// through.
func (d *Delegated) reuse(subjectID, contextHash string, required []string, now time.Time) (Detail, bool) {
	if d.minReissue < 0 {
		return Detail{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.recent[reuseKey(subjectID, contextHash)]
	if !ok {
		return Detail{}, false
	}
	if now.Before(entry.at) || now.Sub(entry.at) >= d.minReissue {
		return Detail{}, false
	}
	// The terms have to be the ones that would be issued now. A revision that
	// only changed which classes are demanded leaves the context hash alone,
	// and reusing terms that no longer match the policy would be a challenge
	// enforcing a requirement nobody declared.
	if !slices.Equal(entry.detail.RequiredACRValues, required) ||
		!slices.Equal(entry.detail.AllowedACRValues, d.allowedACR) {
		return Detail{}, false
	}
	detail := entry.detail
	detail.RequiredACRValues = slices.Clone(entry.detail.RequiredACRValues)
	detail.AllowedACRValues = slices.Clone(entry.detail.AllowedACRValues)
	return detail, true
}

func (d *Delegated) remember(subjectID, contextHash string, detail Detail, now time.Time) {
	if d.minReissue < 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.recent) >= d.maxTracked {
		d.pruneLocked(now)
	}
	d.recent[reuseKey(subjectID, contextHash)] = recentIssue{at: now, detail: detail}
}

// pruneLocked drops entries that can no longer be reused, and then, if the cap
// is still reached, drops arbitrary ones. Losing an entry costs one extra IdP
// request; unbounded growth costs the process.
func (d *Delegated) pruneLocked(now time.Time) {
	for k, entry := range d.recent {
		if now.Sub(entry.at) >= d.minReissue {
			delete(d.recent, k)
		}
	}
	for k := range d.recent {
		if len(d.recent) < d.maxTracked {
			break
		}
		delete(d.recent, k)
	}
}

func reuseKey(subjectID, contextHash string) string { return subjectID + "\x00" + contextHash }

func randomCorrelator() (string, error) {
	buf := make([]byte, correlatorBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
