package mfa

// stepup.go is the RFC 9470 initiator, and D26 makes it the demo's default
// path: CIBA needs a decoupled authentication server no self-hostable IdP
// ships, and a step-up redirect needs nothing but a browser.
//
// The adapter is thin on purpose. The request itself is built by
// [identity.StepUp], because where a deployment sends its people to
// authenticate is the same kind of operator-pinned fact as which issuers it
// trusts, and it belongs beside the code that judges what comes back.

// # What travels and what stays (KTD2, KTD3)
//
// `state` is a fresh random value and not the correlator. The callback path is
// `/decisions/{id}/challenges/{ordinal}/mfa`, so the path already says which
// challenge a redirect belongs to and `state` has only one job left: proving the
// redirect answers a request this deployment made. Sending the correlator
// instead would put a 32-byte binding secret in an address bar, a `Referer` and
// a browser history entry in order to do a job a throwaway nonce does as well.
//
// The PKCE verifier is minted here and stored on the challenge row, because a
// public client has nothing else with which to prove that the party redeeming
// the code is the party that asked for it.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/identity"
)

// stateBytes is the entropy in a `state`. It is a CSRF token that lives for one
// browser round trip, and it is sized as a secret because an attacker who could
// guess it could cause a redirect this deployment would believe it had asked for.
const stateBytes = 32

// StepUp initiates an authentication by sending the subject to the IdP, and
// redeems the redirect it comes back as.
//
// The derived nonce travels as `nonce` and a fresh CSRF token as `state`. The
// correlator does not travel at all: it stays on the challenge row and is what
// the completion is submitted under once the code has been redeemed. The
// reference code does not travel either — there is no `binding_message` in an
// authorization request, and the human-readable amount and payee come from the
// decision lookup the approval screen does.
type StepUp struct {
	requests *identity.StepUp
	newState func() (string, error)
}

var (
	_ Initiator = (*StepUp)(nil)
	_ Redeemer  = (*StepUp)(nil)
)

// NewStepUp wraps a configured [identity.StepUp] as an [Initiator].
func NewStepUp(requests *identity.StepUp) (*StepUp, error) {
	if requests == nil {
		return nil, errors.New("mfa: a step-up initiator needs a configured authorization request builder")
	}
	return &StepUp{requests: requests, newState: randomState}, nil
}

// Initiate implements [Initiator].
func (s *StepUp) Initiate(_ context.Context, req InitiateRequest) (InitiateResult, error) {
	state, err := s.newState()
	if err != nil {
		return InitiateResult{}, fmt.Errorf("mfa: generating a step-up state: %w", err)
	}
	verifier, codeChallenge, err := identity.NewPKCE()
	if err != nil {
		return InitiateResult{}, fmt.Errorf("mfa: %w", err)
	}
	url, err := s.requests.AuthorizationURL(identity.StepUpRequest{
		State:         state,
		Nonce:         req.Nonce,
		ACRValues:     req.ACRValues,
		LoginHint:     req.SubjectID,
		RedirectURI:   req.RedirectURI,
		CodeChallenge: codeChallenge,
	})
	if err != nil {
		return InitiateResult{}, fmt.Errorf("mfa: building a step-up request: %w", err)
	}
	return InitiateResult{
		Method:           MethodStepUp,
		AuthorizationURL: url,
		State:            state,
		CodeVerifier:     verifier,
	}, nil
}

// Redeem implements [Redeemer].
//
// Two refusals happen here and both are the transport's own. The `state`
// comparison is the CSRF check, and it runs before anything is sent anywhere:
// an unsolicited redirect must not cause this deployment to make a token call
// at all. The exchange is the second, and the OP's `redirect_uri` check inside
// it is what makes a code minted for one challenge unusable at another's path,
// because the path is the redirect target.
//
// An `error` parameter is the IdP declining, and it is reported rather than
// treated as a missing code: an operator reading `access_denied` learns
// something an operator reading "no code" does not.
func (s *StepUp) Redeem(ctx context.Context, req RedeemRequest) (string, error) {
	if req.ExpectedState == "" {
		return "", fmt.Errorf("%w: this challenge minted no state to compare against",
			challenge.ErrRedemptionRefused)
	}
	got := req.Params["state"]
	if subtle.ConstantTimeCompare([]byte(got), []byte(req.ExpectedState)) != 1 {
		return "", fmt.Errorf("%w: the callback echoes a state this challenge did not issue",
			challenge.ErrRedemptionRefused)
	}
	if idpErr := req.Params["error"]; idpErr != "" {
		return "", fmt.Errorf("%w: the idp declined with %q: %s",
			challenge.ErrRedemptionRefused, idpErr, req.Params["error_description"])
	}
	code := req.Params["code"]
	if code == "" {
		return "", fmt.Errorf("%w: the callback carries no authorization code",
			challenge.ErrRedemptionRefused)
	}

	token, err := s.requests.Exchange(ctx, identity.CodeExchange{
		Code:         code,
		CodeVerifier: req.CodeVerifier,
		RedirectURI:  req.RedirectURI,
	})
	if err != nil {
		if errors.Is(err, identity.ErrAuthorizationCodeRejected) {
			return "", fmt.Errorf("%w: %w", challenge.ErrRedemptionRefused, err)
		}
		return "", fmt.Errorf("mfa: redeeming the step-up for %s: %w", req.Instance, err)
	}
	return token, nil
}

func randomState() (string, error) {
	buf := make([]byte, stateBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Fallback tries one initiator and falls back to another.
//
// It branches on [ErrInitiationUnsupported] alone. A CIBA request that fails
// because the IdP is down is not a reason to redirect somebody's browser
// instead — it is an outage, and turning it into a different flow would hide
// the outage behind a working-looking demo. D26's fallback is about a capability
// the IdP does not have, not about a request that did not go through.
type Fallback struct {
	primary   Initiator
	secondary Initiator
}

var (
	_ Initiator = (*Fallback)(nil)
	_ Redeemer  = (*Fallback)(nil)
)

// NewFallback builds a chain of two initiators.
func NewFallback(primary, secondary Initiator) (*Fallback, error) {
	if primary == nil || secondary == nil {
		return nil, errors.New("mfa: a fallback chain needs two initiators")
	}
	return &Fallback{primary: primary, secondary: secondary}, nil
}

// Initiate implements [Initiator].
func (f *Fallback) Initiate(ctx context.Context, req InitiateRequest) (InitiateResult, error) {
	out, err := f.primary.Initiate(ctx, req)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, ErrInitiationUnsupported) {
		return InitiateResult{}, err
	}
	return f.secondary.Initiate(ctx, req)
}

// Redeem implements [Redeemer] by forwarding to whichever half of the chain has
// a redirect to redeem.
//
// A challenge that was opened through the fallback was opened by exactly one of
// the two, and only a redirect transport leaves a `state` behind — so the check
// that a redemption belongs to this transport is the state comparison the
// redeemer makes, not a branch here. A chain of two initiators that neither
// redeems is [challenge.ErrNotRedeemable], which is what the lifecycle answers
// for a kind with no redirect at all.
func (f *Fallback) Redeem(ctx context.Context, req RedeemRequest) (string, error) {
	for _, candidate := range []Initiator{f.primary, f.secondary} {
		if r, ok := candidate.(Redeemer); ok {
			return r.Redeem(ctx, req)
		}
	}
	return "", fmt.Errorf("%w: %s", challenge.ErrNotRedeemable, req.Instance)
}
