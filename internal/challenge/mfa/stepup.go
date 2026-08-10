package mfa

// stepup.go is the RFC 9470 initiator, and D26 makes it the demo's default
// path: CIBA needs a decoupled authentication server no self-hostable IdP
// ships, and a step-up redirect needs nothing but a browser.
//
// The adapter is thin on purpose. The request itself is built by
// [identity.StepUp], because where a deployment sends its people to
// authenticate is the same kind of operator-pinned fact as which issuers it
// trusts, and it belongs beside the code that judges what comes back.

import (
	"context"
	"errors"
	"fmt"

	"github.com/d0lim/stamp/internal/identity"
)

// StepUp initiates an authentication by sending the subject to the IdP.
//
// The correlator travels as `state` and the derived nonce as `nonce`. The
// reference code does not travel at all on this path: there is no
// `binding_message` in an authorization request, and the human-readable amount
// and payee come from the decision lookup the approval screen does.
type StepUp struct {
	requests *identity.StepUp
}

var _ Initiator = (*StepUp)(nil)

// NewStepUp wraps a configured [identity.StepUp] as an [Initiator].
func NewStepUp(requests *identity.StepUp) (*StepUp, error) {
	if requests == nil {
		return nil, errors.New("mfa: a step-up initiator needs a configured authorization request builder")
	}
	return &StepUp{requests: requests}, nil
}

// Initiate implements [Initiator].
func (s *StepUp) Initiate(_ context.Context, req InitiateRequest) (InitiateResult, error) {
	url, err := s.requests.AuthorizationURL(identity.StepUpRequest{
		State:       req.Correlator,
		Nonce:       req.Nonce,
		ACRValues:   req.ACRValues,
		LoginHint:   req.SubjectID,
		RedirectURI: req.RedirectURI,
	})
	if err != nil {
		return InitiateResult{}, fmt.Errorf("mfa: building a step-up request: %w", err)
	}
	return InitiateResult{Method: MethodStepUp, AuthorizationURL: url}, nil
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

var _ Initiator = (*Fallback)(nil)

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
