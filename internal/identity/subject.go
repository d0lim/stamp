package identity

// subject.go exists for one reason: [Subject.Claims] reads an unexported field,
// so outside this package a Subject that answers Claims can only be produced by
// running a token through [Verifier.Verify] — which means standing up a JWKS
// endpoint. U20 duplicated ninety lines of mock IdP to get one, and U10 would
// have been the third copy.
//
// [NewSubject] is the narrow way out. It verifies nothing and says so, which is
// the whole safety argument: a caller reaching for it is stating that the
// credential was verified somewhere else, and there is exactly one place in
// production code where that is true — the mTLS path, which builds a Subject
// directly because a certificate carries no claims to attach.

import (
	"encoding/json"
	"slices"
)

// NewSubject assembles a Subject carrying an already-verified claim set.
//
// It performs no verification of any kind. It does not check a signature, an
// issuer, an audience, an expiry or an authentication context class, and it
// must never be reachable from a request path: the only supported way to turn a
// credential into a Subject is [Verifier.Verify], which is where the trust
// boundary in this package is stated.
//
// What it is for is the other direction — a test, or an adapter that has
// verified a credential by some means this package does not implement, that
// needs the resulting caller to answer [Subject.Claims]. The claims are stored
// verbatim; a nil or empty document leaves the Subject in the same state as one
// built from a client certificate, where Claims reports that there are none.
func NewSubject(s Subject, claims json.RawMessage) *Subject {
	out := s
	out.Audience = slices.Clone(s.Audience)
	out.AMR = slices.Clone(s.AMR)
	if len(claims) > 0 {
		out.claims = slices.Clone(claims)
	}
	return &out
}
