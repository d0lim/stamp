package identity

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Workload credential failures.
var (
	// ErrMissingCredential means the request presented no credential at all.
	// R40 requires this to be decided before evaluation, so it is the one
	// failure that costs nothing to produce.
	ErrMissingCredential = errors.New("identity: no credential presented")
	// ErrWrongSubjectKind means the caller authenticated but is the wrong
	// kind of subject for this surface — a user token at a PEP endpoint, or a
	// workload token where a human approval is required.
	ErrWrongSubjectKind = errors.New("identity: wrong subject kind")
	// ErrPeerCertificateUnverified means a client certificate was presented
	// but the TLS handshake did not verify it against the configured roots.
	ErrPeerCertificateUnverified = errors.New("identity: peer certificate was not verified")
	// ErrWorkloadNotAllowed means a verified client certificate carries no
	// identity in the operator's allowlist.
	ErrWorkloadNotAllowed = errors.New("identity: workload identity not allowed")
)

// SubjectKind distinguishes the two kinds of caller STAMP authenticates.
//
// They share one middleware layer and one verification path, but never one
// authorisation decision: a surface always states which kind it accepts, so a
// credential minted for one cannot be replayed at the other.
type SubjectKind string

// The subject kinds.
const (
	// SubjectUser is a human acting through the console or an approval
	// submission. Their token comes from an interactive login.
	SubjectUser SubjectKind = "user"
	// SubjectWorkload is a machine calling the PEP surface, holding either a
	// client-credentials token or a client certificate.
	SubjectWorkload SubjectKind = "workload"
)

// CredentialMethod records how the caller proved who they are, so that an
// audit row says which of the two R40 mechanisms was used.
type CredentialMethod string

// The credential methods.
const (
	// MethodBearerJWT is an OIDC token verified against the issuer's JWKS.
	MethodBearerJWT CredentialMethod = "bearer_jwt"
	// MethodMTLS is a client certificate verified by the TLS handshake.
	MethodMTLS CredentialMethod = "mtls"
)

// Subject is an authenticated caller.
//
// It is the type the check API, the decide lifecycle and the quorum surface
// consume; nothing above this package needs to know whether the credential
// was a token or a certificate. STAMP holds no state about a Subject beyond
// the request that carried it (D7) — this value is derived from the
// credential and thrown away with the request.
type Subject struct {
	// Kind is which sort of caller this is.
	Kind SubjectKind
	// Method is how they proved it.
	Method CredentialMethod
	// Issuer is the token issuer, or the certificate issuer for mTLS.
	Issuer string
	// ID is the subject identifier: `sub` for a token, the matched SAN or
	// common name for a certificate.
	ID string
	// ClientID is the OAuth client the credential was issued to, taken from
	// `azp`, then `client_id`, then `sub`. Empty for mTLS.
	ClientID string
	// Audience is the verified audience list.
	Audience []string
	// IssuedAt, ExpiresAt and AuthTime come from the token; AuthTime is zero
	// when the IdP did not supply `auth_time`.
	IssuedAt  time.Time
	ExpiresAt time.Time
	AuthTime  time.Time
	// ACR is the authentication context class the IdP returned. U0 found that
	// a request for a stronger class is silently downgraded rather than
	// refused, so this is the value that counts — never the one that was
	// asked for.
	ACR string
	// AMR is the authentication methods list. U0 found it empty in default
	// IdP configurations, so a caller may compare it when present but must
	// not require it.
	AMR []string

	claims json.RawMessage
}

// CallerID is the identifier R40 requires on every audit row.
//
// It is qualified by kind and issuer because a subject identifier is only
// unique inside its issuer, and because an audit reader must be able to tell
// a workload apart from a person without joining another table.
func (s *Subject) CallerID() string {
	if s == nil {
		return anonymousCaller
	}
	return fmt.Sprintf("%s:%s#%s", s.Kind, s.Issuer, s.ID)
}

// Claims unmarshals the verified token claims into v. It fails for a subject
// that authenticated with a client certificate, which carries no claims.
func (s *Subject) Claims(v any) error {
	if len(s.claims) == 0 {
		return errors.New("identity: subject carries no token claims")
	}
	return json.Unmarshal(s.claims, v)
}

// anonymousCaller is what an unauthenticated request is called in the audit.
// A rejection still has to name someone, and "nobody" is a truthful name.
const anonymousCaller = "anonymous"

// TLSIdentityConfig pins which client certificates count as workloads.
type TLSIdentityConfig struct {
	// AllowedSubjects is the allowlist of certificate identities. An entry is
	// matched against the leaf certificate's URI SANs (a SPIFFE ID, say),
	// then its DNS SANs, then "CN=" followed by its common name.
	//
	// Chain validity is necessary but not sufficient: any certificate the
	// configured CA has ever signed would otherwise be a PEP credential.
	AllowedSubjects []string
}

// TLSIdentity turns a verified client certificate into a workload subject.
type TLSIdentity struct {
	allowed map[string]struct{}
}

// NewTLSIdentity builds a TLSIdentity, rejecting an empty allowlist — an
// allowlist that admits nothing is a configuration mistake, and one that
// admits everything is not expressible.
func NewTLSIdentity(cfg TLSIdentityConfig) (*TLSIdentity, error) {
	if len(cfg.AllowedSubjects) == 0 {
		return nil, errors.New("identity: mtls requires at least one allowed subject")
	}
	t := &TLSIdentity{allowed: make(map[string]struct{}, len(cfg.AllowedSubjects))}
	for _, s := range cfg.AllowedSubjects {
		if s == "" {
			return nil, errors.New("identity: mtls allowed subjects must not be empty")
		}
		t.allowed[s] = struct{}{}
	}
	return t, nil
}

// Subject derives a workload subject from a TLS connection state.
//
// It requires a verified chain rather than merely a presented certificate:
// with tls.RequestClientCert or tls.VerifyClientCertIfGiven the peer chooses
// what to send and nothing checks it, so trusting PeerCertificates alone
// would accept a self-signed certificate naming any workload.
func (t *TLSIdentity) Subject(state *tls.ConnectionState) (*Subject, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("%w: no client certificate", ErrMissingCredential)
	}
	if len(state.VerifiedChains) == 0 {
		return nil, ErrPeerCertificateUnverified
	}

	leaf := state.PeerCertificates[0]
	candidates := make([]string, 0, len(leaf.URIs)+len(leaf.DNSNames)+1)
	for _, u := range leaf.URIs {
		candidates = append(candidates, u.String())
	}
	candidates = append(candidates, leaf.DNSNames...)
	if leaf.Subject.CommonName != "" {
		candidates = append(candidates, "CN="+leaf.Subject.CommonName)
	}

	for _, c := range candidates {
		if _, ok := t.allowed[c]; ok {
			return &Subject{
				Kind:      SubjectWorkload,
				Method:    MethodMTLS,
				Issuer:    leaf.Issuer.String(),
				ID:        c,
				ExpiresAt: leaf.NotAfter,
				IssuedAt:  leaf.NotBefore,
			}, nil
		}
	}
	return nil, fmt.Errorf("%w: certificate presents %v", ErrWorkloadNotAllowed, candidates)
}

// requireKind reports whether s is one of the accepted kinds. An empty list
// accepts any authenticated subject.
func requireKind(s *Subject, kinds []SubjectKind) error {
	if len(kinds) == 0 {
		return nil
	}
	if slices.Contains(kinds, s.Kind) {
		return nil
	}
	return fmt.Errorf("%w: %q is not one of %v", ErrWrongSubjectKind, s.Kind, kinds)
}
