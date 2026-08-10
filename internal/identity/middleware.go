package identity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Audit reasons. They are stable strings because an audit reader and an alert
// rule match on them; the English in the wrapped error is for a person.
const (
	ReasonAuthenticated        = "authenticated"
	ReasonMissingCredential    = "missing_credential"
	ReasonMalformedToken       = "malformed_token"
	ReasonAlgorithmNotAllowed  = "algorithm_not_allowed"
	ReasonIssuerNotAllowed     = "issuer_not_allowed"
	ReasonAudienceMismatch     = "audience_mismatch"
	ReasonTokenExpired         = "token_expired"
	ReasonSignatureInvalid     = "signature_invalid"
	ReasonUnknownKey           = "unknown_key"
	ReasonRefetchThrottled     = "refetch_throttled"
	ReasonACRNotAllowed        = "acr_not_allowed"
	ReasonWrongSubjectKind     = "wrong_subject_kind"
	ReasonCertificateUnchecked = "peer_certificate_unverified"
	ReasonWorkloadNotAllowed   = "workload_not_allowed"
	ReasonUnknown              = "unknown"
)

// ReasonFor maps a verification failure to its stable audit reason.
func ReasonFor(err error) string {
	switch {
	case err == nil:
		return ReasonAuthenticated
	case errors.Is(err, ErrMissingCredential):
		return ReasonMissingCredential
	case errors.Is(err, ErrAlgorithmNotAllowed):
		return ReasonAlgorithmNotAllowed
	case errors.Is(err, ErrIssuerNotAllowed):
		return ReasonIssuerNotAllowed
	case errors.Is(err, ErrAudienceMismatch):
		return ReasonAudienceMismatch
	case errors.Is(err, ErrTokenExpired):
		return ReasonTokenExpired
	case errors.Is(err, ErrSignatureInvalid):
		return ReasonSignatureInvalid
	case errors.Is(err, ErrUnknownKey):
		return ReasonUnknownKey
	case errors.Is(err, ErrRefetchThrottled):
		return ReasonRefetchThrottled
	case errors.Is(err, ErrACRNotAllowed):
		return ReasonACRNotAllowed
	case errors.Is(err, ErrWrongSubjectKind):
		return ReasonWrongSubjectKind
	case errors.Is(err, ErrPeerCertificateUnverified):
		return ReasonCertificateUnchecked
	case errors.Is(err, ErrWorkloadNotAllowed):
		return ReasonWorkloadNotAllowed
	case errors.Is(err, ErrMalformedToken):
		return ReasonMalformedToken
	default:
		return ReasonUnknown
	}
}

// StatusFor maps a verification failure to the HTTP status the middleware
// answers with.
//
// Every credential failure is 401 whatever the actual cause, so that the
// response is not an oracle telling an attacker which pin they tripped; the
// precise reason goes to the audit record instead. Two cases differ on
// purpose: an authenticated caller of the wrong kind gets 403, because the
// credential is fine and re-presenting it will not help, and a spent refetch
// budget gets 503, because it is a transient server condition that a
// legitimate client should retry rather than re-authenticate for.
func StatusFor(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrRefetchThrottled):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrWrongSubjectKind), errors.Is(err, ErrWorkloadNotAllowed):
		return http.StatusForbidden
	default:
		return http.StatusUnauthorized
	}
}

// AuthRecord is one authentication attempt, accepted or rejected.
//
// R40 asks for the caller identifier on the audit row; a rejection has one
// too, even if it is only "anonymous" and a peer address, because a surface
// that audits nothing but successes cannot show that it refused anything.
type AuthRecord struct {
	// Time is when the attempt was decided.
	Time time.Time
	// CallerID identifies the caller, or is "anonymous" when no credential
	// was presented.
	CallerID string
	// Kind and Method are empty when authentication failed before a subject
	// existed.
	Kind   SubjectKind
	Method CredentialMethod
	// Issuer is the token or certificate issuer, when one was established.
	Issuer string
	// Allowed is whether the request was let through.
	Allowed bool
	// Reason is the stable audit reason; see ReasonFor.
	Reason string
	// HTTPMethod, Path and RemoteAddr locate the attempt.
	HTTPMethod string
	Path       string
	RemoteAddr string
}

// AuditSink receives one AuthRecord per authentication attempt.
//
// The identity layer does not know how audit rows are stored or chained; it
// only knows that a PEP surface which does not record its callers does not
// satisfy R40. Implementations must not block for long — the record is
// written on the request path, before the handler runs.
type AuditSink interface {
	// RecordAuth records one authentication attempt.
	RecordAuth(ctx context.Context, rec AuthRecord)
}

// AuditSinkFunc adapts a function to AuditSink.
type AuditSinkFunc func(ctx context.Context, rec AuthRecord)

// RecordAuth calls f.
func (f AuditSinkFunc) RecordAuth(ctx context.Context, rec AuthRecord) { f(ctx, rec) }

// MiddlewareConfig wires the HTTP authentication boundary.
type MiddlewareConfig struct {
	// Verifier verifies bearer tokens. Required.
	Verifier *Verifier
	// TLS, when set, lets a verified client certificate stand in for a
	// bearer token as a workload credential.
	TLS *TLSIdentity
	// Audit receives every attempt. Required.
	Audit AuditSink
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Middleware authenticates HTTP callers and hands the surfaces above it a
// [Subject].
//
// It is the single authentication layer: user tokens, workload tokens and
// client certificates all arrive here and leave as subjects distinguished by
// [SubjectKind]. A surface states the kinds it accepts and gets nothing else.
type Middleware struct {
	verifier *Verifier
	tls      *TLSIdentity
	audit    AuditSink
	now      func() time.Time
}

// NewMiddleware builds a Middleware.
func NewMiddleware(cfg MiddlewareConfig) (*Middleware, error) {
	if cfg.Verifier == nil {
		return nil, errors.New("identity: middleware requires a verifier")
	}
	if cfg.Audit == nil {
		return nil, errors.New("identity: middleware requires an audit sink")
	}
	m := &Middleware{verifier: cfg.Verifier, tls: cfg.TLS, audit: cfg.Audit, now: cfg.Now}
	if m.now == nil {
		m.now = time.Now
	}
	return m, nil
}

type subjectKey struct{}

// SubjectFromContext returns the authenticated caller a Middleware put on the
// request context.
func SubjectFromContext(ctx context.Context) (*Subject, bool) {
	s, ok := ctx.Value(subjectKey{}).(*Subject)
	return s, ok
}

// RequireWorkload wraps a PEP handler so that only a workload credential
// reaches it.
func (m *Middleware) RequireWorkload(next http.Handler) http.Handler {
	return m.Require(SubjectWorkload)(next)
}

// RequireUser wraps a handler so that only an end-user token reaches it.
func (m *Middleware) RequireUser(next http.Handler) http.Handler {
	return m.Require(SubjectUser)(next)
}

// Require returns middleware that admits only the named subject kinds. With
// no kinds it admits any authenticated caller.
//
// The handler never runs for a request that failed authentication: the
// rejection and its audit record both happen first, which is what R40 means
// by rejecting before evaluation.
func (m *Middleware) Require(kinds ...SubjectKind) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sub, err := m.authenticate(r)
			if err == nil {
				err = requireKind(sub, kinds)
			}
			m.record(r, sub, err)
			if err != nil {
				m.reject(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), subjectKey{}, sub)))
		})
	}
}

// Authenticate exposes the credential check without the HTTP wrapper, for
// surfaces that own their own response shape.
func (m *Middleware) Authenticate(r *http.Request) (*Subject, error) {
	return m.authenticate(r)
}

func (m *Middleware) authenticate(r *http.Request) (*Subject, error) {
	if token, ok := bearerToken(r); ok {
		return m.verifier.Verify(r.Context(), token)
	}
	if m.tls != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return m.tls.Subject(r.TLS)
	}
	return nil, ErrMissingCredential
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	const prefix = "bearer "
	if len(h) <= len(prefix) || !equalASCIIFold(h[:len(prefix)], prefix) {
		return "", false
	}
	token := h[len(prefix):]
	if token == "" {
		return "", false
	}
	return token, true
}

func equalASCIIFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func (m *Middleware) record(r *http.Request, sub *Subject, err error) {
	rec := AuthRecord{
		Time:       m.now(),
		CallerID:   anonymousCaller,
		Allowed:    err == nil,
		Reason:     ReasonFor(err),
		HTTPMethod: r.Method,
		Path:       r.URL.Path,
		RemoteAddr: r.RemoteAddr,
	}
	if sub != nil {
		rec.CallerID = sub.CallerID()
		rec.Kind = sub.Kind
		rec.Method = sub.Method
		rec.Issuer = sub.Issuer
	}
	m.audit.RecordAuth(r.Context(), rec)
}

func (m *Middleware) reject(w http.ResponseWriter, err error) {
	status := StatusFor(err)
	code := "invalid_token"
	switch status {
	case http.StatusForbidden:
		code = "insufficient_scope"
	case http.StatusServiceUnavailable:
		code = "temporarily_unavailable"
		w.Header().Set("Retry-After", "1")
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer error=%q", code))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, fmt.Sprintf("{\"error\":%q}\n", code))
}
