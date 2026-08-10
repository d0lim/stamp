package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingSink struct {
	mu      sync.Mutex
	records []AuthRecord
}

func (r *recordingSink) RecordAuth(_ context.Context, rec AuthRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec)
}

func (r *recordingSink) only(t *testing.T) AuthRecord {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.records) != 1 {
		t.Fatalf("want exactly one audit record, got %d", len(r.records))
	}
	return r.records[0]
}

type middlewareFixture struct {
	idp    *mockIdP
	now    time.Time
	mw     *Middleware
	audit  *recordingSink
	called *bool
}

func newMiddlewareFixture(t *testing.T, tlsID *TLSIdentity) *middlewareFixture {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	cfg := baseConfig(now, idp)
	cfg.Issuers[0].WorkloadClients = []string{"stamp-pep"}
	v := mustVerifier(t, cfg)

	audit := &recordingSink{}
	mw, err := NewMiddleware(MiddlewareConfig{Verifier: v, TLS: tlsID, Audit: audit, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("building middleware: %v", err)
	}
	called := false
	return &middlewareFixture{idp: idp, now: now, mw: mw, audit: audit, called: &called}
}

// handler flips the fixture's flag, so a test can assert that evaluation
// never started.
func (f *middlewareFixture) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*f.called = true
		w.WriteHeader(http.StatusOK)
	})
}

func (f *middlewareFixture) workloadToken(t *testing.T) string {
	t.Helper()
	claims := f.idp.claims(f.now)
	claims["sub"] = "service-account-stamp-pep"
	claims["azp"] = "stamp-pep"
	return f.idp.signRS256(t, "k1", "k1", claims)
}

func TestRequestWithoutWorkloadCredentialIsRejectedBeforeEvaluation(t *testing.T) {
	f := newMiddlewareFixture(t, nil)
	srv := f.mw.RequireWorkload(f.handler())

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", nil)
	req.RemoteAddr = "198.51.100.7:44321"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if *f.called {
		t.Fatal("the handler must not run for an unauthenticated request — R40 rejects before evaluation")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("a 401 must say how to authenticate")
	}

	record := f.audit.only(t)
	if record.Allowed {
		t.Error("the audit record must show the request was refused")
	}
	if record.Reason != ReasonMissingCredential {
		t.Errorf("reason: want %q, got %q", ReasonMissingCredential, record.Reason)
	}
	if record.CallerID != anonymousCaller {
		t.Errorf("caller id: want %q, got %q", anonymousCaller, record.CallerID)
	}
	if record.RemoteAddr != "198.51.100.7:44321" {
		t.Errorf("remote address: want 198.51.100.7:44321, got %q", record.RemoteAddr)
	}
	if record.Path != "/access/v1/evaluation" {
		t.Errorf("path: want /access/v1/evaluation, got %q", record.Path)
	}
}

func TestAuthenticatedWorkloadReachesTheHandlerAndIsAudited(t *testing.T) {
	f := newMiddlewareFixture(t, nil)
	var seen *Subject
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s, ok := SubjectFromContext(r.Context())
		if !ok {
			t.Error("the handler must be able to read the authenticated caller")
		}
		seen = s
	})
	srv := f.mw.RequireWorkload(next)

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", nil)
	req.Header.Set("Authorization", "Bearer "+f.workloadToken(t))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", rec.Code)
	}
	if seen == nil || seen.Kind != SubjectWorkload {
		t.Fatalf("the handler must see a workload subject, got %+v", seen)
	}

	record := f.audit.only(t)
	if !record.Allowed {
		t.Error("the audit record must show the request was allowed")
	}
	if record.Reason != ReasonAuthenticated {
		t.Errorf("reason: want %q, got %q", ReasonAuthenticated, record.Reason)
	}
	if record.CallerID != seen.CallerID() {
		t.Errorf("caller id: want %q, got %q", seen.CallerID(), record.CallerID)
	}
	if record.Kind != SubjectWorkload || record.Method != MethodBearerJWT {
		t.Errorf("the audit record must name the subject kind and credential method, got %q/%q", record.Kind, record.Method)
	}
}

func TestUserTokenIsRefusedOnAWorkloadSurface(t *testing.T) {
	f := newMiddlewareFixture(t, nil)
	srv := f.mw.RequireWorkload(f.handler())

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", nil)
	req.Header.Set("Authorization", "Bearer "+f.idp.signRS256(t, "k1", "k1", f.idp.claims(f.now)))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if *f.called {
		t.Fatal("a user token must not reach a PEP handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status: want 403, got %d", rec.Code)
	}

	record := f.audit.only(t)
	if record.Reason != ReasonWrongSubjectKind {
		t.Errorf("reason: want %q, got %q", ReasonWrongSubjectKind, record.Reason)
	}
	// The caller authenticated, so the audit row names them rather than
	// "anonymous" — that is the difference between "someone tried" and "this
	// service tried".
	if !strings.HasPrefix(record.CallerID, "user:") {
		t.Errorf("caller id: want the authenticated user, got %q", record.CallerID)
	}
}

func TestWorkloadTokenIsRefusedOnAUserSurface(t *testing.T) {
	f := newMiddlewareFixture(t, nil)
	srv := f.mw.RequireUser(f.handler())

	req := httptest.NewRequest(http.MethodPost, "/approvals", nil)
	req.Header.Set("Authorization", "Bearer "+f.workloadToken(t))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if *f.called {
		t.Fatal("a workload token must not stand in for a human approval")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status: want 403, got %d", rec.Code)
	}
}

func TestExpiredTokenIsRefusedByTheMiddleware(t *testing.T) {
	f := newMiddlewareFixture(t, nil)
	srv := f.mw.RequireWorkload(f.handler())

	claims := f.idp.claims(f.now)
	claims["sub"] = "service-account-stamp-pep"
	claims["azp"] = "stamp-pep"
	claims["exp"] = f.now.Add(-time.Minute).Unix()

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", nil)
	req.Header.Set("Authorization", "Bearer "+f.idp.signRS256(t, "k1", "k1", claims))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if *f.called {
		t.Fatal("an expired token must not reach the handler")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", rec.Code)
	}
	if got := f.audit.only(t).Reason; got != ReasonTokenExpired {
		t.Errorf("reason: want %q, got %q", ReasonTokenExpired, got)
	}
}

func TestMalformedAuthorizationHeaderIsAMissingCredential(t *testing.T) {
	f := newMiddlewareFixture(t, nil)
	srv := f.mw.RequireWorkload(f.handler())

	for _, header := range []string{"", "Basic dXNlcjpwYXNz", "Bearer", "Bearer "} {
		req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status want 401, got %d", header, rec.Code)
		}
	}
	if *f.called {
		t.Fatal("no malformed credential may reach the handler")
	}
}

func TestLowercaseBearerSchemeIsAccepted(t *testing.T) {
	f := newMiddlewareFixture(t, nil)
	srv := f.mw.RequireWorkload(f.handler())

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", nil)
	req.Header.Set("Authorization", "bearer "+f.workloadToken(t))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("the auth scheme is case-insensitive per RFC 7235, got %d", rec.Code)
	}
}

func TestClientCertificateIsAWorkloadCredential(t *testing.T) {
	id, err := NewTLSIdentity(TLSIdentityConfig{AllowedSubjects: []string{"spiffe://example.org/stamp/pep"}})
	if err != nil {
		t.Fatalf("building tls identity: %v", err)
	}
	f := newMiddlewareFixture(t, id)
	srv := f.mw.RequireWorkload(f.handler())

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", nil)
	req.TLS = verifiedState(leafCert(t, "spiffe://example.org/stamp/pep", "pep"))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", rec.Code)
	}
	if !*f.called {
		t.Fatal("an mtls workload must reach the handler")
	}
	record := f.audit.only(t)
	if record.Method != MethodMTLS {
		t.Errorf("method: want %q, got %q", MethodMTLS, record.Method)
	}
	if record.CallerID == anonymousCaller {
		t.Error("an mtls caller must be named in the audit record")
	}
}

func TestUnverifiedClientCertificateIsRefused(t *testing.T) {
	id, err := NewTLSIdentity(TLSIdentityConfig{AllowedSubjects: []string{"spiffe://example.org/stamp/pep"}})
	if err != nil {
		t.Fatalf("building tls identity: %v", err)
	}
	f := newMiddlewareFixture(t, id)
	srv := f.mw.RequireWorkload(f.handler())

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leafCert(t, "spiffe://example.org/stamp/pep", "pep")},
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if *f.called {
		t.Fatal("an unverified certificate must not reach the handler")
	}
	if got := f.audit.only(t).Reason; got != ReasonCertificateUnchecked {
		t.Errorf("reason: want %q, got %q", ReasonCertificateUnchecked, got)
	}
}

func TestMiddlewareRequiresAVerifierAndAnAuditSink(t *testing.T) {
	now := time.Now()
	idp := newMockIdP(t, "k1")
	v := mustVerifier(t, baseConfig(now, idp))

	if _, err := NewMiddleware(MiddlewareConfig{Audit: &recordingSink{}}); err == nil {
		t.Error("a middleware without a verifier must be refused")
	}
	if _, err := NewMiddleware(MiddlewareConfig{Verifier: v}); err == nil {
		t.Error("a middleware without an audit sink must be refused — an unaudited PEP surface fails R40")
	}
}

func TestStatusForAndReasonForCoverEveryFailure(t *testing.T) {
	cases := []struct {
		err    error
		reason string
		status int
	}{
		{nil, ReasonAuthenticated, http.StatusOK},
		{ErrMissingCredential, ReasonMissingCredential, http.StatusUnauthorized},
		{ErrMalformedToken, ReasonMalformedToken, http.StatusUnauthorized},
		{ErrAlgorithmNotAllowed, ReasonAlgorithmNotAllowed, http.StatusUnauthorized},
		{ErrIssuerNotAllowed, ReasonIssuerNotAllowed, http.StatusUnauthorized},
		{ErrAudienceMismatch, ReasonAudienceMismatch, http.StatusUnauthorized},
		{ErrTokenExpired, ReasonTokenExpired, http.StatusUnauthorized},
		{ErrSignatureInvalid, ReasonSignatureInvalid, http.StatusUnauthorized},
		{ErrUnknownKey, ReasonUnknownKey, http.StatusUnauthorized},
		{ErrRefetchThrottled, ReasonRefetchThrottled, http.StatusServiceUnavailable},
		{ErrACRNotAllowed, ReasonACRNotAllowed, http.StatusUnauthorized},
		{ErrWrongSubjectKind, ReasonWrongSubjectKind, http.StatusForbidden},
		{ErrPeerCertificateUnverified, ReasonCertificateUnchecked, http.StatusUnauthorized},
		{ErrWorkloadNotAllowed, ReasonWorkloadNotAllowed, http.StatusForbidden},
	}
	for _, c := range cases {
		if got := ReasonFor(c.err); got != c.reason {
			t.Errorf("%v: reason want %q, got %q", c.err, c.reason, got)
		}
		if got := StatusFor(c.err); got != c.status {
			t.Errorf("%v: status want %d, got %d", c.err, c.status, got)
		}
	}
}
