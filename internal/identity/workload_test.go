package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// leafCert mints a client certificate carrying the given SPIFFE-style URI SAN
// and common name.
func leafCert(t *testing.T, uri, commonName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("parsing uri san: %v", err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

func verifiedState(cert *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
}

func TestTLSIdentityAcceptsAnAllowlistedWorkload(t *testing.T) {
	id, err := NewTLSIdentity(TLSIdentityConfig{AllowedSubjects: []string{"spiffe://example.org/stamp/pep"}})
	if err != nil {
		t.Fatalf("building tls identity: %v", err)
	}

	sub, err := id.Subject(verifiedState(leafCert(t, "spiffe://example.org/stamp/pep", "pep")))
	if err != nil {
		t.Fatalf("an allowlisted workload certificate must be accepted, got %v", err)
	}
	if sub.Kind != SubjectWorkload {
		t.Errorf("kind: want %q, got %q", SubjectWorkload, sub.Kind)
	}
	if sub.Method != MethodMTLS {
		t.Errorf("method: want %q, got %q", MethodMTLS, sub.Method)
	}
	if sub.ID != "spiffe://example.org/stamp/pep" {
		t.Errorf("id: want the spiffe id, got %q", sub.ID)
	}
	if sub.CallerID() == anonymousCaller {
		t.Error("an authenticated workload must have a caller id")
	}
}

func TestTLSIdentityRejectsAnUnverifiedChain(t *testing.T) {
	id, err := NewTLSIdentity(TLSIdentityConfig{AllowedSubjects: []string{"spiffe://example.org/stamp/pep"}})
	if err != nil {
		t.Fatalf("building tls identity: %v", err)
	}

	// The peer presented exactly the right certificate — and nothing checked
	// it, because the listener asked for a certificate without verifying one.
	// Anyone can present this.
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leafCert(t, "spiffe://example.org/stamp/pep", "pep")},
	}
	if _, err := id.Subject(state); !errors.Is(err, ErrPeerCertificateUnverified) {
		t.Fatalf("an unverified peer certificate must be rejected, got %v", err)
	}
}

func TestTLSIdentityRejectsAnUnlistedWorkload(t *testing.T) {
	id, err := NewTLSIdentity(TLSIdentityConfig{AllowedSubjects: []string{"spiffe://example.org/stamp/pep"}})
	if err != nil {
		t.Fatalf("building tls identity: %v", err)
	}

	// A valid chain from the same CA, for a different workload. Chain
	// validity alone would make every certificate the CA ever signed into a
	// PEP credential.
	_, err = id.Subject(verifiedState(leafCert(t, "spiffe://example.org/other/service", "other")))
	if !errors.Is(err, ErrWorkloadNotAllowed) {
		t.Fatalf("an unlisted workload must be rejected, got %v", err)
	}
}

func TestTLSIdentityMatchesCommonNameWhenAllowlisted(t *testing.T) {
	id, err := NewTLSIdentity(TLSIdentityConfig{AllowedSubjects: []string{"CN=stamp-pep"}})
	if err != nil {
		t.Fatalf("building tls identity: %v", err)
	}
	sub, err := id.Subject(verifiedState(leafCert(t, "", "stamp-pep")))
	if err != nil {
		t.Fatalf("a common-name allowlist entry must match, got %v", err)
	}
	if sub.ID != "CN=stamp-pep" {
		t.Errorf("id: want CN=stamp-pep, got %q", sub.ID)
	}
}

func TestTLSIdentityRejectsAMissingCertificate(t *testing.T) {
	id, err := NewTLSIdentity(TLSIdentityConfig{AllowedSubjects: []string{"CN=stamp-pep"}})
	if err != nil {
		t.Fatalf("building tls identity: %v", err)
	}
	if _, err := id.Subject(nil); !errors.Is(err, ErrMissingCredential) {
		t.Fatalf("no certificate at all must be a missing credential, got %v", err)
	}
}

func TestTLSIdentityRequiresAnAllowlist(t *testing.T) {
	if _, err := NewTLSIdentity(TLSIdentityConfig{}); err == nil {
		t.Fatal("mtls without an allowlist must be refused")
	}
	if _, err := NewTLSIdentity(TLSIdentityConfig{AllowedSubjects: []string{""}}); err == nil {
		t.Fatal("an empty allowlist entry must be refused")
	}
}

func TestAnonymousCallerIDIsNotEmpty(t *testing.T) {
	var s *Subject
	if s.CallerID() != anonymousCaller {
		t.Errorf("an absent subject must still name a caller, got %q", s.CallerID())
	}
}

func TestRequireKind(t *testing.T) {
	user := &Subject{Kind: SubjectUser}
	workload := &Subject{Kind: SubjectWorkload}

	if err := requireKind(user, nil); err != nil {
		t.Errorf("an empty kind list must accept any subject, got %v", err)
	}
	if err := requireKind(workload, []SubjectKind{SubjectWorkload}); err != nil {
		t.Errorf("a workload must pass a workload requirement, got %v", err)
	}
	if err := requireKind(user, []SubjectKind{SubjectWorkload}); !errors.Is(err, ErrWrongSubjectKind) {
		t.Errorf("a user must not pass a workload requirement, got %v", err)
	}
	if err := requireKind(workload, []SubjectKind{SubjectUser}); !errors.Is(err, ErrWrongSubjectKind) {
		t.Errorf("a workload must not pass a user requirement, got %v", err)
	}
}
