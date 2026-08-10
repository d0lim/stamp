package identity

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The identity tests never reach the network. A mock IdP serves a JWKS over
// httptest and mints tokens with stdlib crypto, which is also what lets a
// test mint the tokens a real IdP would refuse to produce — `none`, HMAC, a
// key ID that was never published.

// testKeyPool is generated once; RSA key generation dominates the runtime of
// this package otherwise.
var testKeyPool = sync.OnceValue(func() []*rsa.PrivateKey {
	keys := make([]*rsa.PrivateKey, 8)
	for i := range keys {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		keys[i] = k
	}
	return keys
})

var testKeyCursor atomic.Int64

func nextTestKey() *rsa.PrivateKey {
	pool := testKeyPool()
	i := testKeyCursor.Add(1) - 1
	return pool[i%int64(len(pool))]
}

// testClock is a hand-wound clock. Several of these tests turn on time
// passing — a negative cache entry ageing out, a refetch budget refilling —
// and a real clock would make them either slow or flaky.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock(at time.Time) *testClock { return &testClock{now: at} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type mockIdP struct {
	server  *httptest.Server
	fetches atomic.Int64

	mu   sync.Mutex
	keys map[string]*rsa.PrivateKey
}

// newMockIdP starts an IdP publishing one signing key per named key ID.
func newMockIdP(t *testing.T, kids ...string) *mockIdP {
	t.Helper()
	m := &mockIdP{keys: make(map[string]*rsa.PrivateKey, len(kids))}
	for _, kid := range kids {
		m.keys[kid] = nextTestKey()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		m.fetches.Add(1)
		m.mu.Lock()
		defer m.mu.Unlock()

		type jwk struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		}
		doc := struct {
			Keys []jwk `json:"keys"`
		}{}
		for kid, key := range m.keys {
			doc.Keys = append(doc.Keys, jwk{
				Kty: "RSA",
				Kid: kid,
				Alg: "RS256",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockIdP) issuer() string  { return m.server.URL }
func (m *mockIdP) jwksURL() string { return m.server.URL + "/jwks" }
func (m *mockIdP) jwksFetches() int {
	return int(m.fetches.Load())
}

// rotate publishes an additional key.
func (m *mockIdP) rotate(kid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[kid] = nextTestKey()
}

func (m *mockIdP) key(kid string) *rsa.PrivateKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[kid]
}

// claimSet is the smallest set of claims the verifier cares about, so that a
// test can drop one of them on purpose.
type claimSet map[string]any

func (m *mockIdP) claims(now time.Time) claimSet {
	return claimSet{
		"iss": m.issuer(),
		"sub": "user-1",
		"aud": []string{testAudience},
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

const testAudience = "stamp"

// signRS256 mints a token signed by the key published under kid. headerKid is
// what goes in the header, which is not always the same thing: an unknown-key
// test signs with a real key and advertises one that was never published.
func (m *mockIdP) signRS256(t *testing.T, signingKID, headerKID string, claims claimSet) string {
	t.Helper()
	key := m.key(signingKID)
	if key == nil {
		t.Fatalf("mock idp has no key %q", signingKID)
	}
	return signRS256With(t, key, headerKID, claims)
}

func signRS256With(t *testing.T, key *rsa.PrivateKey, kid string, claims claimSet) string {
	t.Helper()
	input := signingInput(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}, claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// signHS256 mints a token signed with a shared secret. No configuration can
// make the verifier accept one.
func signHS256(t *testing.T, secret string, kid string, claims claimSet) string {
	t.Helper()
	input := signingInput(t, map[string]any{"alg": "HS256", "typ": "JWT", "kid": kid}, claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// signNone mints an unsigned token.
func signNone(t *testing.T, claims claimSet) string {
	t.Helper()
	return signingInput(t, map[string]any{"alg": "none", "typ": "JWT"}, claims) + "."
}

func signingInput(t *testing.T, header map[string]any, claims claimSet) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshalling header: %v", err)
	}
	c, err := json.Marshal(map[string]any(claims))
	if err != nil {
		t.Fatalf("marshalling claims: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
}
