package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func baseConfig(now time.Time, idps ...*mockIdP) Config {
	cfg := Config{
		Audience:               testAudience,
		Algorithms:             []string{"RS256"},
		AllowInsecureTransport: true,
		Now:                    func() time.Time { return now },
	}
	for _, idp := range idps {
		cfg.Issuers = append(cfg.Issuers, IssuerConfig{Issuer: idp.issuer(), JWKSURL: idp.jwksURL()})
	}
	return cfg
}

func mustVerifier(t *testing.T, cfg Config) *Verifier {
	t.Helper()
	v, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("building verifier: %v", err)
	}
	return v
}

func TestValidTokenIsAccepted(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	v := mustVerifier(t, baseConfig(now, idp))

	sub, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", idp.claims(now)))
	if err != nil {
		t.Fatalf("a validly signed token must verify, got %v", err)
	}
	if sub.Kind != SubjectUser {
		t.Errorf("kind: want %q, got %q", SubjectUser, sub.Kind)
	}
	if sub.Method != MethodBearerJWT {
		t.Errorf("method: want %q, got %q", MethodBearerJWT, sub.Method)
	}
	if sub.ID != "user-1" {
		t.Errorf("id: want user-1, got %q", sub.ID)
	}
	if sub.Issuer != idp.issuer() {
		t.Errorf("issuer: want %q, got %q", idp.issuer(), sub.Issuer)
	}
	if !sub.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Errorf("expiry: want %v, got %v", now.Add(time.Hour), sub.ExpiresAt)
	}
	if want := fmt.Sprintf("user:%s#user-1", idp.issuer()); sub.CallerID() != want {
		t.Errorf("caller id: want %q, got %q", want, sub.CallerID())
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	v := mustVerifier(t, baseConfig(now, idp))

	claims := idp.claims(now)
	claims["exp"] = now.Add(-time.Minute).Unix()

	_, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", claims))
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("an expired token must be rejected as expired, got %v", err)
	}
	if got := ReasonFor(err); got != ReasonTokenExpired {
		t.Errorf("audit reason: want %q, got %q", ReasonTokenExpired, got)
	}
}

func TestTokenFromUnconfiguredIssuerIsRejectedWithoutAFetch(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	configured := newMockIdP(t, "k1")
	stranger := newMockIdP(t, "k1")
	v := mustVerifier(t, baseConfig(now, configured))

	// A perfectly valid token — correct audience, live expiry, real signature
	// from its own issuer's key. The only thing wrong with it is whose it is.
	_, err := v.Verify(context.Background(), stranger.signRS256(t, "k1", "k1", stranger.claims(now)))
	if !errors.Is(err, ErrIssuerNotAllowed) {
		t.Fatalf("a token from an unconfigured issuer must be rejected, got %v", err)
	}
	if n := stranger.jwksFetches(); n != 0 {
		t.Errorf("an unconfigured issuer must not be contacted, got %d fetches", n)
	}
	if n := configured.jwksFetches(); n != 0 {
		t.Errorf("issuer rejection must happen before any key fetch, got %d fetches", n)
	}
}

func TestIssuerClaimSignedByAnotherIssuersKeyIsRejected(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	first := newMockIdP(t, "k1")
	second := newMockIdP(t, "k1")
	v := mustVerifier(t, baseConfig(now, first, second))

	// Both issuers are configured, so selecting a verifier by the unverified
	// `iss` succeeds — and then the pinned key set has to disagree.
	claims := second.claims(now)
	claims["iss"] = first.issuer()

	_, err := v.Verify(context.Background(), second.signRS256(t, "k1", "k1", claims))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("a token claiming another issuer must fail signature verification, got %v", err)
	}
}

func TestTokenWithoutAudienceIsRejected(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	v := mustVerifier(t, baseConfig(now, idp))

	claims := idp.claims(now)
	delete(claims, "aud")

	_, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", claims))
	if !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("a token carrying no audience must be rejected, got %v", err)
	}
}

func TestTokenForAnotherAudienceIsRejected(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	v := mustVerifier(t, baseConfig(now, idp))

	claims := idp.claims(now)
	claims["aud"] = []string{"some-other-service"}

	_, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", claims))
	if !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("a token for another audience must be rejected, got %v", err)
	}
}

func TestSymmetricAlgorithmTokenIsRejected(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	v := mustVerifier(t, baseConfig(now, idp))

	_, err := v.Verify(context.Background(), signHS256(t, "shared-secret", "k1", idp.claims(now)))
	if !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("an HMAC-signed token must be rejected on the algorithm, got %v", err)
	}
	if n := idp.jwksFetches(); n != 0 {
		t.Errorf("algorithm rejection must happen before any key fetch, got %d fetches", n)
	}
}

func TestNoneAlgorithmTokenIsRejected(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	v := mustVerifier(t, baseConfig(now, idp))

	_, err := v.Verify(context.Background(), signNone(t, idp.claims(now)))
	if !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("an unsigned token must be rejected, got %v", err)
	}
	if n := idp.jwksFetches(); n != 0 {
		t.Errorf("an unsigned token must not cause a key fetch, got %d fetches", n)
	}
}

func TestSymmetricAlgorithmCannotBeConfigured(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")

	for _, alg := range []string{"HS256", "HS384", "HS512", "none", ""} {
		cfg := baseConfig(now, idp)
		cfg.Algorithms = []string{alg}
		if _, err := New(context.Background(), cfg); err == nil {
			t.Errorf("configuring %q as a signing algorithm must fail", alg)
		}
	}
}

func TestPlaintextJWKSURLNeedsAnExplicitOptIn(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")

	cfg := baseConfig(now, idp)
	cfg.AllowInsecureTransport = false
	if _, err := New(context.Background(), cfg); err == nil {
		t.Fatal("a plaintext issuer must be refused unless the operator opts in")
	}

	// An https issuer whose key set is served over plaintext is the more
	// dangerous shape of the same mistake, because the issuer url looks fine.
	cfg = baseConfig(now, idp)
	cfg.AllowInsecureTransport = false
	cfg.Issuers[0].Issuer = "https://idp.example.com"
	if _, err := New(context.Background(), cfg); err == nil {
		t.Fatal("a plaintext jwks url must be refused even when the issuer is https")
	}
}

func TestConfigurationRequiresIssuerAudienceAndAlgorithms(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")

	cases := map[string]func(*Config){
		"no issuers":    func(c *Config) { c.Issuers = nil },
		"no audience":   func(c *Config) { c.Audience = "" },
		"no algorithms": func(c *Config) { c.Algorithms = nil },
		"no jwks url":   func(c *Config) { c.Issuers[0].JWKSURL = "" },
		"duplicate issuer": func(c *Config) {
			c.Issuers = append(c.Issuers, c.Issuers[0])
		},
	}
	for name, mutate := range cases {
		cfg := baseConfig(now, idp)
		mutate(&cfg)
		if _, err := New(context.Background(), cfg); err == nil {
			t.Errorf("%s: configuration must be rejected", name)
		}
	}
}

func TestUnknownKeyFloodCostsBoundedRefetches(t *testing.T) {
	const (
		requests = 1000
		burst    = 5
	)
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	cfg := baseConfig(now, idp)
	cfg.JWKSRefetchBurst = burst
	v := mustVerifier(t, cfg)

	for i := range requests {
		// Signed by the real key, but advertising a key ID that was never
		// published — the cheapest way to ask an unprotected relying party to
		// hammer its IdP.
		kid := fmt.Sprintf("ghost-%d", i)
		if _, err := v.Verify(context.Background(), idp.signRS256(t, "k1", kid, idp.claims(now))); err == nil {
			t.Fatalf("request %d: a token with an unpublished key id must be rejected", i)
		}
	}

	fetches := idp.jwksFetches()
	if fetches > burst {
		t.Errorf("%d unknown-key requests caused %d jwks fetches, budget was %d", requests, fetches, burst)
	}
	if fetches == 0 {
		t.Error("the first unknown key must be allowed to refresh the key set")
	}
	if got := v.JWKSFetches(idp.issuer()); got != fetches {
		t.Errorf("verifier counted %d fetches, the idp saw %d", got, fetches)
	}

	// The flood must not have cost legitimate callers their access: a token
	// signed by a published key needs no fetch at all.
	if _, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", idp.claims(now))); err != nil {
		t.Fatalf("a valid token must still verify after the flood, got %v", err)
	}
}

func TestRepeatedUnknownKeyIsNegativelyCached(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	cfg := baseConfig(now, idp)
	cfg.JWKSRefetchBurst = 100
	v := mustVerifier(t, cfg)

	for i := range 1000 {
		_, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "ghost", idp.claims(now)))
		if i > 0 && !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("request %d: a repeat of a known-unknown key must be answered from the negative cache, got %v", i, err)
		}
	}
	if n := idp.jwksFetches(); n != 1 {
		t.Errorf("1000 repeats of one unknown key must cost exactly one fetch, got %d", n)
	}
}

func TestKeyRotationRecoversOnceTheNegativeCacheExpires(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	clock := newTestClock(now)
	idp := newMockIdP(t, "k1")
	cfg := baseConfig(now, idp)
	cfg.JWKSRefetchBurst = 3
	cfg.Now = clock.Now
	v := mustVerifier(t, cfg)

	// Ask for a key before it exists, so it lands in the negative cache.
	if _, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k2", idp.claims(now))); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("an unpublished key id must be rejected, got %v", err)
	}
	idp.rotate("k2")

	// While the entry is fresh the rotation is invisible. That is the price
	// of the negative cache and it is bounded by its TTL, not by anything an
	// attacker controls.
	if _, err := v.Verify(context.Background(), idp.signRS256(t, "k2", "k2", idp.claims(now))); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("a negatively cached key must be answered without a fetch, got %v", err)
	}

	clock.advance(DefaultUnknownKeyTTL + time.Second)
	sub, err := v.Verify(context.Background(), idp.signRS256(t, "k2", "k2", idp.claims(now)))
	if err != nil {
		t.Fatalf("a token signed by a rotated key must verify once the entry ages out, got %v", err)
	}
	if sub.ID != "user-1" {
		t.Errorf("id: want user-1, got %q", sub.ID)
	}
}

func TestRefetchBudgetRefillsOverTime(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	clock := newTestClock(now)
	idp := newMockIdP(t, "k1")
	cfg := baseConfig(now, idp)
	cfg.JWKSRefetchBurst = 1
	cfg.JWKSRefetchInterval = time.Minute
	cfg.Now = clock.Now
	v := mustVerifier(t, cfg)

	if _, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "ghost-1", idp.claims(now))); err == nil {
		t.Fatal("an unpublished key id must be rejected")
	}
	if _, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "ghost-2", idp.claims(now))); !errors.Is(err, ErrRefetchThrottled) {
		t.Fatalf("the second unknown key must exhaust the budget, got %v", err)
	}
	if n := idp.jwksFetches(); n != 1 {
		t.Fatalf("want 1 fetch while the budget is spent, got %d", n)
	}

	clock.advance(2 * time.Minute)
	if _, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "ghost-3", idp.claims(now))); errors.Is(err, ErrRefetchThrottled) {
		t.Error("the budget must refill over time, otherwise one flood disables key rotation for good")
	}
	if n := idp.jwksFetches(); n != 2 {
		t.Errorf("want 2 fetches after the budget refilled, got %d", n)
	}
}

func TestForgeriesOnAPublishedKeyCannotDriveUnboundedRefetches(t *testing.T) {
	const burst = 5
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	cfg := baseConfig(now, idp)
	cfg.JWKSRefetchBurst = burst
	v := mustVerifier(t, cfg)

	if _, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", idp.claims(now))); err != nil {
		t.Fatalf("warm-up token must verify, got %v", err)
	}

	// A key ID that *is* published costs no admission check, because a token
	// bearing it should verify from the cached key set. A forged signature on
	// it makes the library refetch anyway — so if the budget were only
	// charged on the unknown-key path, this would be an unmetered route to
	// the IdP that a valid-looking token walks straight down.
	forger := nextTestKey()
	for i := range 100 {
		if _, err := v.Verify(context.Background(), signRS256With(t, forger, "k1", idp.claims(now))); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("request %d: a forged signature must be rejected, got %v", i, err)
		}
	}
	if n := idp.jwksFetches(); n > burst {
		t.Errorf("100 forgeries on a published key caused %d jwks fetches, budget was %d", n, burst)
	}
}

func TestTamperedTokenDoesNotPoisonAPublishedKey(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	cfg := baseConfig(now, idp)
	cfg.JWKSRefetchBurst = 3
	v := mustVerifier(t, cfg)

	if _, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", idp.claims(now))); err != nil {
		t.Fatalf("warm-up token must verify, got %v", err)
	}

	// A token that names a published key but was signed by something else.
	// Caching "k1 is bad" here would lock out every real token signed with k1.
	forged := signRS256With(t, nextTestKey(), "k1", idp.claims(now))
	if _, err := v.Verify(context.Background(), forged); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("a forged signature must be rejected, got %v", err)
	}
	if _, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", idp.claims(now))); err != nil {
		t.Fatalf("a real token must still verify after a forgery on the same key id, got %v", err)
	}
}

func TestWorkloadClientTokenBecomesAWorkloadSubject(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	cfg := baseConfig(now, idp)
	cfg.Issuers[0].WorkloadClients = []string{"stamp-pep"}
	v := mustVerifier(t, cfg)

	claims := idp.claims(now)
	claims["sub"] = "service-account-stamp-pep"
	claims["azp"] = "stamp-pep"

	sub, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", claims))
	if err != nil {
		t.Fatalf("a workload token must verify, got %v", err)
	}
	if sub.Kind != SubjectWorkload {
		t.Fatalf("kind: want %q, got %q", SubjectWorkload, sub.Kind)
	}
	if sub.ClientID != "stamp-pep" {
		t.Errorf("client id: want stamp-pep, got %q", sub.ClientID)
	}
	if !strings.HasPrefix(sub.CallerID(), "workload:") {
		t.Errorf("caller id must name the kind, got %q", sub.CallerID())
	}

	// The same issuer's ordinary tokens stay users, so a PEP surface and an
	// approval surface cannot be reached with the same credential.
	human, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", idp.claims(now)))
	if err != nil {
		t.Fatalf("a user token must verify, got %v", err)
	}
	if human.Kind != SubjectUser {
		t.Errorf("kind: want %q, got %q", SubjectUser, human.Kind)
	}
}

func TestSilentlyDowngradedACRIsRejected(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	cfg := baseConfig(now, idp)
	cfg.AllowedACRValues = []string{"gold"}
	v := mustVerifier(t, cfg)

	// U0 observed an IdP answering an `acr_values=gold` request with acr=1
	// and no error at all, even for an essential claim. The returned value is
	// the only thing that can be checked.
	downgraded := idp.claims(now)
	downgraded["acr"] = "1"
	if _, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", downgraded)); !errors.Is(err, ErrACRNotAllowed) {
		t.Fatalf("a downgraded acr must be rejected, got %v", err)
	}

	satisfied := idp.claims(now)
	satisfied["acr"] = "gold"
	satisfied["auth_time"] = now.Add(-time.Minute).Unix()
	sub, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", satisfied))
	if err != nil {
		t.Fatalf("an allowed acr must verify, got %v", err)
	}
	if sub.ACR != "gold" {
		t.Errorf("acr: want gold, got %q", sub.ACR)
	}
	if !sub.AuthTime.Equal(now.Add(-time.Minute).UTC()) {
		t.Errorf("auth_time: want %v, got %v", now.Add(-time.Minute).UTC(), sub.AuthTime)
	}
	// U0 also found amr empty in default IdP configurations, so nothing here
	// may require it.
	if len(sub.AMR) != 0 {
		t.Errorf("amr: want empty, got %v", sub.AMR)
	}
}

func TestMalformedTokensAreRejected(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	v := mustVerifier(t, baseConfig(now, idp))

	valid := idp.signRS256(t, "k1", "k1", idp.claims(now))
	cases := map[string]string{
		"empty":         "",
		"not a jws":     "not-a-token",
		"two segments":  "aaa.bbb",
		"five segments": "aaa.bbb.ccc.ddd.eee",
		"empty header":  ".bbb.ccc",
		"bad base64":    "!!!.bbb.ccc",
		"oversized":     valid + strings.Repeat("a", DefaultMaxTokenBytes),
		"no signature":  strings.Join(strings.Split(valid, ".")[:2], ".") + ".",
		"no sub in token": idp.signRS256(t, "k1", "k1", claimSet{
			"iss": idp.issuer(),
			"aud": []string{testAudience},
			"exp": now.Add(time.Hour).Unix(),
		}),
	}
	for name, token := range cases {
		if _, err := v.Verify(context.Background(), token); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestClaimsArePassedThrough(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	idp := newMockIdP(t, "k1")
	v := mustVerifier(t, baseConfig(now, idp))

	claims := idp.claims(now)
	claims["groups"] = []string{"sre", "oncall"}

	sub, err := v.Verify(context.Background(), idp.signRS256(t, "k1", "k1", claims))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var got struct {
		Groups []string `json:"groups"`
	}
	if err := sub.Claims(&got); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if len(got.Groups) != 2 || got.Groups[0] != "sre" {
		t.Errorf("groups: want [sre oncall], got %v", got.Groups)
	}
}
