// Package identity is STAMP's relying-party boundary. Every caller that
// reaches a PEP or console surface arrives holding a credential minted
// somewhere else, and this package is the only place that decides whether
// that credential is worth anything.
//
// STAMP is an OIDC relying party and nothing more (D7): it stores no
// credentials, no roles and no sessions. What it does store is the *shape* of
// the trust boundary, and that shape comes from operator configuration rather
// than from policy data (D21) — a policy author must never be able to widen
// who may call the API.
//
// Four things are pinned by configuration and cannot be moved by a token:
//
//   - the issuer set. A token whose `iss` is not configured is rejected
//     before any network call, so an unknown issuer cannot even cause a JWKS
//     fetch.
//   - the audience. A token that does not name our audience is rejected, and
//     so is a token carrying no `aud` at all.
//   - the signing algorithms, restricted to asymmetric ones. `none` and the
//     HMAC family are refused at configuration load, not merely at verify
//     time, so a deployment cannot be talked into key-confusion.
//   - the transport. JWKS over plaintext HTTP means anyone on the path
//     chooses our signing keys, so it takes an explicit operator opt-in.
//
// The unknown-`kid` path gets its own protection. go-oidc's RemoteKeySet
// refetches the JWKS whenever it meets a key ID it has not cached, which is
// the behaviour the spec recommends and also an unauthenticated amplifier: a
// thousand tokens carrying a thousand invented `kid` values become a thousand
// requests to the IdP. A refetch budget and a negative cache sit in front of
// it, so a flood costs a bounded number of fetches.
//
// User tokens and workload credentials are verified by the same code and
// separated afterwards into distinct [SubjectKind] values, so the HTTP layer
// can demand one or the other without a second authentication stack.
package identity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Token verification failures. Callers match on these with errors.Is rather
// than on message text; [ReasonFor] turns them into stable audit reasons and
// the middleware turns them into status codes.
var (
	// ErrMalformedToken means the credential is not a well-formed JWS.
	ErrMalformedToken = errors.New("identity: malformed token")
	// ErrAlgorithmNotAllowed means the token names a signing algorithm
	// outside the configured asymmetric allowlist, including `none`.
	ErrAlgorithmNotAllowed = errors.New("identity: signing algorithm not allowed")
	// ErrIssuerNotAllowed means the token's issuer is not in the configured
	// issuer set.
	ErrIssuerNotAllowed = errors.New("identity: issuer not allowed")
	// ErrAudienceMismatch means the token does not name the configured
	// audience, or carries no audience at all.
	ErrAudienceMismatch = errors.New("identity: audience mismatch")
	// ErrTokenExpired means the token's expiry is in the past.
	ErrTokenExpired = errors.New("identity: token expired")
	// ErrSignatureInvalid means the signature did not verify against any key
	// in the issuer's key set.
	ErrSignatureInvalid = errors.New("identity: signature verification failed")
	// ErrUnknownKey means the token's key ID is not in the issuer's key set
	// and a recent fetch already established that.
	ErrUnknownKey = errors.New("identity: unknown signing key")
	// ErrRefetchThrottled means the key ID is unknown and the JWKS refetch
	// budget for this issuer is spent. It is a transient server condition,
	// not a statement about the token.
	ErrRefetchThrottled = errors.New("identity: jwks refetch throttled")
	// ErrACRNotAllowed means the token's authentication context class is not
	// in the operator's allowlist.
	ErrACRNotAllowed = errors.New("identity: authentication context class not allowed")
)

// asymmetricAlgs is the closed set of algorithms a STAMP deployment may pin.
// It is deliberately not "everything go-jose can parse" — the HMAC family and
// `none` are absent because a verifier that accepts them can be steered into
// treating a public key, or nothing at all, as a signing secret.
var asymmetricAlgs = map[string]bool{
	oidc.RS256: true,
	oidc.RS384: true,
	oidc.RS512: true,
	oidc.ES256: true,
	oidc.ES384: true,
	oidc.ES512: true,
	oidc.PS256: true,
	oidc.PS384: true,
	oidc.PS512: true,
	oidc.EdDSA: true,
}

// Defaults for the [Config] knobs an operator does not set.
const (
	// DefaultJWKSRefetchBurst is how many back-to-back refetches an
	// unknown-key burst may trigger before the budget bites.
	DefaultJWKSRefetchBurst = 5
	// DefaultJWKSRefetchInterval is the steady-state spacing between
	// refetches once the burst is spent.
	DefaultJWKSRefetchInterval = time.Minute
	// DefaultUnknownKeyTTL is how long a key ID that a fresh key set did not
	// contain stays negatively cached.
	DefaultUnknownKeyTTL = 30 * time.Second
	// DefaultUnknownKeyCacheSize bounds the negative cache so that a flood of
	// invented key IDs cannot grow it without limit.
	DefaultUnknownKeyCacheSize = 1024
	// DefaultMaxTokenBytes bounds the credential we are willing to parse.
	DefaultMaxTokenBytes = 8 * 1024
	// DefaultMaxJWKSBytes bounds the key set body we are willing to read.
	DefaultMaxJWKSBytes = 1 << 20
	// DefaultHTTPTimeout bounds a JWKS fetch when no client is supplied.
	DefaultHTTPTimeout = 10 * time.Second
)

// IssuerConfig pins one trusted issuer.
//
// The JWKS URL is configured rather than discovered. Discovery would make
// process start depend on the IdP being reachable and would let a compromised
// discovery document move the key set, which is exactly the pin we are trying
// to hold.
type IssuerConfig struct {
	// Issuer is the exact `iss` value tokens must carry.
	Issuer string
	// JWKSURL is the key set endpoint for this issuer.
	JWKSURL string
	// WorkloadClients lists the client identifiers whose tokens are workload
	// credentials rather than end-user ones. A token whose client is listed
	// becomes a [SubjectWorkload]; every other token from this issuer is a
	// [SubjectUser]. The split is operator configuration because nothing in a
	// token reliably distinguishes a client-credentials grant from a user
	// login, and guessing it would let one surface's credential be replayed
	// at the other.
	WorkloadClients []string
}

// Config is the pinned trust boundary for token verification.
type Config struct {
	// Issuers is the trusted issuer set. At least one is required.
	Issuers []IssuerConfig
	// Audience is the audience every token must name. Required.
	Audience string
	// Algorithms is the allowlist of signing algorithms. Every entry must be
	// asymmetric; `none` and the HMAC family are rejected here rather than at
	// verify time. Required.
	Algorithms []string
	// AllowedACRValues, when non-empty, is the allowlist of authentication
	// context classes an end-user token may carry.
	//
	// U0 found that an IdP does not report an unsatisfied `acr` request as an
	// error — it silently returns a weaker one, even when the request was an
	// OIDC essential claim. Checking the returned value is therefore the only
	// defence there is, not a convenience.
	//
	// Workload tokens are exempt: a client-credentials grant has no human
	// authentication to classify.
	AllowedACRValues []string

	// JWKSRefetchBurst, JWKSRefetchInterval, UnknownKeyTTL and
	// UnknownKeyCacheSize shape the unknown-key protection. Zero means the
	// corresponding Default constant.
	JWKSRefetchBurst    int
	JWKSRefetchInterval time.Duration
	UnknownKeyTTL       time.Duration
	UnknownKeyCacheSize int

	// MaxTokenBytes and MaxJWKSBytes bound what we parse. Zero means the
	// corresponding Default constant.
	MaxTokenBytes int
	MaxJWKSBytes  int64

	// AllowInsecureTransport permits plaintext http issuer and JWKS URLs.
	// Without it they are refused at load: an attacker who can answer the
	// JWKS request picks the signing keys. Set it only for tests and
	// loopback development.
	AllowInsecureTransport bool

	// HTTPClient fetches key sets. Nil means a client with
	// DefaultHTTPTimeout.
	HTTPClient *http.Client

	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Verifier verifies bearer tokens against a pinned issuer set.
//
// It is safe for concurrent use and is meant to be built once per process:
// the key set caches and the refetch budgets live inside it, so a Verifier
// per request would defeat both.
type Verifier struct {
	audience    string
	allowedAlgs map[string]bool
	allowedACR  []string
	maxToken    int
	now         func() time.Time
	issuers     map[string]*issuerVerifier
}

type issuerVerifier struct {
	cfg      IssuerConfig
	workload map[string]struct{}
	verifier *oidc.IDTokenVerifier
	guard    *keyGuard
}

// New builds a Verifier from a pinned configuration, rejecting any
// configuration that would weaken the boundary.
//
// The context configures the HTTP client used for key set fetches and is not
// used for cancellation; go-oidc treats it as a bag of values that outlives
// the call.
func New(ctx context.Context, cfg Config) (*Verifier, error) {
	if len(cfg.Issuers) == 0 {
		return nil, errors.New("identity: at least one issuer must be configured")
	}
	if cfg.Audience == "" {
		return nil, errors.New("identity: an audience must be configured")
	}
	if len(cfg.Algorithms) == 0 {
		return nil, errors.New("identity: at least one signing algorithm must be configured")
	}

	algs := make(map[string]bool, len(cfg.Algorithms))
	algList := make([]string, 0, len(cfg.Algorithms))
	for _, alg := range cfg.Algorithms {
		if !asymmetricAlgs[alg] {
			return nil, fmt.Errorf("identity: signing algorithm %q is not an allowed asymmetric algorithm", alg)
		}
		if algs[alg] {
			continue
		}
		algs[alg] = true
		algList = append(algList, alg)
	}

	v := &Verifier{
		audience:    cfg.Audience,
		allowedAlgs: algs,
		allowedACR:  slices.Clone(cfg.AllowedACRValues),
		maxToken:    orDefaultInt(cfg.MaxTokenBytes, DefaultMaxTokenBytes),
		now:         cfg.Now,
		issuers:     make(map[string]*issuerVerifier, len(cfg.Issuers)),
	}
	if v.now == nil {
		v.now = time.Now
	}

	for _, ic := range cfg.Issuers {
		if ic.Issuer == "" {
			return nil, errors.New("identity: an issuer entry has an empty issuer")
		}
		if _, dup := v.issuers[ic.Issuer]; dup {
			return nil, fmt.Errorf("identity: issuer %q is configured twice", ic.Issuer)
		}
		if ic.JWKSURL == "" {
			return nil, fmt.Errorf("identity: issuer %q has no jwks url", ic.Issuer)
		}
		if err := checkTransport(ic.Issuer, cfg.AllowInsecureTransport); err != nil {
			return nil, err
		}
		if err := checkTransport(ic.JWKSURL, cfg.AllowInsecureTransport); err != nil {
			return nil, err
		}

		guard := newKeyGuard(cfg, v.now)
		keyCtx := oidc.ClientContext(ctx, guardedClient(cfg, guard))

		iv := &issuerVerifier{
			cfg:      ic,
			workload: make(map[string]struct{}, len(ic.WorkloadClients)),
			guard:    guard,
			verifier: oidc.NewVerifier(ic.Issuer, &guardedKeySet{
				remote: oidc.NewRemoteKeySet(keyCtx, ic.JWKSURL),
				guard:  guard,
			}, &oidc.Config{
				SupportedSigningAlgs: algList,
				// The audience is checked by Verify against the pinned value
				// below, not here, so that the failure carries
				// ErrAudienceMismatch instead of an opaque library string.
				// Skipping it here does not skip it.
				SkipClientIDCheck: true,
				Now:               v.now,
			}),
		}
		for _, c := range ic.WorkloadClients {
			iv.workload[c] = struct{}{}
		}
		v.issuers[ic.Issuer] = iv
	}
	return v, nil
}

func checkTransport(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("identity: %q is not a url: %w", raw, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if allowInsecure {
		return nil
	}
	return fmt.Errorf("identity: %q must use https, or the deployment must set AllowInsecureTransport", raw)
}

func orDefaultInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func orDefaultDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// Verify checks a raw bearer token against the pinned boundary and returns
// the caller it identifies.
//
// The order of the checks is part of the defence. Shape, algorithm and issuer
// are settled from the unverified token before anything touches the network,
// so a token from an unconfigured issuer — or one signed with HMAC — cannot
// spend a JWKS fetch. Reading the unverified `iss` only selects which pinned
// verifier runs; that verifier then re-checks `iss` against its own pin, so a
// lie in the unverified claim cannot pick a different key set than the one
// the issuer is entitled to.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Subject, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: empty token", ErrMalformedToken)
	}
	if len(raw) > v.maxToken {
		return nil, fmt.Errorf("%w: token is longer than %d bytes", ErrMalformedToken, v.maxToken)
	}

	hdrSeg, payloadSeg, sigSeg, err := splitJWS(raw)
	if err != nil {
		return nil, err
	}
	if sigSeg == "" {
		return nil, fmt.Errorf("%w: token carries no signature", ErrAlgorithmNotAllowed)
	}

	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(hdrSeg, &hdr); err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrMalformedToken, err)
	}
	if !v.allowedAlgs[hdr.Alg] {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithmNotAllowed, hdr.Alg)
	}

	var unverified struct {
		Issuer string `json:"iss"`
	}
	if err := decodeSegment(payloadSeg, &unverified); err != nil {
		return nil, fmt.Errorf("%w: claims: %w", ErrMalformedToken, err)
	}
	iv, ok := v.issuers[unverified.Issuer]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrIssuerNotAllowed, unverified.Issuer)
	}

	if err := iv.guard.admit(hdr.Kid); err != nil {
		return nil, err
	}

	state := &verifyState{kid: hdr.Kid}
	tok, err := iv.verifier.Verify(context.WithValue(ctx, verifyStateKey{}, state), raw)
	if err != nil {
		return nil, classifyVerifyError(err, state)
	}

	if !slices.Contains(tok.Audience, v.audience) {
		return nil, fmt.Errorf("%w: token audience %v does not include %q", ErrAudienceMismatch, tok.Audience, v.audience)
	}
	if tok.Subject == "" {
		return nil, fmt.Errorf("%w: token has no subject", ErrMalformedToken)
	}

	var claims struct {
		AuthTime *int64   `json:"auth_time"`
		ACR      string   `json:"acr"`
		AMR      []string `json:"amr"`
		AZP      string   `json:"azp"`
		ClientID string   `json:"client_id"`
	}
	var rawClaims json.RawMessage
	if err := tok.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("%w: claims: %w", ErrMalformedToken, err)
	}
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %w", ErrMalformedToken, err)
	}

	clientID := firstNonEmpty(claims.AZP, claims.ClientID, tok.Subject)
	kind := SubjectUser
	if _, isWorkload := iv.workload[clientID]; isWorkload {
		kind = SubjectWorkload
	}

	if kind == SubjectUser && len(v.allowedACR) > 0 && !slices.Contains(v.allowedACR, claims.ACR) {
		return nil, fmt.Errorf("%w: %q", ErrACRNotAllowed, claims.ACR)
	}

	sub := &Subject{
		Kind:      kind,
		Method:    MethodBearerJWT,
		Issuer:    tok.Issuer,
		ID:        tok.Subject,
		ClientID:  clientID,
		Audience:  slices.Clone(tok.Audience),
		IssuedAt:  tok.IssuedAt,
		ExpiresAt: tok.Expiry,
		ACR:       claims.ACR,
		AMR:       slices.Clone(claims.AMR),
		claims:    rawClaims,
	}
	if claims.AuthTime != nil {
		sub.AuthTime = time.Unix(*claims.AuthTime, 0).UTC()
	}
	return sub, nil
}

// JWKSFetches reports how many key set fetches this verifier has made for the
// named issuer. It exists so that the refetch budget can be asserted on and
// exported as a metric rather than merely believed.
func (v *Verifier) JWKSFetches(issuer string) int {
	iv, ok := v.issuers[issuer]
	if !ok {
		return 0
	}
	return iv.guard.fetches()
}

func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if s != "" {
			return s
		}
	}
	return ""
}

func splitJWS(raw string) (header, payload, signature string, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("%w: expected 3 dot-separated segments, got %d", ErrMalformedToken, len(parts))
	}
	if parts[0] == "" || parts[1] == "" {
		return "", "", "", fmt.Errorf("%w: token has an empty header or payload", ErrMalformedToken)
	}
	return parts[0], parts[1], parts[2], nil
}

func decodeSegment(seg string, into any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return fmt.Errorf("segment is not base64url: %w", err)
	}
	return json.Unmarshal(b, into)
}

// verifyState carries the key ID into the key set and the signature outcome
// back out. go-oidc wraps a signature failure with %v rather than %w, so the
// cause cannot be recovered with errors.Is; recording the outcome as it
// happens is how Verify tells "the signature did not verify" apart from "the
// signature verified and a later claim check failed".
type verifyState struct {
	kid      string
	verified bool
}

type verifyStateKey struct{}

func classifyVerifyError(err error, state *verifyState) error {
	if !state.verified {
		return fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}
	var expired *oidc.TokenExpiredError
	if errors.As(err, &expired) {
		return fmt.Errorf("%w: %w", ErrTokenExpired, err)
	}
	return fmt.Errorf("%w: %w", ErrMalformedToken, err)
}

// guardedKeySet wraps go-oidc's RemoteKeySet so that the outcome of each
// signature check is recorded. Admission — the negative cache and the refetch
// budget — happens in Verify, before the library is entered at all, so its
// errors reach the caller intact.
type guardedKeySet struct {
	remote *oidc.RemoteKeySet
	guard  *keyGuard
}

func (g *guardedKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	state, _ := ctx.Value(verifyStateKey{}).(*verifyState)
	payload, err := g.remote.VerifySignature(ctx, jwt)
	if err != nil {
		if state != nil {
			g.guard.observeFailure(state.kid)
		}
		return nil, err
	}
	if state != nil {
		state.verified = true
	}
	return payload, nil
}

// keyGuard bounds what an unknown key ID can cost.
//
// It knows which key IDs the issuer actually serves because the JWKS response
// passes through [jwksTransport] on its way into the library. That matters:
// with only "did the signature verify" to go on, a tampered token bearing a
// legitimate key ID would poison the negative cache for that key and lock out
// the real tokens signed with it. Caching "the key set did not contain this
// ID" instead of "this ID failed" removes that.
type keyGuard struct {
	mu       sync.Mutex
	served   map[string]struct{}
	negative map[string]time.Time
	negTTL   time.Duration
	negMax   int

	tokens float64
	burst  float64
	perSec float64
	last   time.Time

	fetchCount int

	now func() time.Time
}

func newKeyGuard(cfg Config, now func() time.Time) *keyGuard {
	burst := orDefaultInt(cfg.JWKSRefetchBurst, DefaultJWKSRefetchBurst)
	interval := orDefaultDuration(cfg.JWKSRefetchInterval, DefaultJWKSRefetchInterval)
	return &keyGuard{
		served:   make(map[string]struct{}),
		negative: make(map[string]time.Time),
		negTTL:   orDefaultDuration(cfg.UnknownKeyTTL, DefaultUnknownKeyTTL),
		negMax:   orDefaultInt(cfg.UnknownKeyCacheSize, DefaultUnknownKeyCacheSize),
		tokens:   float64(burst),
		burst:    float64(burst),
		perSec:   1 / interval.Seconds(),
		now:      now,
	}
}

// admit decides whether a token bearing kid may reach the key set.
//
// A key ID the issuer is known to serve costs nothing: the library answers
// from its cache. Anything else either has a fresh answer in the negative
// cache — rejected without a fetch — or needs the refetch budget to have
// something left in it.
//
// The budget is only inspected here, never spent. Spending happens in
// [jwksTransport], because that is the one place a fetch actually occurs: a
// tampered token carrying a *published* key ID also makes the library
// refetch, and a budget charged only on this path would leave that route
// unmetered. Checking here as well is what lets the common case fail with
// ErrRefetchThrottled instead of an opaque signature error.
func (g *keyGuard) admit(kid string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.served[kid]; ok {
		return nil
	}
	now := g.now()
	if until, ok := g.negative[kid]; ok {
		if now.Before(until) {
			return fmt.Errorf("%w: %q", ErrUnknownKey, kid)
		}
		delete(g.negative, kid)
	}
	g.refillLocked(now)
	if g.tokens < 1 {
		return fmt.Errorf("%w: key %q is unknown and the refetch budget is spent", ErrRefetchThrottled, kid)
	}
	return nil
}

func (g *keyGuard) refillLocked(now time.Time) {
	if !g.last.IsZero() {
		g.tokens = min(g.tokens+now.Sub(g.last).Seconds()*g.perSec, g.burst)
	}
	g.last = now
}

// spend takes one refetch out of the budget, reporting false when it is
// empty.
func (g *keyGuard) spend() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refillLocked(g.now())
	if g.tokens < 1 {
		return false
	}
	g.tokens--
	g.fetchCount++
	return true
}

// observeFailure records that a verification attempt failed. Only a key ID
// the freshly fetched key set does not contain is cached as unknown; a
// signature that simply did not match a key we do serve says nothing about
// the key.
func (g *keyGuard) observeFailure(kid string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.served[kid]; ok {
		return
	}
	g.evictLocked()
	g.negative[kid] = g.now().Add(g.negTTL)
}

func (g *keyGuard) evictLocked() {
	if len(g.negative) < g.negMax {
		return
	}
	now := g.now()
	for k, until := range g.negative {
		if !now.Before(until) {
			delete(g.negative, k)
		}
	}
	for k := range g.negative {
		if len(g.negative) < g.negMax {
			break
		}
		delete(g.negative, k)
	}
}

// recordKeySet takes the key IDs from a fetched JWKS document. Anything the
// document lists stops being unknown, which is what lets a key rotation
// recover immediately instead of waiting out a negative cache entry.
func (g *keyGuard) recordKeySet(kids []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.served = make(map[string]struct{}, len(kids))
	for _, k := range kids {
		g.served[k] = struct{}{}
		delete(g.negative, k)
	}
}

func (g *keyGuard) fetches() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fetchCount
}

// jwksTransport is where the refetch budget is actually spent, where the key
// IDs an issuer serves are learned, and where the size of a key set document
// is bounded. Every JWKS fetch the library makes passes through here — there
// is no second route to the endpoint — so a bound placed here is a bound on
// the traffic STAMP can be made to aim at an IdP.
type jwksTransport struct {
	base  http.RoundTripper
	guard *keyGuard
	max   int64
}

func (t *jwksTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.guard.spend() {
		return nil, fmt.Errorf("identity: jwks refetch budget for %s is spent", req.URL.Host)
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK || resp.Body == nil {
		return resp, nil
	}

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, t.max+1))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("identity: reading jwks: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("identity: reading jwks: %w", closeErr)
	}
	if int64(len(body)) > t.max {
		return nil, fmt.Errorf("identity: jwks document is larger than %d bytes", t.max)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))

	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		// Let the library produce the decode error; we only lose the key ID
		// census for this fetch, and the fetch itself already cost a token.
		return resp, nil
	}
	kids := make([]string, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		kids = append(kids, k.Kid)
	}
	t.guard.recordKeySet(kids)
	return resp, nil
}

func guardedClient(cfg Config, guard *keyGuard) *http.Client {
	base := cfg.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	rt := base.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &http.Client{
		Transport: &jwksTransport{
			base:  rt,
			guard: guard,
			max:   int64(orDefaultInt(int(cfg.MaxJWKSBytes), DefaultMaxJWKSBytes)),
		},
		CheckRedirect: base.CheckRedirect,
		Jar:           base.Jar,
		Timeout:       base.Timeout,
	}
}
