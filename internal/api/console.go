package api

// console.go serves the console bundle and the one document that tells the
// bundle where its API is.
//
// Two things here are load-bearing rather than incidental.
//
// The API base URL is operator configuration, delivered by the server, and the
// console has no other way to learn it. R50 forbids reading it from a query
// string, a fragment or localStorage, because all three are writable by whoever
// can hand an approver a link — and a console that took its base URL from a
// link would send that approver's token wherever the link said. The base URL
// therefore arrives in a response body from the origin serving the bundle, and
// the CSP on every console response pins connect-src to that origin and the
// IdP, so code that got into the bundle by some other route still cannot reach
// a fourth destination. The allowlist the engine enforces on its own side is a
// request-side control and does not cover this direction; the CSP does.
//
// The bundle is served without a credential, and that is a distinct auth kind
// rather than a hole in the console surface's mount rule. See [AuthStatic].

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
)

// Paths the console serving role answers.
const (
	// ConsoleBasePath is the subtree the bundle is served from. It is a
	// subtree pattern, so a deep link the router owns resolves to index.html
	// rather than to a 404.
	ConsoleBasePath = "/console/"
	// ConsoleConfigPath is the operator configuration document. It is the one
	// URL the bundle may hardcode, because it is same-origin with the bundle
	// by construction — it is how the bundle finds out what is not.
	ConsoleConfigPath = "/console/config.json"
)

// ConsoleOIDC is the relying-party configuration the console needs to run an
// authorization code flow with PKCE in the browser.
//
// It is separate from the verification configuration in [identity] on purpose.
// Verification says which issuers this process trusts on the way in; this says
// which one the console sends a person to on the way out, and a deployment that
// accepts tokens from two issuers still logs its operators in through one.
type ConsoleOIDC struct {
	// Issuer is the issuer identifier the returned token must carry.
	Issuer string
	// AuthorizationEndpoint is where the browser is redirected to log in.
	AuthorizationEndpoint string
	// TokenEndpoint is where the console exchanges the code. It is a fetch, so
	// its origin has to be in connect-src.
	TokenEndpoint string
	// EndSessionEndpoint is the IdP's RP-initiated logout endpoint. Optional:
	// without it, logging out drops the in-memory session only.
	EndSessionEndpoint string
	// ClientID is the console's public client identifier.
	ClientID string
	// Scopes are requested at authorization. Empty selects openid, profile,
	// email.
	Scopes []string
	// RoleClaim names the token claim the console derives its navigation and
	// its default landing from. Empty selects "roles".
	RoleClaim string
}

// ConsoleConfig configures [NewConsole].
type ConsoleConfig struct {
	// Assets is the built bundle, rooted at the directory holding index.html.
	// Nil — or a filesystem with no index.html — is a build that was compiled
	// without running the console build, and every asset request says so.
	Assets fs.FS

	// APIBaseURL is where the console sends its API calls. Empty means the
	// same origin the bundle came from, which is what the single-container
	// install has. A non-empty value must be an absolute http(s) URL, and its
	// origin is what connect-src is widened to.
	APIBaseURL string

	// OIDC is the browser-side relying party configuration.
	OIDC ConsoleOIDC

	// AllowInsecureTransport permits http origins in APIBaseURL and in the
	// OIDC endpoints. It exists for loopback development and for tests.
	AllowInsecureTransport bool
}

// Console serves the console bundle, its configuration document, and the
// security headers that bound what the bundle may talk to.
type Console struct {
	assets fs.FS
	// hasIndex is resolved once at construction: a missing bundle is a build
	// time fact, and re-statting it per request would only hide that.
	hasIndex bool

	config []byte
	csp    string
}

// NewConsole builds the console serving provider.
func NewConsole(cfg ConsoleConfig) (*Console, error) {
	apiBase, apiOrigin, err := normalizeAPIBase(cfg.APIBaseURL, cfg.AllowInsecureTransport)
	if err != nil {
		return nil, err
	}

	connect := []string{"'self'"}
	if apiOrigin != "" {
		connect = append(connect, apiOrigin)
	}
	// Only the token endpoint widens connect-src: it is the one IdP URL the
	// console fetches. Authorization is a top level navigation, which no fetch
	// directive governs, and the issuer identifier is a claim to compare
	// against rather than a URL to call — [identity] is what validates that
	// one, and restating the check here would give two places to disagree.
	if cfg.OIDC.TokenEndpoint != "" {
		origin, oerr := originOf(cfg.OIDC.TokenEndpoint, cfg.AllowInsecureTransport)
		if oerr != nil {
			return nil, fmt.Errorf("api: console token endpoint %q: %w", cfg.OIDC.TokenEndpoint, oerr)
		}
		connect = append(connect, origin)
	}
	if cfg.OIDC.AuthorizationEndpoint != "" {
		if _, oerr := originOf(cfg.OIDC.AuthorizationEndpoint, cfg.AllowInsecureTransport); oerr != nil {
			return nil, fmt.Errorf("api: console authorization endpoint %q: %w",
				cfg.OIDC.AuthorizationEndpoint, oerr)
		}
	}

	scopes := cfg.OIDC.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	roleClaim := cfg.OIDC.RoleClaim
	if roleClaim == "" {
		roleClaim = "roles"
	}

	doc := consoleDocument{
		Version:    ContractVersion,
		APIBaseURL: apiBase,
		BasePath:   ConsoleBasePath,
		OIDC: consoleOIDCDocument{
			Issuer:                cfg.OIDC.Issuer,
			AuthorizationEndpoint: cfg.OIDC.AuthorizationEndpoint,
			TokenEndpoint:         cfg.OIDC.TokenEndpoint,
			EndSessionEndpoint:    cfg.OIDC.EndSessionEndpoint,
			ClientID:              cfg.OIDC.ClientID,
			Scopes:                scopes,
			RoleClaim:             roleClaim,
		},
	}
	body, err := doc.encode()
	if err != nil {
		return nil, err
	}

	c := &Console{
		assets: cfg.Assets,
		config: body,
		csp:    consoleCSP(dedupe(connect)),
	}
	if cfg.Assets != nil {
		if f, oerr := cfg.Assets.Open("index.html"); oerr == nil {
			_ = f.Close()
			c.hasIndex = true
		} else if !errors.Is(oerr, fs.ErrNotExist) {
			return nil, fmt.Errorf("api: console assets: %w", oerr)
		}
	}
	return c, nil
}

// Available reports whether this binary carries a built bundle.
func (c *Console) Available() bool { return c.hasIndex }

// ContentSecurityPolicy returns the policy sent with every console response.
func (c *Console) ContentSecurityPolicy() string { return c.csp }

// Routes implements [Provider].
func (c *Console) Routes() []Route {
	return []Route{
		{
			Name:    "console-config",
			Surface: SurfaceConsole,
			Pattern: "GET " + ConsoleConfigPath,
			Auth:    AuthStatic,
			Handler: c.secured(http.HandlerFunc(c.serveConfig)),
		},
		{
			// The subtree pattern carries no method, and that is not an
			// oversight. net/http answers 405 when a path matches a pattern
			// whose method does not, so a `GET /console/` subtree would make a
			// console-only tier answer 405 to `POST /console/v1/policies/
			// dry-run` — announcing that the endpoint exists here, on the one
			// tier that does not serve it. The composition root's whole rule is
			// that 404 means "this process does not run that subsystem", so the
			// method check moves inside the handler and comes back as a 404.
			Name:    "console-shell",
			Surface: SurfaceConsole,
			Pattern: ConsoleBasePath,
			Auth:    AuthStatic,
			Handler: c.secured(http.HandlerFunc(c.serveAsset)),
		},
		{
			// Without this a person who typed the path without its trailing
			// slash gets the console surface's 404 and concludes the console
			// is not deployed.
			Name:    "console-root-redirect",
			Surface: SurfaceConsole,
			Pattern: strings.TrimSuffix(ConsoleBasePath, "/"),
			Auth:    AuthStatic,
			Handler: c.secured(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !isRead(r) {
					http.NotFound(w, r)
					return
				}
				http.Redirect(w, r, ConsoleBasePath, http.StatusMovedPermanently)
			})),
		},
	}
}

// secured attaches the response headers that bound the bundle.
//
// They are attached here rather than in a server-wide middleware because they
// are the console's headers: a CSP naming the console's API origin has no
// meaning on the PEP surface, and frame-ancestors on a JSON API is noise.
func (c *Console) secured(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", c.csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// frame-ancestors is in the CSP above; this is for the proxies and
		// browsers that still only read the header.
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("X-Stamp-Component", "console")
		next.ServeHTTP(w, r)
	})
}

func (c *Console) serveConfig(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	// An operator who repoints the API base must not have to explain to every
	// approver how to clear a cache.
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(c.config)
}

// consoleDocument is the operator configuration the bundle boots from.
//
// Everything in it is a deployment decision, and none of it is a secret: a
// public client identifier and a set of endpoints are exactly what an
// authorization code flow with PKCE publishes anyway. What matters is not that
// the document is unreadable but that it is the console's *only* source for
// these values.
type consoleDocument struct {
	Version    int                 `json:"version"`
	APIBaseURL string              `json:"apiBaseUrl"`
	BasePath   string              `json:"basePath"`
	OIDC       consoleOIDCDocument `json:"oidc"`
}

type consoleOIDCDocument struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorizationEndpoint"`
	TokenEndpoint         string   `json:"tokenEndpoint"`
	EndSessionEndpoint    string   `json:"endSessionEndpoint,omitempty"`
	ClientID              string   `json:"clientId"`
	Scopes                []string `json:"scopes"`
	RoleClaim             string   `json:"roleClaim"`
}

func (d consoleDocument) encode() ([]byte, error) {
	body, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("api: encode console configuration: %w", err)
	}
	return append(body, '\n'), nil
}

// assetPrefixes that must never fall back to index.html.
//
// A missing hashed asset that answered with HTML would surface as a syntax
// error inside the module loader instead of as a 404, and "v1" is the console
// surface's own API namespace — [DryRunPath] lives under /console/v1 — so a
// mistyped API path has to look like a mistyped API path.
var noFallbackPrefixes = []string{"assets/", "v1/"}

// isRead reports whether the request is one a static file server answers.
func isRead(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead
}

func (c *Console) serveAsset(w http.ResponseWriter, r *http.Request) {
	// See the comment on the console-shell route: a write method under the
	// bundle's subtree is an endpoint this process does not serve, and that is
	// a 404 rather than a 405.
	if !isRead(r) {
		http.NotFound(w, r)
		return
	}
	if !c.hasIndex {
		c.serveUnbuilt(w)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, ConsoleBasePath)
	name = strings.TrimPrefix(path.Clean("/"+name), "/")
	if name == "" || name == "." {
		c.serveIndex(w, r)
		return
	}

	if f, err := c.assets.Open(name); err == nil {
		info, serr := f.Stat()
		_ = f.Close()
		if serr == nil && !info.IsDir() {
			// Vite writes a content hash into every emitted asset name, so the
			// only cache invalidation these need is a new name.
			if strings.HasPrefix(name, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			http.ServeFileFS(w, r, c.assets, name)
			return
		}
	}

	for _, prefix := range noFallbackPrefixes {
		if strings.HasPrefix(name, prefix) {
			http.NotFound(w, r)
			return
		}
	}
	if !acceptsHTML(r) {
		http.NotFound(w, r)
		return
	}
	c.serveIndex(w, r)
}

func (c *Console) serveIndex(w http.ResponseWriter, r *http.Request) {
	// index.html names the hashed bundle, so caching it is how a deploy fails
	// to take effect.
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFileFS(w, r, c.assets, "index.html")
}

// serveUnbuilt answers when the binary was compiled without a console build.
//
// It is a 503 rather than a 404: the route is mounted, the role is running,
// and what is missing is an artifact the build produces. Saying so in the body
// is the difference between a five minute fix and a hunt through role flags.
func (c *Console) serveUnbuilt(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(w, consoleUnbuiltMessage)
}

// ConsoleUnbuiltMessage is the guidance a build with no bundle returns.
const consoleUnbuiltMessage = "the console bundle is not embedded in this build\n\n" +
	"this binary was compiled without console/dist. build it and rebuild:\n" +
	"    cd console && npm ci && npm run build\n" +
	"    go build ./cmd/stamp\n\n" +
	"the console role is running and this route is mounted; only the assets are missing.\n"

func acceptsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" {
		// A bare deep link from an old client is still a navigation.
		return true
	}
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

// consoleCSP renders the policy.
//
// default-src 'none' means every fetch directive that is not named below is
// denied, so a directive nobody thought of does not default to permissive.
// script-src and style-src have no 'unsafe-inline': the bundle emits external
// modules and one external stylesheet, and the console is written without
// inline style attributes so that this stays true.
func consoleCSP(connect []string) string {
	directives := []string{
		"default-src 'none'",
		"script-src 'self'",
		"style-src 'self'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src " + strings.Join(connect, " "),
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"manifest-src 'self'",
	}
	return strings.Join(directives, "; ")
}

// normalizeAPIBase validates the operator's API base URL and returns it
// alongside the origin connect-src has to be widened to.
//
// An empty base is same-origin and widens nothing, which is why the
// single-container install needs no console configuration at all.
func normalizeAPIBase(raw string, allowInsecure bool) (base, origin string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", nil
	}
	u, perr := url.Parse(trimmed)
	if perr != nil {
		return "", "", fmt.Errorf("api: console api base url %q: %w", raw, perr)
	}
	if !u.IsAbs() {
		return "", "", fmt.Errorf(
			"api: console api base url %q is relative: give an absolute origin, or leave it empty for same-origin", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("api: console api base url %q carries a query or fragment", raw)
	}
	if err := checkScheme(u, allowInsecure); err != nil {
		return "", "", fmt.Errorf("api: console api base url %q: %w", raw, err)
	}
	// A trailing slash here and a leading slash on every contract path would
	// join into a double slash, which some proxies normalize and some route.
	base = strings.TrimRight(u.String(), "/")
	return base, u.Scheme + "://" + u.Host, nil
}

func originOf(raw string, allowInsecure bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if !u.IsAbs() || u.Host == "" {
		return "", errors.New("expected an absolute http(s) url")
	}
	if err := checkScheme(u, allowInsecure); err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

func checkScheme(u *url.URL, allowInsecure bool) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecure {
			return nil
		}
		return errors.New("http is refused: set the insecure transport flag for loopback development")
	default:
		return fmt.Errorf("scheme %q is not http or https", u.Scheme)
	}
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	// 'self' stays first; the rest sort so the header is stable.
	if len(out) > 1 {
		sort.Strings(out[1:])
	}
	return out
}
