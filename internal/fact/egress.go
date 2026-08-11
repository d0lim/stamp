package fact

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrBlocked is the sentinel every egress refusal wraps.
//
// It survives the wrapping http.Client does around a dial error, so a refusal
// that happened inside the dialler is still recognisable as a refusal by the
// time it reaches the caller, rather than being flattened into an unhelpful
// "connection failed".
var ErrBlocked = errors.New("destination is not permitted by the egress allowlist")

// DefaultMaxResponseBytes caps a fact response body when the operator sets no
// cap of their own.
const DefaultMaxResponseBytes int64 = 1 << 20

// egressMaxIdleConns is the idle connection budget, and it is deliberately one
// number serving as both the global cap and the per-host cap. The reasoning is
// above newEgressClient, where the two are set.
const egressMaxIdleConns = 32

// EgressConfig is the operator's deployment configuration for outbound fact
// calls. It is the whole of what a fact source is allowed to reach; nothing in
// a policy document adds to it.
type EgressConfig struct {
	// Allow lists the permitted origins, each written scheme://host[:port].
	// Matching is exact on scheme, host, and port — there are no wildcards,
	// because a wildcard is how an allowlist stops being a list of decisions
	// somebody made.
	Allow []string
	// AllowLoopback permits 127.0.0.0/8 and ::1. Off by default. It exists for
	// local development and for tests that need a real listener.
	AllowLoopback bool
	// AllowPrivate permits the RFC 1918 and unique-local ranges. Off by
	// default. It does not admit link-local addresses, which stay blocked
	// under every configuration.
	AllowPrivate bool
	// Resolve overrides hostname resolution. Nil uses the system resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// RootCAs overrides the trusted roots for TLS. Nil uses the system pool.
	// It never disables verification; there is no configuration that does.
	RootCAs *x509.CertPool
	// MaxResponseBytes caps a fact response body. Zero selects
	// DefaultMaxResponseBytes.
	MaxResponseBytes int64
}

func (c EgressConfig) maxResponseBytes() int64 {
	if c.MaxResponseBytes <= 0 {
		return DefaultMaxResponseBytes
	}
	return c.MaxResponseBytes
}

// Gate decides what may be dialled. It is consulted at load time, again at call
// time, and once more inside the dialler after the destination has been
// resolved to an address — the same rules each time, so there is no ordering in
// which a destination is admitted by one check and would have been refused by
// another.
type Gate struct {
	origins       map[string]struct{}
	allowLoopback bool
	allowPrivate  bool
	resolve       func(ctx context.Context, host string) ([]netip.Addr, error)
	rootCAs       *x509.CertPool
}

// NewGate builds a gate from operator configuration.
func NewGate(cfg EgressConfig) (*Gate, error) {
	g := &Gate{
		origins:       make(map[string]struct{}, len(cfg.Allow)),
		allowLoopback: cfg.AllowLoopback,
		allowPrivate:  cfg.AllowPrivate,
		resolve:       cfg.Resolve,
		rootCAs:       cfg.RootCAs,
	}
	if g.resolve == nil {
		g.resolve = systemResolve
	}
	for _, entry := range cfg.Allow {
		origin, err := parseOrigin(entry)
		if err != nil {
			return nil, fmt.Errorf("allowlist entry %q: %w", entry, err)
		}
		g.origins[origin] = struct{}{}
	}
	return g, nil
}

// CheckURL reports whether a destination is admitted by the allowlist, without
// touching the network.
//
// It is the check that runs at load time on a declared target and again at call
// time before the request is built, and it is the same check applied to a
// redirect's target — which is what makes "declared directly" and "arrived at
// by redirect" the same question with the same answer.
func (g *Gate) CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %q is not a valid URL", ErrBlocked, raw)
	}
	if u.User != nil {
		return fmt.Errorf("%w: %s carries credentials in the URL", ErrBlocked, u.Redacted())
	}
	origin, err := originOf(u)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrBlocked, u.Redacted(), err)
	}
	if _, ok := g.origins[origin]; !ok {
		return fmt.Errorf("%w: origin %s is not on the operator allowlist", ErrBlocked, origin)
	}
	// A target written as an address literal never reaches the resolver, so
	// the range rules are applied here as well.
	if addr, err := netip.ParseAddr(u.Hostname()); err == nil {
		if err := g.CheckAddr(addr); err != nil {
			return err
		}
	}
	return nil
}

// neverDialable are the ranges no configuration opens. They are the ones where
// "reachable from this process" and "meaningful to the caller" come apart: an
// address that means something different depending on who dials it, or that
// names infrastructure rather than a peer.
var neverDialable = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved, and the broadcast address
	netip.MustParsePrefix("::/128"),        // unspecified
	netip.MustParsePrefix("::/96"),         // IPv4-compatible, deprecated
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"), // 6to4, which embeds an arbitrary IPv4 destination
	netip.MustParsePrefix("fec0::/10"), // site-local, deprecated
}

// CheckAddr reports whether an address may be dialled.
//
// The IPv4-mapped form is unwrapped before anything else. ::ffff:169.254.169.254
// is the metadata service written a different way, and a check that reasons
// about it as an IPv6 address concludes it is an ordinary public destination.
//
// Link-local is refused under every configuration, including the loosest one an
// operator can set. The loopback and private ranges have opt-ins because a
// deployment may legitimately front a fact endpoint on its own network, but the
// address family that resolves to "whatever is attached to this host" has no
// legitimate use as a policy-named destination.
func (g *Gate) CheckAddr(addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: not a valid address", ErrBlocked)
	}
	addr = addr.Unmap()
	refuse := func(what string) error {
		return fmt.Errorf("%w: %s is %s", ErrBlocked, addr, what)
	}
	switch {
	case addr.IsUnspecified():
		return refuse("the unspecified address")
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return refuse("link-local, which is never dialable by a fact source")
	case addr.IsInterfaceLocalMulticast(), addr.IsMulticast():
		return refuse("a multicast address")
	case addr.IsLoopback():
		if !g.allowLoopback {
			return refuse("loopback, which this deployment does not permit")
		}
		// Returning here rather than falling through: ::1 sits inside the
		// deprecated IPv4-compatible prefix below, and a permitted loopback is
		// permitted.
		return nil
	case addr.IsPrivate():
		if !g.allowPrivate {
			return refuse("in a private range, which this deployment does not permit")
		}
	}
	for _, prefix := range neverDialable {
		if prefix.Contains(addr) {
			return refuse("in the reserved range " + prefix.String())
		}
	}
	return nil
}

// Preflight resolves a declared target at load time and refuses it if the
// resolution lands anywhere the gate would not dial.
//
// A resolution that fails is not a refusal. DNS is allowed to be down when a
// process starts, and a deployment that would not load because of it turns a
// transient outage into a restart loop. What is refused is a resolution that
// succeeds and points somewhere forbidden — a hostname is not a way to spell an
// address the operator did not permit.
func (g *Gate) Preflight(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %q is not a valid URL", ErrBlocked, raw)
	}
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		return g.CheckAddr(addr)
	}
	addrs, err := g.resolve(ctx, host)
	if err != nil {
		return nil
	}
	return g.checkAll(host, addrs)
}

// checkAll refuses the whole answer if any address in it is forbidden.
//
// Taking the permitted address and dialling that would leave the outcome up to
// which record the resolver happened to return first, which is a choice an
// attacker who controls the zone gets to make.
func (g *Gate) checkAll(host string, addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return fmt.Errorf("%w: %s resolved to no addresses", ErrBlocked, host)
	}
	for _, addr := range addrs {
		if err := g.CheckAddr(addr); err != nil {
			return fmt.Errorf("%w (via %s)", err, host)
		}
	}
	return nil
}

// DialContext resolves a destination, refuses the answer if any address in it
// is forbidden, and then dials an address literal.
//
// This is where the resolved address is pinned, and it is deliberately the only
// place. The transport hands this function the host from the request URL and
// layers TLS on top of whatever connection comes back, deriving the server name
// from that same URL — so the certificate is checked against the hostname the
// policy named while the socket goes to the address the gate approved.
//
// The obvious alternative, rewriting the request URL to the resolved address,
// pins just as well and quietly moves TLS verification onto the address. A
// certificate that happens to cover the address then satisfies a request for a
// hostname it says nothing about, and nothing in the call reports that the name
// was never checked. Doing it in the dialler is what keeps the two properties
// from trading against each other.
//
// There is no window between the check and the dial: what is handed to the
// system dialler is a literal, so it cannot be resolved a second time into
// something else.
func (g *Gate) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not a host:port pair", ErrBlocked, addr)
	}
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not a valid port", ErrBlocked, port)
	}

	var addrs []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{literal}
	} else {
		resolved, err := g.resolve(ctx, host)
		if err != nil {
			// Not an egress refusal. A name that did not resolve is a transport
			// failure, and filing it as a blocked destination would put a DNS
			// outage in the audit trail next to the SSRF attempts.
			return nil, fmt.Errorf("resolving %s: %w", host, err)
		}
		addrs = resolved
	}
	if err := g.checkAll(host, addrs); err != nil {
		return nil, err
	}

	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, a := range addrs {
		conn, err := dialer.DialContext(ctx, network, netip.AddrPortFrom(a.Unmap(), uint16(portNum)).String())
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// newEgressClient builds the HTTP client every http fact source shares.
//
// Every field here is load-bearing.
//
// DialContext is the gate's, so the address pin applies to every connection.
// Every connection, not every request — the difference is the subject of the
// note below, and it is a real one. TLSClientConfig is left without ServerName
// so the transport fills it in from the request URL, and without
// InsecureSkipVerify because no configuration in this package turns
// verification off.
//
// Proxy is nil rather than http.ProxyFromEnvironment. An environment proxy
// would take the destination back out of the dialler's hands — the connection
// would go to the proxy and the hostname would be resolved at the far end,
// which is the address pin undone by a stray variable in a deployment manifest.
//
// Jar is nil and there is no CheckRedirect that follows anything, for the same
// reason: a fact call carries no ambient authority and takes no steps the
// declaration did not name.
//
// # Why pooling connections does not weaken the pin
//
// A request that rides a pooled connection does not call DialContext, so it
// does not resolve the name and does not run checkAll. That is not a hole, and
// working out why is what settled the size of the pool rather than the other
// way round.
//
// The check the dialler performs is a question about an address:
// may this process open a socket to this peer? An established socket's peer
// cannot be changed by anything that happens afterwards — not by a DNS record,
// not by the remote end. So a reused connection carries the request to the
// address the gate approved, which is the same thing the pin was there to
// guarantee. It is the opposite of a bypass: a name whose meaning has drifted
// is exactly what a pinned socket refuses to follow.
//
// The check is also a pure function of the address and the gate's ranges, both
// of which are fixed for a gate's lifetime. An address the gate admitted cannot
// become one it would refuse. There is no moment at which a pooled connection
// is holding open something the gate has since decided against.
//
// What reuse does cost is promptness. If the operator's endpoint moves — a
// legitimate DNS change, or a rebinding attempt — the pool keeps talking to the
// old address until the connection is dialled again. IdleConnTimeout bounds
// that for a deployment whose traffic is bursty enough to let the connection go
// idle; under sustained load it does not, because http.Transport has no maximum
// connection lifetime and a busy connection is never idle. The delay is
// acceptable because what it delays is a change of destination among addresses
// the gate permits, not an escape to one it does not. The per-request checks
// that do still run every time — the allowlist, the scheme, the absence of
// credentials in the URL — are in httpSource.Fetch, and they are the ones whose
// answer an operator can change.
//
// Pooling is keyed by the requested host, so one host's request never inherits
// another's connection; TestDifferentHostsDoNotShareAConnection and
// TestABlockedHostCannotInheritAnApprovedConnection hold that premise down,
// because if it were false the reasoning above would collapse.
//
// ForceAttemptHTTP2 is left off, and that is now a decision rather than an
// accident of the field being unset. Supplying a DialContext and a
// TLSClientConfig already disables the automatic HTTP/2 upgrade, so these are
// HTTP/1.1 connections and the pool is the HTTP/1.1 pool the tests above
// describe. Turning HTTP/2 on would put a different pool underneath the same
// claim, and that claim would have to be re-established before it could be
// relied on.
//
// # The size of the pool
//
// MaxIdleConnsPerHost is set rather than left at Go's default of 2, which is
// what made every concurrent fact call past the second open and discard a
// socket, and what exhausted the loopback ephemeral port range under load.
//
// It is set to the same number as MaxIdleConns, from one constant, because an
// egress allowlist is a list somebody wrote by hand and the ordinary deployment
// has one or two fact origins on it. A per-host cap below the global one would
// mean the common deployment can never use the budget it was given. Sharing the
// budget costs a host nothing it can fail on: the per-host cap governs how many
// idle connections are kept, not how many may be open, so a host that finds the
// pool empty dials — it pays a handshake, it is not refused.
func newEgressClient(g *Gate) *http.Client {
	transport := &http.Transport{
		Proxy:       nil,
		DialContext: g.DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    g.rootCAs,
		},
		MaxIdleConns:          egressMaxIdleConns,
		MaxIdleConnsPerHost:   egressMaxIdleConns,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Transport: transport,
		Jar:       nil,
		// A redirect is a destination the policy author did not declare and the
		// operator did not allow, chosen by whoever answered the call. Returning
		// the 3xx instead of following it keeps "which destinations may be
		// reached" a question the allowlist answers, rather than one the remote
		// end gets a say in. The caller reports it as a failure, so the attempt
		// lands in the audit trail instead of disappearing into a hop.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// HTTPClient returns the gated client for callers outside this package.
//
// It exists because a fact source is not the only outbound call a deployment
// makes: an external challenge posts a webhook to an operator-allowlisted
// target and must reach it through this gate rather than through a client of
// its own. Handing out the constructed client rather than the pieces is the
// point — a second caller assembling its own transport is a second place the
// proxy setting, the redirect policy and the address pin can be got wrong, and
// the one that is got wrong is the one an audit does not cover.
func (g *Gate) HTTPClient() *http.Client { return newEgressClient(g) }

func systemResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// parseOrigin normalizes an allowlist entry to the canonical origin key.
func parseOrigin(entry string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(entry))
	if err != nil {
		return "", fmt.Errorf("not a valid URL: %w", err)
	}
	if u.User != nil {
		return "", errors.New("must not carry credentials")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("must be an origin (scheme://host[:port]) with no path")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("must be an origin (scheme://host[:port]) with no query or fragment")
	}
	return originOf(u)
}

// originOf renders the canonical origin key of a URL: lowercase scheme and
// host, with the port always written out.
func originOf(u *url.URL) (string, error) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("scheme %q is not permitted; only http and https are", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("has no host")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.Unmap().String()
		if addr.Is6() && !addr.Is4In6() {
			host = "[" + host + "]"
		}
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", fmt.Errorf("port %q is not a valid port", port)
	}
	return scheme + "://" + host + ":" + port, nil
}
