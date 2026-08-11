// Package idpgroup serves R16's IdP group lookup: given a group identifier it
// answers with the list of member subject identifiers, so a quorum can name a
// group instead of a list of people.
//
// It lives beside the synchronous fact plane rather than inside it, for the
// same reason the velocity sources do — its transport half is nothing like an
// HTTP fact source's — but it speaks that plane's vocabulary throughout:
// [fact.Declaration]'s split between the schema half and the operator half,
// [fact.Failure] with its stable reasons, [fact.ErrLoad] on a rejected
// declaration, and the egress gate on every outbound byte. A caller reading an
// audit row cannot tell which plane produced it, which is the point.
//
// D7 noticed the shape: because approver identity is delegated to the IdP,
// resolving an approver set is fact procurement with a different name. This
// package is where that observation becomes code. One type answers both
// [engine.SourceResolver], so a condition can ask what a group contains, and
// [challenge.GroupResolver], so a quorum can resolve its approvers from one —
// R18's third mode, whose seam U20 left open.
//
// Three rules are this unit's own.
//
// Membership staleness is an authorization property, not a latency knob. The
// TTL on a whitelist buys throughput at the cost of an out-of-date answer; the
// TTL on a group membership is the window in which somebody who has been
// removed from the group can still be named an approver. So the TTL is
// required, it is explicit, and it is capped at [DefaultMaxTTL] at load — an
// operator may lower the cap for their deployment, a policy author cannot raise
// it. An entry past its TTL is gone rather than available as a fallback, and a
// failed lookup is not cached at all.
//
// The directory credential is operator configuration and is unreachable from a
// policy. U6's rule is that a fact call carries no ambient authority, because
// the policy author is outside the trust boundary (D21) and a call they aimed
// must not be able to spend the deployment's identity. A group directory does
// need a credential, so this source carries one — but it is bound to the
// operator's configured endpoint, it never appears in [Declaration.SourceDecl],
// and there is no field in a policy document that names or reaches it.
//
// Failing open has no meaning for an approver set. The declaration's failure
// behaviour is honoured for condition use exactly as the fact plane honours it,
// with allow admitted only by the operator flag. But [Sources.ResolveApprovers]
// never consults it: allow answers the question "should this request proceed",
// and there is no answer it could give to "who is permitted to approve this". A
// directory that cannot answer means the challenge is not issued.
package idpgroup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
)

// Failure reasons for a group lookup. They join the fact plane's reason
// vocabulary rather than starting a second one, because an operator greps one
// audit stream and a dashboard groups one set of labels. Everything that can go
// wrong the way an HTTP fact call goes wrong reuses that call's reason.
const (
	// ReasonUnknownGroup means the directory does not know the named group. It
	// is distinguished from an empty group because the two are different
	// operator problems: a name no longer in the directory, or a group somebody
	// emptied.
	ReasonUnknownGroup fact.Reason = "fact_idp_group_unknown"
	// ReasonDirectoryDenied means the directory refused the operator's
	// credential. It is separated from a generic bad status because it names
	// the one failure an operator fixes without touching a policy.
	ReasonDirectoryDenied fact.Reason = "fact_idp_directory_denied"
	// ReasonDirectoryPaged means the directory reported more members than it
	// returned. A truncated membership list is an approver set with people
	// silently missing from it, so it is refused rather than used.
	ReasonDirectoryPaged fact.Reason = "fact_idp_directory_paginated"
)

// Defaults applied when [SourcesConfig] leaves a bound unset.
const (
	// DefaultMaxTTL caps how stale a membership answer may be. It is minutes
	// rather than hours because this TTL is a revocation delay budget: it is
	// how long after somebody leaves a group that they can still be resolved
	// into an approver set.
	DefaultMaxTTL = 5 * time.Minute
	// DefaultMaxCacheEntries bounds the membership cache. The cache key
	// includes the group identifier, which can be request-derived, so an
	// unbounded cache would be a memory amplifier reachable from outside.
	DefaultMaxCacheEntries = 1024
	// DefaultMaxMembers bounds how many members one answer may carry.
	DefaultMaxMembers = 10000
	// DefaultMembersField is the answer field holding the member list. It is
	// what a SCIM group representation calls it.
	DefaultMembersField = "members"
	// DefaultMemberIDField is the field of a member object holding the subject
	// identifier. SCIM calls it "value".
	DefaultMemberIDField = "value"
	// DefaultTotalField is the answer field reporting how many members exist,
	// which is how a paginated answer is detected. SCIM calls it
	// "totalResults".
	DefaultTotalField = "totalResults"
)

// Declaration is one configured group source.
//
// It splits the way [fact.Declaration] does and for the same reason. The
// signature half — name, parameters, return type, failure behaviour — is
// authored with the policy and appears in the schema. Everything else is
// deployment configuration: which directory is called, with which credential,
// how its answer is shaped, how long an answer may be reused. A policy author
// who could write those fields could aim the deployment's IdP credential at a
// destination of their choosing, which is the whole of what the split prevents.
type Declaration struct {
	// Name is the declared source name, matching a policy.SourceDecl of kind
	// idp_group.
	Name string
	// Issuer is the token issuer whose subject identifiers this directory
	// returns. It must be one of the deployment's trusted issuers: a member
	// list from an issuer whose tokens are not accepted names approvers who can
	// never appear, and that shows up as a quorum nobody can satisfy rather
	// than as the misconfiguration it is.
	Issuer string
	// URL is the group directory endpoint. It must be admitted by the
	// operator's egress allowlist. Any query string it carries is preserved and
	// the group argument is added alongside it.
	URL string
	// Credential is the bearer credential presented to the directory. Empty
	// sends no Authorization header at all. It is operator configuration and is
	// never derived from, or nameable by, a policy document.
	Credential string
	// MembersField, MemberIDField and TotalField name the shape of the
	// directory's answer. Empty selects the SCIM-shaped defaults.
	MembersField  string
	MemberIDField string
	TotalField    string
	// TTL bounds how stale a membership answer may be. Required, positive, and
	// capped by the deployment's maximum.
	TTL time.Duration
	// Timeout bounds one directory call. Required and positive.
	Timeout time.Duration
	// Params is the positional parameter list. A group source takes exactly one
	// string: the group identifier being resolved.
	Params []policy.Param
	// Returns is the declared result type, which is list<string>.
	Returns policy.Type
	// OnError is the failure behaviour for condition use. Empty means the safe
	// default, deny. Approver resolution never consults it.
	OnError policy.OnError
}

// SourceDecl returns the policy-schema half of the declaration, so a caller can
// compare a deployment's transport configuration against the schema a policy
// set was written against. Nothing about the directory — its URL, its
// credential, its answer shape — crosses into it.
func (d Declaration) SourceDecl() policy.SourceDecl {
	params := make([]policy.Param, len(d.Params))
	copy(params, d.Params)
	onErr := d.OnError
	if onErr == "" {
		onErr = policy.DefaultOnError
	}
	return policy.SourceDecl{
		Name:    d.Name,
		Kind:    policy.SourceIdPGroup,
		Params:  params,
		Returns: d.Returns,
		OnError: onErr,
	}
}

// SourcesConfig configures a [Sources].
type SourcesConfig struct {
	// Gate decides what may be dialled. Required. It is passed in rather than
	// built here so that one deployment has one allowlist: a second gate is a
	// second place the loopback and private opt-ins can disagree.
	Gate *fact.Gate
	// Issuers is the deployment's trusted issuer set, as the identity layer
	// pins it. Required: every directory is bound to one of these.
	Issuers []identity.IssuerConfig
	// AllowFailOpen is the operator-level flag that admits declarations asking
	// to fail open. With it unset, such a declaration is rejected at load.
	AllowFailOpen bool
	// MaxTTL caps a declaration's TTL. Zero selects DefaultMaxTTL.
	MaxTTL time.Duration
	// MaxCacheEntries bounds the membership cache. Zero selects
	// DefaultMaxCacheEntries.
	MaxCacheEntries int
	// MaxResponseBytes caps a directory answer. Zero selects
	// fact.DefaultMaxResponseBytes.
	MaxResponseBytes int64
	// MaxMembers caps how many members one answer may carry. Zero selects
	// DefaultMaxMembers.
	MaxMembers int
	// Fallback answers the calls in a batch that name a source this resolver
	// does not own — in practice the synchronous fact plane. Nil makes an
	// unknown call an error.
	Fallback engine.SourceResolver
	// Now overrides the clock. Nil means time.Now.
	Now func() time.Time
	// Audit receives a record of every failed lookup, exactly as the
	// synchronous plane's does. Nil discards them.
	Audit fact.Auditor
}

// Sources is the load-checked set of group sources one deployment serves.
//
// Construction is the load gate: a Sources that exists is one whose every
// declaration was admitted by operator configuration.
type Sources struct {
	cfg        SourcesConfig
	gate       *fact.Gate
	client     *http.Client
	cache      *cache
	now        func() time.Time
	limits     limits
	decls      declarations
	maxBytes   int64
	maxMembers int
}

// Compile-time proof that one type closes both loops: the condition language's
// resolver and the quorum's approver-set seam.
var (
	_ engine.SourceResolver   = (*Sources)(nil)
	_ challenge.GroupResolver = (*Sources)(nil)
)

// NewSources resolves group declarations against this deployment.
//
// Rejections wrap [fact.ErrLoad] — the same sentinel the other two planes use —
// so a composition root can tell "this deployment refuses to serve this policy
// set" from a runtime failure without caring which plane refused. They are
// collected rather than reported one at a time, so an operator fixing a
// deployment sees the whole list in one pass.
func NewSources(decls []Declaration, cfg SourcesConfig) (*Sources, error) {
	if cfg.Gate == nil {
		return nil, fmt.Errorf("%w: group sources require an egress gate", fact.ErrLoad)
	}
	if len(cfg.Issuers) == 0 {
		return nil, fmt.Errorf("%w: group sources require the deployment's trusted issuer set", fact.ErrLoad)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	maxEntries := cfg.MaxCacheEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxCacheEntries
	}
	maxTTL := cfg.MaxTTL
	if maxTTL <= 0 {
		maxTTL = DefaultMaxTTL
	}
	maxBytes := cfg.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = fact.DefaultMaxResponseBytes
	}
	maxMembers := cfg.MaxMembers
	if maxMembers <= 0 {
		maxMembers = DefaultMaxMembers
	}

	bounds, err := newLimits(cfg.Issuers, cfg.AllowFailOpen, maxTTL)
	if err != nil {
		return nil, err
	}
	s := &Sources{
		cfg:        cfg,
		gate:       cfg.Gate,
		client:     cfg.Gate.HTTPClient(),
		cache:      newCache(maxEntries, now),
		now:        now,
		limits:     bounds,
		maxBytes:   maxBytes,
		maxMembers: maxMembers,
	}
	if s.decls, err = resolveAll(decls, s.resolve); err != nil {
		return nil, err
	}
	return s, nil
}

// limits are the operator-level bounds a declaration is admitted against: which
// issuers this deployment trusts, whether it grants fail-open, and how stale a
// membership answer may be.
//
// They are held apart from [Sources] because they are the whole of what
// admitting a declaration needs. A [Gate] holds the same three and nothing
// else, which is what makes its declaration set the same set — see [NewGate].
type limits struct {
	issuers       map[string]struct{}
	allowFailOpen bool
	maxTTL        time.Duration
}

func newLimits(issuers []identity.IssuerConfig, allowFailOpen bool, maxTTL time.Duration) (limits, error) {
	l := limits{
		issuers:       make(map[string]struct{}, len(issuers)),
		allowFailOpen: allowFailOpen,
		maxTTL:        maxTTL,
	}
	if l.maxTTL <= 0 {
		l.maxTTL = DefaultMaxTTL
	}
	for _, iss := range issuers {
		if iss.Issuer == "" {
			return limits{}, fmt.Errorf("%w: a trusted issuer entry carries no issuer", fact.ErrLoad)
		}
		l.issuers[iss.Issuer] = struct{}{}
	}
	return l, nil
}

// resolveAll admits a declaration list, refusing a repeated name and collecting
// every rejection rather than reporting the first.
//
// It is the shared half of [NewSources] and [NewGate]: they differ only in the
// admit function they hand it, and therefore only in whether a destination is
// put through the egress gate.
func resolveAll(decls []Declaration, admit func(Declaration) (Declaration, error)) (declarations, error) {
	out := make(declarations, len(decls))
	var errs []error
	for _, decl := range decls {
		if _, dup := out[decl.Name]; dup {
			errs = append(errs, fmt.Errorf("%w: source %q: declared more than once", fact.ErrLoad, decl.Name))
			continue
		}
		resolved, err := admit(decl)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out[decl.Name] = resolved
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// resolve checks one declaration against operator configuration, and then puts
// its destination through the egress gate.
//
// The gate is the only thing this adds to [limits.admit], and it is the only
// thing a process that will never call a directory does not need.
func (s *Sources) resolve(decl Declaration) (Declaration, error) {
	decl, err := s.limits.admit(decl)
	if err != nil {
		return decl, err
	}
	failWith := func(err error) error {
		return fmt.Errorf("%w: source %q: %w", fact.ErrLoad, decl.Name, err)
	}
	// The first of the egress gate's checks. The same gate runs again at call
	// time and once more inside the dialler, so a destination is admitted by
	// exactly one rule set however it is arrived at.
	if err := s.gate.CheckURL(decl.URL); err != nil {
		return decl, failWith(err)
	}
	if err := s.gate.Preflight(context.Background(), decl.URL); err != nil {
		return decl, failWith(err)
	}
	return decl, nil
}

// admit checks one declaration against operator configuration and fills in its
// defaults. It reaches nothing: every rule here is about the declaration and
// the deployment's own settings, which is why a gate-only deployment applies
// exactly this and stops.
func (l limits) admit(decl Declaration) (Declaration, error) {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: source %q: %s", fact.ErrLoad, decl.Name, fmt.Sprintf(format, args...))
	}
	if !policy.ValidIdent(decl.Name) {
		return decl, fail("name is not a valid identifier")
	}
	if decl.Issuer == "" {
		return decl, fail("no issuer is configured; a group source is bound to the issuer whose subjects it names")
	}
	if _, ok := l.issuers[decl.Issuer]; !ok {
		return decl, fail("issuer %q is not trusted by this deployment, so its members could never be recognised as approvers", decl.Issuer)
	}

	if len(decl.Params) != 1 || decl.Params[0].Type != policy.TypeString {
		return decl, fail("takes exactly one string parameter, the group identifier being resolved")
	}
	if !policy.ValidIdent(decl.Params[0].Name) {
		return decl, fail("parameter %q is not a valid identifier", decl.Params[0].Name)
	}
	if decl.Returns != policy.ListOf(policy.TypeString) {
		return decl, fail("returns %q; a group source returns %s, the member subject identifiers",
			decl.Returns, policy.ListOf(policy.TypeString))
	}

	onErr := decl.OnError
	if onErr == "" {
		onErr = policy.DefaultOnError
	}
	if !onErr.Valid() {
		return decl, fail("on_error %q is not a valid failure behaviour", onErr)
	}
	// The operator flag, not the declaration, is what grants fail-open. The
	// check is repeated here rather than borrowed from the synchronous plane
	// because a deployment may configure this plane and not that one.
	if onErr == policy.OnErrorAllow && !l.allowFailOpen {
		return decl, fail("on_error: allow requires the operator fail-open flag, which is not enabled on this deployment")
	}
	decl.OnError = onErr

	switch {
	case decl.TTL <= 0:
		return decl, fail("ttl must be positive; the freshness bound of a membership answer is not allowed to be implicit")
	case decl.TTL > l.maxTTL:
		// The cap is the deployment's revocation delay budget. A membership
		// answer held past it is a person who left the group and can still be
		// resolved into an approver set.
		return decl, fail("ttl %s exceeds the maximum %s; a membership ttl is how long a removed member stays an eligible approver",
			decl.TTL, l.maxTTL)
	}
	if decl.Timeout <= 0 {
		return decl, fail("timeout must be positive")
	}
	if decl.URL == "" {
		return decl, fail("url is required")
	}

	if decl.MembersField == "" {
		decl.MembersField = DefaultMembersField
	}
	if decl.MemberIDField == "" {
		decl.MemberIDField = DefaultMemberIDField
	}
	if decl.TotalField == "" {
		decl.TotalField = DefaultTotalField
	}
	return decl, nil
}

// declarations is an admitted declaration set, and the whole of what verifying
// a schema needs.
//
// It is its own type because two things hold one: [Sources], which can call a
// directory, and [Gate], which cannot. Verification is a method here rather
// than on either of them, so the two cannot drift into checking different
// things — there is only one implementation to drift.
type declarations map[string]Declaration

// Names returns the declared source names, sorted.
func (d declarations) Names() []string {
	out := make([]string, 0, len(d))
	for name := range d {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// VerifySchema checks a policy schema's idp_group sources against this
// deployment.
//
// It is the counterpart of [fact.Registry.VerifySchema], which skips this kind
// precisely because it is served here. Between the two of them and the stream
// plane's, every source a schema declares is checked by exactly one.
//
// Nothing it reads is a credential: it compares the schema against
// [Declaration.SourceDecl], which by construction carries nothing about the
// directory. That is what lets a deployment gate a kind it never calls.
func (d declarations) VerifySchema(schema *policy.Schema) error {
	if schema == nil {
		return nil
	}
	var errs []error
	for i := range schema.Sources {
		sd := schema.Sources[i]
		if sd.Kind != policy.SourceIdPGroup {
			continue
		}
		decl, ok := d[sd.Name]
		if !ok {
			errs = append(errs, fmt.Errorf("%w: source %q: declared by the schema as an idp group source but not configured on this deployment",
				fact.ErrLoad, sd.Name))
			continue
		}
		if err := sameSignature(decl.SourceDecl(), sd); err != nil {
			errs = append(errs, fmt.Errorf("%w: source %q: %w", fact.ErrLoad, sd.Name, err))
		}
	}
	return errors.Join(errs...)
}

// GateConfig configures a [Gate]. It is [SourcesConfig] with everything a call
// would need taken out: there is no egress gate, no fallback resolver and no
// cache, because a gate makes no call and answers no lookup.
type GateConfig struct {
	// Issuers is the deployment's trusted issuer set, as the identity layer
	// pins it. Required, and required for the same reason [SourcesConfig] needs
	// it: a declaration bound to an untrusted issuer is refused here exactly as
	// it is there.
	Issuers []identity.IssuerConfig
	// AllowFailOpen is the operator-level flag that admits declarations asking
	// to fail open.
	AllowFailOpen bool
	// MaxTTL caps a declaration's TTL. Zero selects DefaultMaxTTL.
	MaxTTL time.Duration
}

// Gate is the schema gate for the idp_group kind on a process that will never
// call a directory.
//
// It exists because the two questions a deployment asks about a group source
// are separable and only one of them needs a credential. "Does this schema
// name a source this deployment serves, with the signature it serves it with"
// is answered from [Declaration.SourceDecl] alone — [declarations.VerifySchema]
// is literally the method [Sources] answers it with. "What is in this group" is
// the one that dials, and a role that never asks it has no business holding the
// directory's credential (R42).
//
// It is not a weaker gate. Weakening the gate is the thing
// [runtime.snapshotSource] must never do: a kind missing a plane is not a
// laxer check but no check at all, so a process that stops calling directories
// still has to refuse every schema a calling process would refuse. That is why
// this type verifies through the same map and the same method rather than
// through a second implementation that agrees today.
type Gate struct {
	decls declarations
}

// NewGate admits the same declarations [NewSources] admits, minus the egress
// check — which is the one rule about the destination rather than about the
// declaration, and the one a process that will not dial does not need.
//
// Its rejections wrap [fact.ErrLoad] like every other plane's.
func NewGate(decls []Declaration, cfg GateConfig) (*Gate, error) {
	if len(cfg.Issuers) == 0 {
		return nil, fmt.Errorf("%w: group sources require the deployment's trusted issuer set", fact.ErrLoad)
	}
	bounds, err := newLimits(cfg.Issuers, cfg.AllowFailOpen, cfg.MaxTTL)
	if err != nil {
		return nil, err
	}
	admitted, err := resolveAll(decls, bounds.admit)
	if err != nil {
		return nil, err
	}
	return &Gate{decls: admitted}, nil
}

// Names returns the declared group source names, sorted.
func (g *Gate) Names() []string { return g.decls.Names() }

// VerifySchema implements the schema gate. It is [Sources]' answer, from the
// same code.
func (g *Gate) VerifySchema(schema *policy.Schema) error { return g.decls.VerifySchema(schema) }

// Names returns the configured group source names, sorted.
func (s *Sources) Names() []string { return s.decls.Names() }

// Declaration returns the resolved declaration for a source.
func (s *Sources) Declaration(name string) (Declaration, bool) {
	decl, ok := s.decls[name]
	return decl, ok
}

// VerifySchema implements the schema gate for a deployment that can also call
// these directories. It is [Gate]'s answer, from the same code.
func (s *Sources) VerifySchema(schema *policy.Schema) error { return s.decls.VerifySchema(schema) }

func sameSignature(configured, declared policy.SourceDecl) error {
	if configured.Returns != declared.Returns {
		return fmt.Errorf("configured to return %q, declared to return %q", configured.Returns, declared.Returns)
	}
	if len(configured.Params) != len(declared.Params) {
		return fmt.Errorf("configured with %d parameters, declared with %d", len(configured.Params), len(declared.Params))
	}
	for i := range configured.Params {
		if configured.Params[i] != declared.Params[i] {
			return fmt.Errorf("parameter %d: configured as %s %s, declared as %s %s",
				i, configured.Params[i].Name, configured.Params[i].Type,
				declared.Params[i].Name, declared.Params[i].Type)
		}
	}
	onErr := declared.OnError
	if onErr == "" {
		onErr = policy.DefaultOnError
	}
	if configured.OnError != onErr {
		return fmt.Errorf("configured with on_error %q, declared with %q", configured.OnError, onErr)
	}
	return nil
}

// Lookup resolves one group's membership, serving it from cache while the
// declaration's TTL still covers it and calling the directory otherwise.
//
// On failure it returns a [fact.Failure] carrying the declaration's failure
// behaviour, and the same record has already gone to the auditor.
func (s *Sources) Lookup(ctx context.Context, name string, args ...fact.Value) (fact.Value, error) {
	decl, ok := s.decls[name]
	if !ok {
		return fact.Value{}, s.record(ctx, &fact.Failure{
			Source: name,
			Reason: fact.ReasonUnknownSource,
			Detail: "no group source by that name is configured on this deployment",
		}, policy.OnErrorDeny)
	}
	group, err := groupArgument(args)
	if err != nil {
		return fact.Value{}, s.record(ctx, &fact.Failure{
			Source: name,
			Reason: fact.ReasonBadArgument,
			Detail: err.Error(),
		}, decl.OnError)
	}

	key := cacheKey(name, group)
	if members, hit := s.cache.get(key); hit {
		return memberValue(members), nil
	}

	callCtx := ctx
	if decl.Timeout > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, decl.Timeout)
		defer cancel()
	}

	members, err := s.fetch(callCtx, decl, group)
	if err != nil {
		f := asFailure(name, err)
		// The timeout is the declaration's, so a context that expired during
		// the call is reported as the declared timeout elapsing rather than as
		// a generic transport error.
		if f.Reason == fact.ReasonTransport && callCtx.Err() != nil && ctx.Err() == nil {
			f.Reason = fact.ReasonTimeout
			f.Detail = "declared timeout of " + decl.Timeout.String() + " elapsed"
		}
		// Nothing is served from the cache here. A TTL-expired entry was
		// evicted on the miss above rather than kept as a fallback, and a
		// failure is not cached at all: a directory outage must not pin an
		// answer for the length of a TTL, in either direction.
		return fact.Value{}, s.record(ctx, f, decl.OnError)
	}
	s.cache.put(key, members, decl.TTL)
	return memberValue(members), nil
}

// ResolveSources implements [engine.SourceResolver].
//
// The batch is split by name: calls this deployment serves as group sources are
// answered here, and the rest go to the fallback in one batch of their own so
// that the synchronous plane still sees a batch rather than a call at a time.
func (s *Sources) ResolveSources(ctx context.Context, calls []engine.SourceCall) (*engine.Facts, error) {
	var mine, theirs []engine.SourceCall
	for _, call := range calls {
		if _, ok := s.decls[call.Name]; ok {
			mine = append(mine, call)
			continue
		}
		theirs = append(theirs, call)
	}

	facts := engine.NewFacts()
	if len(theirs) > 0 {
		if s.cfg.Fallback == nil {
			return nil, fmt.Errorf("idpgroup: fact source %q is not configured on this deployment", theirs[0].Name)
		}
		delegated, err := s.cfg.Fallback.ResolveSources(ctx, theirs)
		if err != nil {
			return nil, err
		}
		for _, call := range theirs {
			v, ok := delegated.Value(call)
			if !ok {
				return nil, fmt.Errorf("idpgroup: fact source %q was not answered by the fact plane", call.Name)
			}
			facts.Set(call, v)
		}
	}

	for _, call := range mine {
		if len(call.Args) != 1 {
			return nil, fmt.Errorf("idpgroup: group source %q takes 1 argument, condition passed %d",
				call.Name, len(call.Args))
		}
		v, err := s.Lookup(ctx, call.Name, fact.Value{Type: policy.TypeString, Data: call.Args[0]})
		if err != nil {
			return nil, fmt.Errorf("idpgroup: group source %q: %w", call.Name, err)
		}
		facts.Set(call, v.Data)
	}
	return facts, nil
}

// ResolveApprovers implements [challenge.GroupResolver]: R18's third mode.
//
// The answer carries the declaration's issuer alongside the members, and that
// is the reason this mode needs no deployment-wide approver-issuer
// designation. A member identifier is a `sub`, and a `sub` is unique only
// inside its issuer; the operator already stated which issuer this directory
// speaks for when they configured the source, so the pair travels together and
// the challenge freezes both. A quorum resolved this way can name approvers in
// an IdP that is not the deployment's default one, which a bare member list
// deliberately cannot.
//
// The argument is reduced against the decision's frozen request rather than
// against a live one, because the challenge is being issued for a decision that
// has already been made and every other term of it is frozen too. The
// membership itself is read now and frozen by the caller, which is what makes
// the TTL the whole of the staleness this mode admits.
//
// The declaration's failure behaviour is deliberately not consulted. There is
// no fail-open shape for "who is permitted to approve this", so a directory
// that cannot answer means the challenge is not issued.
func (s *Sources) ResolveApprovers(ctx context.Context, ref policy.SourceRef, dec challenge.DecisionContext) (challenge.ApproverGroup, error) {
	none := challenge.ApproverGroup{}
	decl, ok := s.decls[ref.Name]
	if !ok {
		return none, s.record(ctx, &fact.Failure{
			Source: ref.Name,
			Reason: fact.ReasonUnknownSource,
			Detail: "no group source by that name is configured on this deployment",
		}, policy.OnErrorDeny)
	}
	if len(ref.Args) != 1 {
		return none, s.record(ctx, &fact.Failure{
			Source: ref.Name,
			Reason: fact.ReasonBadArgument,
			Detail: fmt.Sprintf("expected 1 argument, got %d", len(ref.Args)),
		}, policy.OnErrorDeny)
	}
	group, err := frozenOperand(ref.Args[0], dec)
	if err != nil {
		return none, s.record(ctx, &fact.Failure{
			Source: ref.Name,
			Reason: fact.ReasonBadArgument,
			Detail: err.Error(),
		}, policy.OnErrorDeny)
	}

	// Lookup applies the declaration's failure behaviour to the record it
	// audits; what it must not do here is turn a failure into an answer, and it
	// cannot — a *Failure comes back either way and this returns it on.
	v, err := s.Lookup(ctx, decl.Name, fact.String(group))
	if err != nil {
		return none, err
	}
	items, ok := v.Data.([]any)
	if !ok {
		return none, s.record(ctx, &fact.Failure{
			Source: ref.Name,
			Reason: fact.ReasonDecode,
			Detail: fmt.Sprintf("expected a member list, got %T", v.Data),
		}, policy.OnErrorDeny)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		member, ok := item.(string)
		if !ok {
			return none, s.record(ctx, &fact.Failure{
				Source: ref.Name,
				Reason: fact.ReasonDecode,
				Detail: fmt.Sprintf("member is %T, not a subject identifier", item),
			}, policy.OnErrorDeny)
		}
		out = append(out, member)
	}
	// decl.Issuer is non-empty and trusted by construction: the load gate
	// refuses a declaration without one, and refuses one the identity layer
	// does not pin.
	return challenge.ApproverGroup{Issuer: decl.Issuer, Members: out}, nil
}

// Close releases the connections the directory client is holding.
func (s *Sources) Close() { s.client.CloseIdleConnections() }

func (s *Sources) record(ctx context.Context, f *fact.Failure, onErr policy.OnError) error {
	if onErr == "" {
		onErr = policy.DefaultOnError
	}
	f.OnError = onErr
	f.At = s.now()
	if s.cfg.Audit != nil {
		s.cfg.Audit.RecordFactFailure(ctx, f)
	}
	return f
}

func asFailure(name string, err error) *fact.Failure {
	var f *fact.Failure
	if errors.As(err, &f) {
		if f.Source == "" {
			f.Source = name
		}
		return f
	}
	return &fact.Failure{Source: name, Reason: fact.ReasonTransport, Err: err}
}

// groupArgument reduces a lookup's arguments to the one group identifier a
// group source takes.
func groupArgument(args []fact.Value) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("expected 1 argument, got %d", len(args))
	}
	if args[0].Type != policy.TypeString {
		return "", fmt.Errorf("expected a string group identifier, got %s", args[0].Type)
	}
	group, ok := args[0].Data.(string)
	if !ok {
		return "", fmt.Errorf("expected a string group identifier, got %T", args[0].Data)
	}
	if strings.TrimSpace(group) == "" {
		return "", errors.New("the group identifier is blank")
	}
	return group, nil
}

// memberValue renders a member list as the declared return type.
func memberValue(members []string) fact.Value {
	data := make([]any, len(members))
	for i, m := range members {
		data[i] = m
	}
	return fact.Value{Type: policy.ListOf(policy.TypeString), Data: data}
}

// cacheKey builds the membership cache key. The source name is length-prefixed
// so that no group identifier can forge the separator and be read back as a
// lookup against a different source.
func cacheKey(name, group string) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(len(name)))
	b.WriteByte(':')
	b.WriteString(name)
	b.WriteByte(0x1f)
	b.WriteString(group)
	return b.String()
}
