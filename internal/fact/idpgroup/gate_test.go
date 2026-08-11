package idpgroup

// gate_test.go holds the assertion the credential split rests on.
//
// A process that never resolves a group holds no directory credential, and gets
// [Gate] where a resolving process gets [Sources]. That is only safe if the two
// answer the schema gate identically — a gate-only tier that accepted a schema
// the calling tier refuses would load a policy set nothing in the deployment
// can serve, and one that refused a schema the calling tier accepts would be a
// tier that cannot start. So the parity is asserted rather than argued: the
// same declarations, the same schemas, the same answers down to the message.

import (
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
)

// gateIssuers is the pinned issuer set both halves are built against.
func gateIssuers() []identity.IssuerConfig {
	return []identity.IssuerConfig{{Issuer: testIssuer, JWKSURL: testIssuer + "/jwks"}}
}

// parityPair builds the two halves over one declaration list. The Sources half
// gets a real egress gate admitting the stub directory; the Gate half is given
// nothing to dial with, because it has nothing to dial.
func parityPair(t *testing.T, decls []Declaration, target string, allowFailOpen bool) (*Sources, *Gate) {
	t.Helper()
	full, ferr := NewSources(decls, SourcesConfig{
		Gate: newGate(t, fact.EgressConfig{
			Allow:         []string{originOfURL(t, target)},
			AllowLoopback: true,
			Resolve:       newFakeResolver().resolve,
		}),
		Issuers:       gateIssuers(),
		AllowFailOpen: allowFailOpen,
	})
	if ferr != nil {
		t.Fatalf("NewSources: %v", ferr)
	}
	t.Cleanup(full.Close)
	gateOnly, gerr := NewGate(decls, GateConfig{Issuers: gateIssuers(), AllowFailOpen: allowFailOpen})
	if gerr != nil {
		t.Fatalf("NewGate: %v", gerr)
	}
	return full, gateOnly
}

func groupSourceDecl() policy.SourceDecl {
	return policy.SourceDecl{
		Name:    "release_approvers",
		Kind:    policy.SourceIdPGroup,
		Params:  []policy.Param{{Name: "group", Type: policy.TypeString}},
		Returns: policy.ListOf(policy.TypeString),
		OnError: policy.OnErrorDeny,
	}
}

// TestTheGateAndTheCallerVerifyTheSameSchemas is the safety argument for the
// role split, stated as a test.
//
// Every schema here is run through both halves and the two answers are compared
// exactly: same acceptance, same message. An asymmetry in either direction is
// the failure the split would otherwise hide.
func TestTheGateAndTheCallerVerifyTheSameSchemas(t *testing.T) {
	d := newDirectory(t)
	decl := groupDecl(d.url())
	full, gateOnly := parityPair(t, []Declaration{decl}, d.url(), false)

	other := func(mutate func(*policy.SourceDecl)) policy.SourceDecl {
		sd := groupSourceDecl()
		mutate(&sd)
		return sd
	}

	tests := []struct {
		name   string
		schema *policy.Schema
		accept bool
	}{
		{"no schema at all", nil, true},
		{"a schema with no sources", &policy.Schema{}, true},
		{
			"the configured source, declared as configured",
			&policy.Schema{Sources: []policy.SourceDecl{groupSourceDecl()}},
			true,
		},
		{
			// on_error empty means deny, and the declaration was admitted with
			// the same default. Both halves have to apply it.
			"the configured source with an implicit on_error",
			&policy.Schema{Sources: []policy.SourceDecl{other(func(sd *policy.SourceDecl) { sd.OnError = "" })}},
			true,
		},
		{
			"an idp_group source this deployment does not configure",
			&policy.Schema{Sources: []policy.SourceDecl{other(func(sd *policy.SourceDecl) { sd.Name = "absent_group" })}},
			false,
		},
		{
			"the configured source declared with a different return type",
			&policy.Schema{Sources: []policy.SourceDecl{other(func(sd *policy.SourceDecl) { sd.Returns = policy.TypeString })}},
			false,
		},
		{
			"the configured source declared with a different parameter name",
			&policy.Schema{Sources: []policy.SourceDecl{other(func(sd *policy.SourceDecl) {
				sd.Params = []policy.Param{{Name: "team", Type: policy.TypeString}}
			})}},
			false,
		},
		{
			"the configured source declared with an extra parameter",
			&policy.Schema{Sources: []policy.SourceDecl{other(func(sd *policy.SourceDecl) {
				sd.Params = append(sd.Params, policy.Param{Name: "tenant", Type: policy.TypeString})
			})}},
			false,
		},
		{
			"the configured source declared to fail open",
			&policy.Schema{Sources: []policy.SourceDecl{other(func(sd *policy.SourceDecl) { sd.OnError = policy.OnErrorAllow })}},
			false,
		},
		{
			// Not this plane's kind: both halves skip it and leave it to the
			// plane that owns it, and "skip" has to mean the same thing twice.
			"an http source, which another plane owns",
			&policy.Schema{Sources: []policy.SourceDecl{{
				Name: "account_whitelist", Kind: policy.SourceHTTP,
				Params:  []policy.Param{{Name: "account", Type: policy.TypeString}},
				Returns: policy.ListOf(policy.TypeString), OnError: policy.OnErrorDeny,
			}}},
			true,
		},
		{
			"an event source, which another plane owns",
			&policy.Schema{Sources: []policy.SourceDecl{{
				Name: "transfer_count", Kind: policy.SourceEvent,
				Params:  []policy.Param{{Name: "subject", Type: policy.TypeString}},
				Returns: policy.TypeInt, OnError: policy.OnErrorDeny,
			}}},
			true,
		},
		{
			// Several refusals in one schema: both halves collect rather than
			// stopping at the first, and an operator has to see the same list.
			"two refusals at once",
			&policy.Schema{Sources: []policy.SourceDecl{
				other(func(sd *policy.SourceDecl) { sd.Name = "absent_group" }),
				other(func(sd *policy.SourceDecl) { sd.Returns = policy.TypeString }),
			}},
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fromFull := full.VerifySchema(tc.schema)
			fromGate := gateOnly.VerifySchema(tc.schema)

			if (fromFull == nil) != tc.accept {
				t.Fatalf("the calling half accepted = %v, want %v (err %v)", fromFull == nil, tc.accept, fromFull)
			}
			if (fromFull == nil) != (fromGate == nil) {
				t.Fatalf("the two halves disagree: caller err = %v, gate err = %v", fromFull, fromGate)
			}
			if fromFull != nil && fromFull.Error() != fromGate.Error() {
				t.Fatalf("the two halves refuse differently:\n caller: %v\n   gate: %v", fromFull, fromGate)
			}
		})
	}
}

// TestTheGateAdmitsTheSameDeclarations is the other half of the parity: a
// declaration list one accepts, the other accepts, so a role split cannot turn
// a deployment that boots into one that does not.
//
// The single deliberate difference is the egress check. A gate makes no call,
// so it has no destination to admit, and it holds no credential for the one it
// would have called — which is the whole point of the split.
func TestTheGateAdmitsTheSameDeclarations(t *testing.T) {
	d := newDirectory(t)
	good := groupDecl(d.url())

	tests := []struct {
		name    string
		decls   []Declaration
		failOpn bool
		accept  bool
	}{
		{"nothing configured", nil, false, true},
		{"one well-formed declaration", []Declaration{good}, false, true},
		{
			"a name that is not an identifier",
			[]Declaration{mutateDecl(good, func(dd *Declaration) { dd.Name = "not a name" })},
			false, false,
		},
		{
			"an issuer this deployment does not trust",
			[]Declaration{mutateDecl(good, func(dd *Declaration) { dd.Issuer = "https://elsewhere.example" })},
			false, false,
		},
		{
			"no ttl",
			[]Declaration{mutateDecl(good, func(dd *Declaration) { dd.TTL = 0 })},
			false, false,
		},
		{
			"a ttl past the deployment's cap",
			[]Declaration{mutateDecl(good, func(dd *Declaration) { dd.TTL = DefaultMaxTTL + time.Minute })},
			false, false,
		},
		{
			"no timeout",
			[]Declaration{mutateDecl(good, func(dd *Declaration) { dd.Timeout = 0 })},
			false, false,
		},
		{
			"no url",
			[]Declaration{mutateDecl(good, func(dd *Declaration) { dd.URL = "" })},
			false, false,
		},
		{
			"the wrong parameter shape",
			[]Declaration{mutateDecl(good, func(dd *Declaration) { dd.Params = nil })},
			false, false,
		},
		{
			"a return type that is not a member list",
			[]Declaration{mutateDecl(good, func(dd *Declaration) { dd.Returns = policy.TypeString })},
			false, false,
		},
		{
			"fail-open without the operator flag",
			[]Declaration{mutateDecl(good, func(dd *Declaration) { dd.OnError = policy.OnErrorAllow })},
			false, false,
		},
		{
			"fail-open with the operator flag",
			[]Declaration{mutateDecl(good, func(dd *Declaration) { dd.OnError = policy.OnErrorAllow })},
			true, true,
		},
		{"one name declared twice", []Declaration{good, good}, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			full, ferr := NewSources(tc.decls, SourcesConfig{
				Gate: newGate(t, fact.EgressConfig{
					Allow:         []string{originOfURL(t, d.url())},
					AllowLoopback: true,
					Resolve:       newFakeResolver().resolve,
				}),
				Issuers:       gateIssuers(),
				AllowFailOpen: tc.failOpn,
			})
			if ferr == nil {
				t.Cleanup(full.Close)
			}
			_, gerr := NewGate(tc.decls, GateConfig{Issuers: gateIssuers(), AllowFailOpen: tc.failOpn})

			if (ferr == nil) != tc.accept {
				t.Fatalf("NewSources accepted = %v, want %v (err %v)", ferr == nil, tc.accept, ferr)
			}
			if (ferr == nil) != (gerr == nil) {
				t.Fatalf("the two halves disagree on the configuration: NewSources = %v, NewGate = %v", ferr, gerr)
			}
			if ferr != nil && ferr.Error() != gerr.Error() {
				t.Fatalf("the two halves refuse the configuration differently:\n NewSources: %v\n    NewGate: %v", ferr, gerr)
			}
		})
	}
}

// TestTheGateHoldsNoDirectoryCredential is the property the split exists for.
//
// The declaration carries one and the gate is built from the declaration, so
// "it does not hold it" has to be a fact about the type rather than about how
// it is called: [Gate] is a declaration set and a method, and there is no field
// on it a credential could reach.
func TestTheGateHoldsNoDirectoryCredential(t *testing.T) {
	d := newDirectory(t)
	decl := groupDecl(d.url())
	decl.Credential = "Bearer the-directory-secret"

	gateOnly, err := NewGate([]Declaration{decl}, GateConfig{Issuers: gateIssuers()})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	if got := gateOnly.Names(); len(got) != 1 || got[0] != decl.Name {
		t.Fatalf("Names() = %v, want [%s]", got, decl.Name)
	}
	// A gate answers the gate and nothing else. There is no Lookup, no
	// ResolveApprovers and no client on it — the compiler is the assertion for
	// those — so the credential's only reachable trace would be a schema
	// refusal, which is written from the schema's own words.
	err = gateOnly.VerifySchema(&policy.Schema{Sources: []policy.SourceDecl{{
		Name: "release_approvers", Kind: policy.SourceIdPGroup,
		Params:  []policy.Param{{Name: "group", Type: policy.TypeString}},
		Returns: policy.TypeString, OnError: policy.OnErrorDeny,
	}}})
	if err == nil {
		t.Fatal("a schema with the wrong return type was accepted")
	}
	if strings.Contains(err.Error(), "the-directory-secret") {
		t.Fatalf("the refusal carries the directory credential: %v", err)
	}
}

// TestTheGateCannotBeMistakenForAPlane pins the boundary from the other side.
// A gate handed to the evaluator, or to a quorum, would be a plane that has to
// answer a lookup with nothing behind it — so it must not satisfy either seam,
// and a composition root that tried would not compile.
func TestTheGateCannotBeMistakenForAPlane(t *testing.T) {
	var v any = &Gate{}
	if _, ok := v.(engine.SourceResolver); ok {
		t.Error("Gate satisfies engine.SourceResolver; it can resolve nothing")
	}
	if _, ok := v.(challenge.GroupResolver); ok {
		t.Error("Gate satisfies challenge.GroupResolver; it can resolve nobody")
	}
}

func mutateDecl(base Declaration, mutate func(*Declaration)) Declaration {
	out := base
	mutate(&out)
	return out
}
