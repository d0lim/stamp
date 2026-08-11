package runtime

// credentials_test.go is R42's second clause under test: a secret is not
// present where it is not needed.
//
// The assertions come in two shapes. The role→credential rule is a pure
// function and is tested as one, over every role subset rather than the five
// single-role tiers — a deployment may run any combination, and "check plus
// console" must not accidentally hold what neither holds alone. The rest is
// asserted against the assembled process, because the failure this closes was
// not a wrong rule but a composition root that never asked.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/fact/idpgroup"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/stream"
)

// --- the rule ---------------------------------------------------------------

// TestOnlyTheRolesThatUseACredentialHoldIt walks every role subset, not the
// five tiers. A deployment may run any combination of roles, and a rule that
// happened to be right for the five named tiers and wrong for "check,console"
// would be a rule the chart is allowed to be right about by luck.
func TestOnlyTheRolesThatUseACredentialHoldIt(t *testing.T) {
	full := Config{
		ExternalTargets: []challenge.ExternalTarget{{
			Name: "risk", URL: "https://risk.example/hook", Secret: strings.Repeat("k", 32),
		}},
		IngestCredentials: []stream.IngestCredential{{CallerID: "workload:idp#svc-payments"}},
		MFA: MFAConfig{CIBA: CIBAConfig{
			BackchannelEndpoint: "https://idp.example/ciba",
			ClientID:            "stamp-ciba",
			ClientSecret:        "ciba-secret",
		}},
	}

	all := knownRoles()
	for mask := 1; mask < 1<<len(all); mask++ {
		roles := Set{}
		for i, r := range all {
			if mask&(1<<i) != 0 {
				roles[r] = struct{}{}
			}
		}
		t.Run(roles.String(), func(t *testing.T) {
			got := withoutUnusedCredentials(full, roles)

			wantChallenges := roles.Has(RoleDecide) || roles.Has(RoleAPI)
			if held := len(got.ExternalTargets) > 0; held != wantChallenges {
				t.Errorf("holds the external targets = %v, want %v: only a role that can issue a "+
					"challenge presents a target's shared secret", held, wantChallenges)
			}
			if held := got.MFA.CIBA.Configured(); held != wantChallenges {
				t.Errorf("holds the ciba client credentials = %v, want %v", held, wantChallenges)
			}
			if held := len(got.IngestCredentials) > 0; held != roles.Has(RoleConsumer) {
				t.Errorf("holds the ingest grants = %v, want %v: they authenticate a producer "+
					"against the ingest route, which only the consumer role mounts",
					held, roles.Has(RoleConsumer))
			}
			// The declaration documents are never narrowed. Every process loads
			// the policy set at boot and the schema gate refuses a kind no plane
			// answers for, so a tier without them is a tier that cannot start.
			if got.IdPGroupSources == nil && full.IdPGroupSources != nil {
				t.Error("the group source declarations were cleared; the schema gate is built from them")
			}
		})
	}
}

// --- the assembled process --------------------------------------------------

// TestACheckTierHoldsNoCredentialItCannotSpend is #34 stated as an assertion.
//
// The deployment configures all three, exactly as the chart used to hand them
// to every tier. A check process assembled from it holds none.
func TestACheckTierHoldsNoCredentialItCannotSpend(t *testing.T) {
	h := newHarness(t, harnessOptions{
		roles: "check", writerID: "cred-check-writer", mutate: withEveryCredential,
	})

	if got := h.app.cfg.ExternalTargets; len(got) != 0 {
		t.Errorf("the check tier holds %d external target(s); it issues no challenge and signs no webhook", len(got))
	}
	if h.app.cfg.MFA.CIBA.Configured() {
		t.Error("the check tier holds the ciba client secret; it initiates no backchannel authentication")
	}
	if got := h.app.cfg.IngestCredentials; len(got) != 0 {
		t.Errorf("the check tier holds %d ingest grant(s); it mounts no ingest route", len(got))
	}
	// The database side of R39 is what this restores parity with: a check tier
	// already reads its own login. The point of the three above is that the
	// least privilege it buys is no longer handed back through the filesystem.
	if h.app.cfg.MFA.AuthorizationEndpoint == "" {
		t.Error("the step-up endpoint was cleared with the credentials; it is not one")
	}
}

// TestTheTiersThatIssueChallengesHoldTheirCredentials is the other direction,
// and it is the one that keeps the narrowing from being a deployment that
// cannot work.
//
// The api role is here deliberately. Applying a revision revalidates the
// decisions still open under it and re-issues a challenge whose binding moved,
// so an api tier without the targets would fail at the moment a governance
// change landed.
func TestTheTiersThatIssueChallengesHoldTheirCredentials(t *testing.T) {
	for _, role := range []string{"decide", "api"} {
		t.Run(role, func(t *testing.T) {
			h := newHarness(t, harnessOptions{
				roles: role, writerID: "cred-" + role + "-writer", mutate: withEveryCredential,
			})
			if len(h.app.cfg.ExternalTargets) != 1 {
				t.Errorf("the %s tier holds no external target; it can issue an external challenge", role)
			}
			if !h.app.cfg.MFA.CIBA.Configured() {
				t.Errorf("the %s tier holds no ciba client; it can issue an mfa challenge", role)
			}
			if len(h.app.cfg.IngestCredentials) != 0 {
				t.Errorf("the %s tier holds the ingest grants; it mounts no ingest route", role)
			}
		})
	}
}

// TestTheConsumerTierHoldsTheIngestGrants pins the one tier that authenticates
// an event producer.
func TestTheConsumerTierHoldsTheIngestGrants(t *testing.T) {
	h := newHarness(t, harnessOptions{
		roles: "consumer", writerID: "cred-consumer-writer", mutate: withEveryCredential,
	})
	if len(h.app.cfg.IngestCredentials) != 1 {
		t.Error("the consumer tier holds no ingest grant; the ingest route it mounts would authenticate nobody")
	}
	if len(h.app.cfg.ExternalTargets) != 0 {
		t.Error("the consumer tier holds an external target; it issues no challenge")
	}
	if h.app.cfg.MFA.CIBA.Configured() {
		t.Error("the consumer tier holds the ciba client secret")
	}
}

// TestACheckTierNeverBuildsTheCIBAClient is the behavioural half, and the
// counterfactual is the point of it.
//
// The configuration here names a CIBA backchannel and no client secret, which
// [mfa.NewCIBA] refuses outright. A check tier boots on it — because it never
// constructs the client — and a decide tier does not. Without the second
// assertion the first would pass on a deployment where nothing was narrowed at
// all.
func TestACheckTierNeverBuildsTheCIBAClient(t *testing.T) {
	incomplete := func(cfg *Config) {
		cfg.MFA.CIBA = CIBAConfig{
			BackchannelEndpoint: "https://idp.example/ciba",
			ClientID:            "stamp-ciba",
			// No secret. The one the chart mounts on the tiers that issue.
		}
	}

	h := newHarness(t, harnessOptions{
		roles: "check", writerID: "ciba-check-writer", stepUp: true, mutate: incomplete,
	})
	if h.app.cfg.MFA.CIBA.Configured() {
		t.Fatal("the check tier kept the ciba configuration")
	}

	err := tryAssemble(t, "decide", func(cfg *Config) {
		cfg.WriterID = "ciba-decide-writer"
		withStepUp(cfg)
		incomplete(cfg)
	})
	if err == nil {
		t.Fatal("a decide tier assembled with a ciba client that has no secret; " +
			"the check tier's success above proves nothing")
	}
	if !strings.Contains(err.Error(), "client credentials") {
		t.Fatalf("the decide tier failed for some other reason: %v", err)
	}
}

// --- the group plane --------------------------------------------------------

// TestACheckTierResolvesAGroupSource is the limit of the narrowing. The
// directory credential stays on check because check genuinely calls a
// directory: a condition may read a group's membership, and this is that
// condition, judged end to end over the PEP surface.
func TestACheckTierResolvesAGroupSource(t *testing.T) {
	dir := newGroupDirectory(t, map[string][]string{"payers": {"2002", "3003"}})
	h := newHarness(t, harnessOptions{
		roles: "check", writerID: "group-check-writer", mutate: withGroupDirectory(dir),
	})
	if h.app.groups == nil {
		t.Fatal("the check tier has no group plane; it cannot answer a condition that reads one")
	}

	h.seed(groupSchema(), groupMembershipPolicy("group-transfer"))
	pep := h.idp.workload(t, testWorkload)

	allowed, reason, _ := h.evaluate(t, pep, evaluation("1001", "2002", "transfer"))
	if !allowed {
		t.Fatalf("a member of the group was denied (%s)", reason)
	}
	if dir.calls.Load() == 0 {
		t.Fatal("the directory was never called; the answer did not come from it")
	}
	// Presented, not merely configured: the check tier keeps this credential
	// because it is the tier that spends it.
	if got := dir.credential.Load(); got == nil || *got != "Bearer "+groupCredential {
		t.Fatalf("the directory was presented %q, want the configured credential", derefOr(got))
	}

	if allowed, _, _ = h.evaluate(t, pep, evaluation("1001", "9999", "transfer")); allowed {
		t.Fatal("a subject outside the group was allowed")
	}
}

// TestAGateOnlyTierRefusesExactlyWhatACallingTierRefuses is the composition
// root's half of the parity [idpgroup] asserts on its own types.
//
// A consumer tier resolves no group, so it gets the gate. It still has to
// accept the schema a check tier accepts and refuse the schema a check tier
// refuses, because a policy set is installed once for the whole deployment and
// every process loads it.
func TestAGateOnlyTierRefusesExactlyWhatACallingTierRefuses(t *testing.T) {
	dir := newGroupDirectory(t, map[string][]string{"payers": {"2002"}})

	unconfigured := groupSchema()
	unconfigured.Sources = append(unconfigured.Sources, policy.SourceDecl{
		Name:    "other_approvers",
		Kind:    policy.SourceIdPGroup,
		Params:  []policy.Param{{Name: "group", Type: policy.TypeString}},
		Returns: policy.ListOf(policy.TypeString),
		OnError: policy.OnErrorDeny,
	})

	for _, tc := range []struct{ role, writer string }{
		{"check", "gate-parity-check"},
		{"consumer", "gate-parity-consumer"},
		{"console", "gate-parity-console"},
	} {
		t.Run(tc.role, func(t *testing.T) {
			h := newHarness(t, harnessOptions{
				roles: tc.role, writerID: tc.writer, mutate: withGroupDirectory(dir),
			})
			callsIt := callsDirectories(h.app.roles)
			if (h.app.groups != nil) != callsIt {
				t.Fatalf("the %s tier holds a calling group plane = %v, want %v",
					tc.role, h.app.groups != nil, callsIt)
			}

			// The configured source loads on every tier, gate or caller.
			if err := h.trySeed(groupSchema()); err != nil {
				t.Fatalf("the schema naming the configured group source was refused: %v", err)
			}
			// And the unconfigured one is refused on every tier, gate or caller.
			err := h.trySeed(unconfigured)
			if err == nil {
				t.Fatal("a schema naming a group source this deployment does not configure loaded")
			}
			if !errors.Is(err, fact.ErrLoad) {
				t.Fatalf("refusal = %v, want it to wrap %v", err, fact.ErrLoad)
			}
			if !strings.Contains(err.Error(), "other_approvers") {
				t.Errorf("the refusal does not name the source: %v", err)
			}
		})
	}
}

// TestTheSchemaGateCoversEveryKindInEveryRole is the guard on the guard.
//
// snapshot.go's rule is that a plane missing from the gate list is not a laxer
// check for its kind but no check at all, and the credential split moved one of
// those planes. So the list is asserted where it is easiest to get wrong:
// undeclared sources of all three kinds, on a deployment that configures none
// of them, in every role.
func TestTheSchemaGateCoversEveryKindInEveryRole(t *testing.T) {
	kinds := []policy.SourceDecl{
		{
			Name: "unconfigured_http", Kind: policy.SourceHTTP,
			Params:  []policy.Param{{Name: "account", Type: policy.TypeString}},
			Returns: policy.ListOf(policy.TypeString), OnError: policy.OnErrorDeny,
		},
		{
			Name: "unconfigured_event", Kind: policy.SourceEvent,
			Params:  []policy.Param{{Name: "subject", Type: policy.TypeString}},
			Returns: policy.TypeInt, OnError: policy.OnErrorDeny,
		},
		{
			Name: "unconfigured_group", Kind: policy.SourceIdPGroup,
			Params:  []policy.Param{{Name: "group", Type: policy.TypeString}},
			Returns: policy.ListOf(policy.TypeString), OnError: policy.OnErrorDeny,
		},
	}

	for _, role := range []string{"check", "decide", "consumer", "api", "console"} {
		t.Run(role, func(t *testing.T) {
			h := newHarness(t, harnessOptions{
				roles: role, writerID: "gatelist-" + role, noSources: true,
			})
			for _, sd := range kinds {
				schema := tenantSchema()
				schema.Sources = []policy.SourceDecl{sd}
				err := h.trySeed(schema)
				if err == nil {
					t.Errorf("a schema naming an unconfigured %s source loaded on the %s tier",
						sd.Kind, role)
					continue
				}
				if !errors.Is(err, fact.ErrLoad) {
					t.Errorf("%s: refusal = %v, want it to wrap %v", sd.Kind, err, fact.ErrLoad)
				}
				if !strings.Contains(err.Error(), sd.Name) {
					t.Errorf("%s: the refusal does not name the source: %v", sd.Kind, err)
				}
			}
		})
	}
}

// --- fixtures ---------------------------------------------------------------

const groupCredential = "Bearer directory-token"

// withEveryCredential configures all four credential-bearing settings, which is
// what the chart used to hand every tier.
func withEveryCredential(cfg *Config) {
	withStepUp(cfg)
	cfg.ExternalTargets = []challenge.ExternalTarget{{
		Name: "risk", URL: "https://risk.internal.example/hook", Secret: strings.Repeat("k", 32),
	}}
	cfg.MFA.CIBA = CIBAConfig{
		BackchannelEndpoint: "https://idp.internal.example/ciba",
		TokenEndpoint:       "https://idp.internal.example/token",
		ClientID:            "stamp-ciba",
		ClientSecret:        "ciba-client-secret",
	}
	cfg.Egress.Allow = append(cfg.Egress.Allow,
		"https://risk.internal.example", "https://idp.internal.example")
	// The velocity declarations and the grants that spend them are two
	// documents, and the split matters here: the declarations reach every tier
	// because the schema gate is built from them, and the grants reach only the
	// tier that mounts the route they authenticate against.
	withVelocity("workload:nobody#nobody")(cfg)
}

// withStepUp configures the delegated mfa handler against endpoints that are
// never called. It is the surrounding configuration the CIBA block sits in, and
// it has to be present for [Config.validate] to reach the CIBA question at all.
func withStepUp(cfg *Config) {
	cfg.CallbackBaseURL = "https://stamp-callback.example"
	cfg.MFA.AllowedACRValues = []string{testStepUpACR}
	cfg.MFA.AuthorizationEndpoint = "https://idp.internal.example/authorize"
	cfg.MFA.ClientID = "stamp-stepup"
	cfg.MFA.RedirectURI = "https://stamp-callback.example/mfa/return"
}

// groupDirectory is a stub SCIM-shaped group directory that records the
// credential it was presented.
type groupDirectory struct {
	server     *httptest.Server
	calls      atomic.Int64
	credential atomic.Pointer[string]
}

func newGroupDirectory(t *testing.T, groups map[string][]string) *groupDirectory {
	t.Helper()
	d := &groupDirectory{}
	d.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.calls.Add(1)
		auth := r.Header.Get("Authorization")
		d.credential.Store(&auth)
		members := groups[r.URL.Query().Get("group")]
		out := make([]map[string]any, 0, len(members))
		for _, m := range members {
			out = append(out, map[string]any{"value": m})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"members": out, "totalResults": len(out),
		})
	}))
	t.Cleanup(d.server.Close)
	return d
}

// withGroupDirectory declares one group source against the stub.
func withGroupDirectory(d *groupDirectory) func(*Config) {
	return func(cfg *Config) {
		cfg.Egress.Allow = append(cfg.Egress.Allow, d.server.URL)
		cfg.IdPGroupSources = []idpgroup.Declaration{{
			Name:       "payer_group",
			Issuer:     cfg.OIDC.Issuers[0].Issuer,
			URL:        d.server.URL + "/Groups",
			Credential: groupCredential,
			TTL:        time.Minute,
			Timeout:    2 * time.Second,
			Params:     []policy.Param{{Name: "group", Type: policy.TypeString}},
			Returns:    policy.ListOf(policy.TypeString),
			OnError:    policy.OnErrorDeny,
		}}
	}
}

func derefOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func groupSchema() *policy.Schema {
	schema := tenantSchema()
	schema.Sources = append(schema.Sources, policy.SourceDecl{
		Name:    "payer_group",
		Kind:    policy.SourceIdPGroup,
		Params:  []policy.Param{{Name: "group", Type: policy.TypeString}},
		Returns: policy.ListOf(policy.TypeString),
		OnError: policy.OnErrorDeny,
	})
	return schema
}

// groupMembershipPolicy allows a transfer when the destination account is in
// the directory group. It is a condition that reads a group source, which is
// the reason the check tier keeps the directory credential.
func groupMembershipPolicy(id string) *policy.Policy {
	return &policy.Policy{
		ID:       id,
		Subject:  "account",
		Resource: "account",
		Actions:  []string{"transfer"},
		Condition: policy.Member{
			Left:       policy.Field(policy.RoleResource, "number"),
			Collection: policy.Source("payer_group", policy.String("payers")),
		},
	}
}

// tryAssemble builds a process and reports what happened, for the assertions
// where refusing to boot is the answer. It does not serve: the question is
// whether the graph can be constructed at all.
func tryAssemble(t *testing.T, roleSpec string, mutate func(*Config)) error {
	t.Helper()
	idp := newMockIdP(t)
	cfg := Config{
		DSN:         freshDB(t),
		MaxConns:    8,
		Migrate:     true,
		ApplyGrants: true,
		InstanceID:  "assemble",
		WriterID:    "assemble-" + roleSpec,
		Addresses: map[api.Surface]string{
			api.SurfacePEP:      "127.0.0.1:0",
			api.SurfaceConsole:  "127.0.0.1:0",
			api.SurfaceCallback: "127.0.0.1:0",
		},
		OIDC: OIDCConfig{
			Issuers: []IssuerConfig{{
				Issuer:          idp.server.URL,
				JWKSURL:         idp.server.URL + "/jwks",
				WorkloadClients: []string{testWorkload},
			}},
			Audience:               testAudience,
			Algorithms:             []string{"RS256"},
			AllowInsecureTransport: true,
		},
		Egress:          fact.EgressConfig{AllowLoopback: true},
		AuditFailClosed: true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	roles, err := ParseRoles(roleSpec)
	if err != nil {
		t.Fatalf("parse roles %q: %v", roleSpec, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app, err := Assemble(ctx, cfg, roles, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if app != nil {
		app.Close()
	}
	return err
}
