package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/policy"
)

// clearEnv unsets every variable the configuration reads, so a test starts from
// a known environment rather than from the developer's shell.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		EnvDSN, EnvMaxConns, EnvMigrate, EnvApplyGrants,
		EnvRoleCheck, EnvRoleDecide, EnvRoleConsume, EnvRoleAdmin,
		EnvInstanceID, EnvWriterID,
		EnvPEPAddr, EnvConsoleAddr, EnvCallbackAddr,
		EnvOIDCIssuer, EnvOIDCJWKSURL, EnvOIDCAudience, EnvOIDCWorkloadClients,
		EnvOIDCAlgorithms, EnvOIDCACRValues, EnvOIDCAllowInsecure,
		EnvFactSources, EnvEgressAllow, EnvEgressLoopback, EnvEgressPrivate, EnvFactAllowFailOpen,
		EnvAuditFailClosed, EnvAuditCapacity, EnvAuditBatchSize, EnvAuditFlushInterval,
		EnvPolicyRefreshInterval, EnvPolicyStalenessDeadline,
		EnvDecisionTTL, EnvMaxOutstanding,
		EnvFloorMinApprovers, EnvFloorProposerMayApprove,
		EnvRevisionTTL, EnvReconcileInterval, EnvBootstrapWarnInterval,
		EnvCheckContextEntity, EnvCheckPropertyAliases,
		EnvExternalTargets, EnvCallbackBaseURL,
		EnvMFAACRValues, EnvMFARequiredAMR, EnvMFAAuthzEndpoint, EnvMFAClientID,
		EnvMFARedirectURI, EnvMFAScopes, EnvMFAIssuer, EnvMFATokenClientID,
		EnvMFAAudience, EnvMFAAllowInsecure,
		EnvCIBABackchannel, EnvCIBATokenURL, EnvCIBAClientID, EnvCIBAClientSecret, EnvCIBAScope,
	} {
		t.Setenv(key, "")
		_ = os.Unsetenv(key)
	}
}

func TestConfigFromEnvReportsEveryMissingRequirementAtOnce(t *testing.T) {
	clearEnv(t)
	_, err := ConfigFromEnv()
	if err == nil {
		t.Fatal("an empty environment produced a configuration, want a failure")
	}
	// An operator filling in a manifest should learn about all of them at once
	// rather than restarting the container three times.
	for _, want := range []string{EnvDSN, EnvOIDCIssuer, EnvOIDCAudience} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %s:\n%v", want, err)
		}
	}
}

func TestConfigFromEnvReadsADeployment(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvDSN, "postgres://stamp@localhost/stamp")
	t.Setenv(EnvOIDCIssuer, "https://idp.example")
	t.Setenv(EnvOIDCJWKSURL, "https://idp.example/jwks")
	t.Setenv(EnvOIDCAudience, "stamp")
	t.Setenv(EnvOIDCWorkloadClients, "pep-1, pep-2")
	t.Setenv(EnvCallbackAddr, ":9090")
	t.Setenv(EnvEgressAllow, "https://facts.example")
	t.Setenv(EnvCheckPropertyAliases, "ownerID=owner_id")
	t.Setenv(EnvPolicyRefreshInterval, "2s")
	t.Setenv(EnvFloorMinApprovers, "2")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if got := cfg.Addresses[api.SurfacePEP]; got != DefaultPEPAddr {
		t.Errorf("pep address = %q, want the default %q", got, DefaultPEPAddr)
	}
	if got := cfg.Addresses[api.SurfaceCallback]; got != ":9090" {
		t.Errorf("callback address = %q, want :9090", got)
	}
	if len(cfg.OIDC.Issuers) != 1 || cfg.OIDC.Issuers[0].Issuer != "https://idp.example" {
		t.Errorf("issuers = %+v", cfg.OIDC.Issuers)
	}
	if got := cfg.OIDC.Issuers[0].WorkloadClients; len(got) != 2 || got[1] != "pep-2" {
		t.Errorf("workload clients = %v, want the whitespace trimmed", got)
	}
	if !cfg.AuditFailClosed {
		t.Error("the audit buffer defaults to fail-open, want fail-closed")
	}
	if cfg.AllowFactFailOpen {
		t.Error("fact sources default to permitting fail-open, want the operator flag to be required")
	}
	if cfg.Egress.AllowLoopback || cfg.Egress.AllowPrivate {
		t.Error("egress defaults admit loopback or private ranges")
	}
	if cfg.CheckPropertyAliases["ownerID"] != "owner_id" {
		t.Errorf("aliases = %v", cfg.CheckPropertyAliases)
	}
	if cfg.PolicyRefreshInterval != 2*time.Second {
		t.Errorf("refresh interval = %v, want 2s", cfg.PolicyRefreshInterval)
	}
	if cfg.GovernanceFloor.MinApprovers != 2 {
		t.Errorf("operator floor = %d, want 2", cfg.GovernanceFloor.MinApprovers)
	}
}

func TestConfigFromEnvUnbindsASurfaceSetToNothing(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvDSN, "postgres://stamp@localhost/stamp")
	t.Setenv(EnvOIDCIssuer, "https://idp.example")
	t.Setenv(EnvOIDCJWKSURL, "https://idp.example/jwks")
	t.Setenv(EnvOIDCAudience, "stamp")
	t.Setenv(EnvConsoleAddr, " ")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	// A blank address is not a default: it is how a PEP tier runs with no
	// console reachable anywhere.
	if _, bound := cfg.Addresses[api.SurfaceConsole]; bound {
		t.Errorf("the console surface is bound to %q, want it unbound", cfg.Addresses[api.SurfaceConsole])
	}
}

func TestFactSourcesRead(t *testing.T) {
	const doc = `[{
		"name": "account_whitelist",
		"kind": "http",
		"params": [{"name": "account", "type": "string"}],
		"returns": "list<string>",
		"on_error": "deny",
		"ttl": "5m",
		"timeout": "2s",
		"url": "https://facts.example/whitelist"
	}]`

	path := filepath.Join(t.TempDir(), "sources.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write declarations: %v", err)
	}

	// A container mounts a file and a laptop pastes a literal; both are read.
	for name, spec := range map[string]string{"inline": doc, "file": path} {
		decls, err := factSourcesFrom(spec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(decls) != 1 {
			t.Fatalf("%s: %d declarations, want 1", name, len(decls))
		}
		d := decls[0]
		if d.Name != "account_whitelist" || d.Kind != policy.SourceHTTP {
			t.Errorf("%s: declaration = %+v", name, d)
		}
		if d.Returns != policy.ListOf(policy.TypeString) {
			t.Errorf("%s: returns = %q", name, d.Returns)
		}
		if d.TTL != 5*time.Minute || d.Timeout != 2*time.Second {
			t.Errorf("%s: ttl = %v, timeout = %v", name, d.TTL, d.Timeout)
		}
		if len(d.Params) != 1 || d.Params[0].Type != policy.TypeString {
			t.Errorf("%s: params = %+v", name, d.Params)
		}
	}
}

func TestFactSourcesRejectAnUnknownField(t *testing.T) {
	// A misspelled key is a source that would silently lose its TTL or its
	// call target, so it is refused rather than ignored.
	if _, err := factSourcesFrom(`[{"name":"x","kind":"static","returns":"string","tll":"5m"}]`); err == nil {
		t.Fatal("a declaration with an unknown field was accepted")
	}
}

func TestWriterIDFor(t *testing.T) {
	cases := map[string]string{
		"stamp-check-7d9f-abc": "stamp-check-7d9f-abc",
		"host name":            "host-name",
		"---":                  "stamp",
		"":                     "stamp",
	}
	for in, want := range cases {
		if got := writerIDFor(in); got != want {
			t.Errorf("writerIDFor(%q) = %q, want %q", in, got, want)
		}
	}
	if got := writerIDFor(strings.Repeat("a", 100)); len(got) != 64 {
		t.Errorf("a long instance name produced a %d character writer id, want it capped at 64", len(got))
	}
}

// ---------------------------------------------------------------------------
// the M2 challenge configuration
// ---------------------------------------------------------------------------

func TestExternalTargetsAreReadFromTheEnvironment(t *testing.T) {
	doc := `[{"name":"reviewer","url":"https://reviewer.example/hook",
	           "secret":"0123456789abcdef0123456789abcdef","timeout":"3s","respond_within":"10m"}]`
	targets, err := externalTargetsFrom(doc)
	if err != nil {
		t.Fatalf("read external targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("read %d targets, want 1", len(targets))
	}
	got := targets[0]
	if got.Name != "reviewer" || got.URL != "https://reviewer.example/hook" {
		t.Errorf("target = %+v", got)
	}
	if got.Timeout != 3*time.Second || got.RespondWithin != 10*time.Minute {
		t.Errorf("timeout = %v, respond_within = %v", got.Timeout, got.RespondWithin)
	}
}

func TestExternalTargetsRejectAnUnknownField(t *testing.T) {
	// A misspelled key is a target that silently loses its secret or its
	// deadline, so it is refused rather than ignored.
	if _, err := externalTargetsFrom(`[{"name":"x","url":"https://x.example","secrat":"y"}]`); err == nil {
		t.Fatal("a target with an unknown field was accepted")
	}
}

// U10's first trap, as a configuration rule: the allowlist is the only defence
// the delegated handler has, so asking for the handler without one fails the
// boot instead of producing a handler whose one real check does not run.
func TestDelegatedMFANeedsAnACRAllowlist(t *testing.T) {
	cfg := baseConfig()
	cfg.MFA = MFAConfig{
		AuthorizationEndpoint: "https://idp.example/authorize",
		ClientID:              "stamp-console",
		RedirectURI:           "https://stamp.example/callback",
	}
	err := cfg.validate()
	if err == nil {
		t.Fatal("a delegated mfa handler with no acr allowlist was accepted")
	}
	if !strings.Contains(err.Error(), EnvMFAACRValues) {
		t.Errorf("the error does not name %s:\n%v", EnvMFAACRValues, err)
	}
}

// U10's second trap. The process-wide allowlist bounds every end-user token, so
// a step-up class outside it is rejected by token verification before the mfa
// handler ever sees the completion — which looks like a credential failure and
// not like a challenge failure.
func TestStepUpClassesMustBeAdmittedByTheProcessWideAllowlist(t *testing.T) {
	cfg := baseConfig()
	cfg.OIDC.AllowedACRValues = []string{"aal1"}
	cfg.MFA = MFAConfig{
		AllowedACRValues:      []string{"aal2"},
		AuthorizationEndpoint: "https://idp.example/authorize",
		ClientID:              "stamp-console",
		RedirectURI:           "https://stamp.example/callback",
	}
	err := cfg.validate()
	if err == nil {
		t.Fatal("a step-up class outside the process-wide allowlist was accepted")
	}
	if !strings.Contains(err.Error(), EnvOIDCACRValues) {
		t.Errorf("the error does not name %s:\n%v", EnvOIDCACRValues, err)
	}

	// The superset is fine, and so is the empty process-wide allowlist, which
	// means "no bound" rather than "no classes".
	cfg.OIDC.AllowedACRValues = []string{"aal1", "aal2"}
	if err := cfg.validate(); err != nil {
		t.Fatalf("a superset allowlist was refused: %v", err)
	}
	cfg.OIDC.AllowedACRValues = nil
	if err := cfg.validate(); err != nil {
		t.Fatalf("an unbounded process-wide allowlist was refused: %v", err)
	}
}

// A deployment that configures no step-up at all is valid: the mfa kind simply
// has no handler, which is fail-closed rather than permissive.
func TestNoMFAConfigurationIsValid(t *testing.T) {
	if err := baseConfig().validate(); err != nil {
		t.Fatalf("a deployment with no delegated mfa was refused: %v", err)
	}
	if baseConfig().MFA.Configured() {
		t.Error("an empty MFAConfig reports itself configured")
	}
}

// baseConfig is the smallest configuration that validates.
func baseConfig() Config {
	return Config{
		DSN:       "postgres://stamp@localhost/stamp",
		Addresses: map[api.Surface]string{api.SurfacePEP: ":8080"},
		OIDC: OIDCConfig{
			Issuers:  []IssuerConfig{{Issuer: "https://idp.example", JWKSURL: "https://idp.example/jwks"}},
			Audience: "stamp",
		},
	}
}
