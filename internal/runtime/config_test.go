package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/stream"
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
		EnvAuditAlertThreshold,
		EnvCheckpointKeyFile, EnvCheckpointKeyID, EnvCheckpointVerifyKeys,
		EnvCheckpointSinkFile, EnvCheckpointSinkWebhook, EnvCheckpointInterval,
		EnvPolicyRefreshInterval, EnvPolicyStalenessDeadline,
		EnvDecisionTTL, EnvMaxOutstanding,
		EnvDecideRate, EnvDecideBurst, EnvDecideSubjectRate, EnvDecideSubjectRateBurst,
		EnvChallengeIssueRate, EnvChallengeIssueBurst,
		EnvChallengeIssueCeilingRate, EnvChallengeIssueCeilingBurst,
		EnvApprovalRate, EnvApprovalBurst,
		EnvCancellationRate, EnvCancellationBurst,
		EnvFloorMinApprovers, EnvFloorProposerMayApprove,
		EnvRevisionTTL, EnvReconcileInterval, EnvBootstrapWarnInterval,
		EnvAuthoringMode, EnvCapabilityClaim,
		EnvRevisionRateWindow, EnvRevisionRateBurst,
		EnvApplyMaxDocuments, EnvApplyMaxDocumentBytes, EnvApplyMaxTotalBytes,
		EnvApplyMaxPolicies, EnvApplyMaxConditionNodes, EnvApplyMaxConditionDepth,
		EnvCheckContextEntity, EnvCheckPropertyAliases,
		EnvExternalTargets, EnvCallbackBaseURL,
		EnvMFAACRValues, EnvMFARequiredAMR, EnvMFAAuthzEndpoint, EnvMFAClientID,
		EnvMFARedirectURI, EnvMFAScopes, EnvMFAIssuer, EnvMFATokenClientID,
		EnvMFAAudience, EnvMFAAllowInsecure, EnvMFATokenEndpoint, EnvMFAClientSecret,
		EnvCIBABackchannel, EnvCIBATokenURL, EnvCIBAClientID, EnvCIBAClientSecret, EnvCIBAScope,
		EnvStreamSources, EnvIngestCredentials, EnvIngestAdapterName,
		EnvIngestRate, EnvIngestBurst, EnvIngestSubjectRate, EnvIngestSubjectBurst,
		EnvIngestMaxBatch, EnvIngestMaxBytes,
		EnvKafkaBrokers, EnvKafkaGroup, EnvKafkaTopics, EnvKafkaAdapterName, EnvKafkaPollRecords,
		EnvRetentionSweepInterval,
		EnvIdPGroupSources, EnvIdPGroupMaxTTL, EnvApproverIssuer,
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

// TestAuditAlertThresholdIsReadFromTheEnvironment is R32's sensitivity arriving
// on the deployment surface. What it does once it gets there is
// TestAuditAlertThresholdMovesWhenTheLossAlertFires.
func TestAuditAlertThresholdIsReadFromTheEnvironment(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvDSN, "postgres://stamp@localhost/stamp")
	t.Setenv(EnvOIDCIssuer, "https://idp.example")
	t.Setenv(EnvOIDCJWKSURL, "https://idp.example/jwks")
	t.Setenv(EnvOIDCAudience, "stamp")

	t.Run("an unset variable takes the api package's default", func(t *testing.T) {
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("ConfigFromEnv: %v", err)
		}
		if cfg.AuditAlertThreshold != 0 {
			t.Errorf("threshold = %d with nothing set, want 0 so the buffer selects its own default of %d",
				cfg.AuditAlertThreshold, api.DefaultAuditAlertThreshold)
		}
	})

	t.Run("a raised threshold is read", func(t *testing.T) {
		t.Setenv(EnvAuditAlertThreshold, "512")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("ConfigFromEnv: %v", err)
		}
		if cfg.AuditAlertThreshold != 512 {
			t.Errorf("threshold = %d, want 512", cfg.AuditAlertThreshold)
		}
	})
}

// TestAuditAlertThresholdRefusesAValueItCannotMean is the boot failure.
//
// Both refusals are the same argument: an operator who wrote this variable down
// is trying to move the sensitivity, and every alternative to refusing leaves
// them with the default and no indication that their setting did nothing. That
// is the state this unit exists to end, so resolving a bad value into the
// default here would be reintroducing it at the parser.
func TestAuditAlertThresholdRefusesAValueItCannotMean(t *testing.T) {
	for _, raw := range []string{"0", "-1", "-4096", "one", "3.5", "1e3"} {
		t.Run(raw, func(t *testing.T) {
			clearEnv(t)
			t.Setenv(EnvDSN, "postgres://stamp@localhost/stamp")
			t.Setenv(EnvOIDCIssuer, "https://idp.example")
			t.Setenv(EnvOIDCJWKSURL, "https://idp.example/jwks")
			t.Setenv(EnvOIDCAudience, "stamp")
			t.Setenv(EnvAuditAlertThreshold, raw)

			_, err := ConfigFromEnv()
			if err == nil {
				t.Fatalf("%s=%q produced a configuration, want a startup failure", EnvAuditAlertThreshold, raw)
			}
			if !strings.Contains(err.Error(), EnvAuditAlertThreshold) {
				t.Errorf("the refusal does not name %s, so an operator cannot find it:\n%v",
					EnvAuditAlertThreshold, err)
			}
		})
	}
}

// TestAuditAlertThresholdIsValidatedOnAConfigBuiltInCode covers the path that
// does not pass through the environment reader at all: an embedder, or a test,
// handing Assemble a Config directly.
func TestAuditAlertThresholdIsValidatedOnAConfigBuiltInCode(t *testing.T) {
	base := Config{
		DSN:       "postgres://stamp@localhost/stamp",
		Addresses: map[api.Surface]string{api.SurfacePEP: "127.0.0.1:0"},
		OIDC: OIDCConfig{
			Issuers:  []IssuerConfig{{Issuer: "https://idp.example", JWKSURL: "https://idp.example/jwks"}},
			Audience: "stamp",
		},
	}
	if err := base.withDefaults().validate(everyRole()); err != nil {
		t.Fatalf("the baseline configuration is already invalid, so this test proves nothing: %v", err)
	}

	negative := base
	negative.AuditAlertThreshold = -1
	err := negative.withDefaults().validate(everyRole())
	if err == nil {
		t.Fatal("a negative alert threshold validated, want a startup failure")
	}
	if !strings.Contains(err.Error(), EnvAuditAlertThreshold) {
		t.Errorf("the refusal does not name %s:\n%v", EnvAuditAlertThreshold, err)
	}
}

// TestConfigFromEnvReadsTheFileAuthoringSurface is the environment half of M4's
// wiring: every one of these knobs has a package default that is correct, which
// is precisely why an unread variable is invisible — the deployment behaves
// well and the operator's setting does nothing at all.
func TestConfigFromEnvReadsTheFileAuthoringSurface(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvDSN, "postgres://stamp@localhost/stamp")
	t.Setenv(EnvOIDCIssuer, "https://idp.example")
	t.Setenv(EnvOIDCJWKSURL, "https://idp.example/jwks")
	t.Setenv(EnvOIDCAudience, "stamp")

	t.Run("unset leaves every field zero, which is the package default", func(t *testing.T) {
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("ConfigFromEnv: %v", err)
		}
		if cfg.AuthoringMode != revision.AuthoringBoth {
			t.Errorf("authoring mode = %q, want %q", cfg.AuthoringMode, revision.AuthoringBoth)
		}
		// Empty and not the claim name itself: the resolution belongs to
		// [revision.ClaimCapabilities], so that a deployment and the package
		// cannot come to hold two different ideas of what the default is.
		if cfg.CapabilityClaim != "" {
			t.Errorf("capability claim = %q, want it left to the package default", cfg.CapabilityClaim)
		}
		if (cfg.RevisionRate != revision.Rate{}) {
			t.Errorf("revision rate = %+v, want the zero value", cfg.RevisionRate)
		}
		if (cfg.ApplyLimits != revision.PayloadLimits{}) {
			t.Errorf("apply limits = %+v, want the zero value", cfg.ApplyLimits)
		}
	})

	t.Run("every variable reaches its field", func(t *testing.T) {
		t.Setenv(EnvAuthoringMode, string(revision.AuthoringFile))
		t.Setenv(EnvCapabilityClaim, "entitlements")
		t.Setenv(EnvRevisionRateWindow, "5m")
		t.Setenv(EnvRevisionRateBurst, "3")
		t.Setenv(EnvApplyMaxDocuments, "11")
		t.Setenv(EnvApplyMaxDocumentBytes, "22")
		t.Setenv(EnvApplyMaxTotalBytes, "33")
		t.Setenv(EnvApplyMaxPolicies, "44")
		t.Setenv(EnvApplyMaxConditionNodes, "55")
		t.Setenv(EnvApplyMaxConditionDepth, "66")

		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("ConfigFromEnv: %v", err)
		}
		if cfg.AuthoringMode != revision.AuthoringFile {
			t.Errorf("authoring mode = %q, want %q", cfg.AuthoringMode, revision.AuthoringFile)
		}
		if cfg.CapabilityClaim != "entitlements" {
			t.Errorf("capability claim = %q, want entitlements", cfg.CapabilityClaim)
		}
		if want := (revision.Rate{Window: 5 * time.Minute, Burst: 3}); cfg.RevisionRate != want {
			t.Errorf("revision rate = %+v, want %+v", cfg.RevisionRate, want)
		}
		want := revision.PayloadLimits{
			MaxDocuments: 11, MaxDocumentBytes: 22, MaxTotalBytes: 33,
			MaxPolicies: 44, MaxConditionNodes: 55, MaxConditionDepth: 66,
		}
		if cfg.ApplyLimits != want {
			t.Errorf("apply limits = %+v, want %+v", cfg.ApplyLimits, want)
		}
	})
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
	cfg := stepUpBaseConfig()
	cfg.MFA = MFAConfig{
		AuthorizationEndpoint: "https://idp.example/authorize",
		TokenEndpoint:         "https://idp.example/token",
		ClientID:              "stamp-console",
		RedirectURI:           "https://stamp.example/callback",
	}
	err := cfg.validate(everyRole())
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
	cfg := stepUpBaseConfig()
	cfg.OIDC.AllowedACRValues = []string{"aal1"}
	cfg.MFA = MFAConfig{
		AllowedACRValues:      []string{"aal2"},
		AuthorizationEndpoint: "https://idp.example/authorize",
		TokenEndpoint:         "https://idp.example/token",
		ClientID:              "stamp-console",
		RedirectURI:           "https://stamp.example/callback",
	}
	err := cfg.validate(everyRole())
	if err == nil {
		t.Fatal("a step-up class outside the process-wide allowlist was accepted")
	}
	if !strings.Contains(err.Error(), EnvOIDCACRValues) {
		t.Errorf("the error does not name %s:\n%v", EnvOIDCACRValues, err)
	}

	// The superset is fine, and so is the empty process-wide allowlist, which
	// means "no bound" rather than "no classes".
	cfg.OIDC.AllowedACRValues = []string{"aal1", "aal2"}
	if err := cfg.validate(everyRole()); err != nil {
		t.Fatalf("a superset allowlist was refused: %v", err)
	}
	cfg.OIDC.AllowedACRValues = nil
	if err := cfg.validate(everyRole()); err != nil {
		t.Fatalf("an unbounded process-wide allowlist was refused: %v", err)
	}
}

// U2's trap, and the one #41 was made of: a step-up with nowhere to redeem its
// code is a challenge that can be opened and never completed. It fails the boot
// rather than the moment somebody has finished authenticating and is waiting for
// a page.
func TestDelegatedMFANeedsSomewhereToRedeemTheCode(t *testing.T) {
	cfg := stepUpBaseConfig()
	cfg.MFA = MFAConfig{
		AllowedACRValues:      []string{"aal2"},
		AuthorizationEndpoint: "https://idp.example/authorize",
		ClientID:              "stamp-console",
		RedirectURI:           "https://stamp.example/callback",
	}
	err := cfg.validate(everyRole())
	if err == nil {
		t.Fatal("a step-up with no token endpoint was accepted")
	}
	if !strings.Contains(err.Error(), EnvMFATokenEndpoint) {
		t.Errorf("the error does not name %s:\n%v", EnvMFATokenEndpoint, err)
	}
	cfg.MFA.TokenEndpoint = "https://idp.example/token"
	if err := cfg.validate(everyRole()); err != nil {
		t.Fatalf("a complete step-up configuration was refused: %v", err)
	}
	// R42: the secret is a path, never a value. A public client — which is what
	// a step-up client normally is — names none at all.
	if cfg.MFA.ClientSecretFile != "" {
		t.Error("a client secret file is required where PKCE is the proof")
	}
}

// A deployment that configures no step-up at all is valid: the mfa kind simply
// has no handler, which is fail-closed rather than permissive.
func TestNoMFAConfigurationIsValid(t *testing.T) {
	if err := baseConfig().validate(everyRole()); err != nil {
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

// stepUpBaseConfig is baseConfig with the callback surface bound.
//
// The three step-up tests above ask whether the delegated MFA settings are
// coherent among themselves. Since [Config.surfaceRequirements] a step-up also
// needs the listener its completion comes back on, so leaving it unbound would
// make each of those configurations invalid for a second reason and let a test
// pass on the wrong error. Binding it keeps every one of them on its own
// question; the unbound case has its own tests below.
func stepUpBaseConfig() Config {
	cfg := baseConfig()
	cfg.Addresses[api.SurfaceCallback] = ":8082"
	return cfg
}

// everyRole is what --roles=all resolves to. Validation is per role only on the
// surface axis, so a test that is not about roles takes the widest set — the
// one that mounts every route and can therefore strand any of them.
func everyRole() Set {
	set := Set{}
	for _, r := range knownRoles() {
		set[r] = struct{}{}
	}
	return set
}

// ---------------------------------------------------------------------------
// the callback surface cross-check
//
// Until this section existed the chart was the only guard: `helm template`
// refused a release that configured what completes on the callback surface and
// bound no listener, and `stamp --roles=all` with the same settings started and
// reported itself healthy. The demo runs on docker-compose and a developer runs
// the binary, so the one guard covered neither.
// ---------------------------------------------------------------------------

// roleSet is ParseRoles for a test, which has a literal spec and no reason to
// carry its error.
func roleSet(t *testing.T, spec string) Set {
	t.Helper()
	set, err := ParseRoles(spec)
	if err != nil {
		t.Fatalf("parse roles %q: %v", spec, err)
	}
	return set
}

// withStepUpSettings, withExternalTarget and withIngestGrant are the three
// settings the guard triggers on, each applied on its own so that a refusal can
// be attributed to one of them.
func withStepUpSettings(cfg *Config) {
	cfg.CallbackBaseURL = "https://stamp.example/callback"
	cfg.MFA = MFAConfig{
		AllowedACRValues:      []string{"aal2"},
		AuthorizationEndpoint: "https://idp.example/authorize",
		ClientID:              "stamp-stepup",
		RedirectURI:           "https://stamp.example/callback/mfa",
		TokenEndpoint:         "https://idp.example/token",
	}
}

func withExternalTarget(cfg *Config) {
	cfg.ExternalTargets = []challenge.ExternalTarget{{
		Name: "risk", URL: "https://risk.example/hook", Secret: strings.Repeat("k", 32),
	}}
}

func withIngestGrant(cfg *Config) {
	cfg.IngestCredentials = []stream.IngestCredential{{CallerID: "workload:https://idp.example#svc-payments"}}
}

// TestAFeatureThatCompletesOnTheCallbackSurfaceNeedsItBound is the check itself,
// one feature at a time.
//
// Each of the three completes on the callback surface and on no other, so each
// of them alone is enough to make an unbound listener a deployment that cannot
// finish what it starts. The paired "bound" case is what keeps this from being
// a check that refuses everything.
func TestAFeatureThatCompletesOnTheCallbackSurfaceNeedsItBound(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*Config)
		// env is the variable the refusal has to name, because it is the one an
		// operator would go and look at.
		env string
		// route is the path that becomes unreachable, which is the part that
		// says what is actually lost.
		route string
	}{
		{
			name: "delegated step-up mfa", configure: withStepUpSettings,
			env: EnvMFAAuthzEndpoint, route: "/decisions/{id}/challenges/{ordinal}/mfa",
		},
		{
			name: "external challenge targets", configure: withExternalTarget,
			env: EnvExternalTargets, route: "/external/{id}/{ordinal}",
		},
		{
			name: "http velocity ingest", configure: withIngestGrant,
			env: EnvIngestCredentials, route: "/ingest/v1/events",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			tc.configure(&cfg)

			err := cfg.validate(everyRole())
			if err == nil {
				t.Fatalf("%s with no callback listener was accepted: the route it completes on is "+
					"mounted on a surface nothing binds", tc.name)
			}
			for _, want := range []string{EnvCallbackAddr, tc.env, tc.route, EnvCallbackBaseURL} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not name %q:\n%v", want, err)
				}
			}

			// The same configuration with the listener bound is the deployment
			// an operator meant, and it validates.
			cfg.Addresses[api.SurfaceCallback] = ":8082"
			if err := cfg.validate(everyRole()); err != nil {
				t.Fatalf("%s with the callback listener bound was refused: %v", tc.name, err)
			}
		})
	}
}

// A refusal names every stranded setting rather than the first one it found: an
// operator who cleared one and restarted would otherwise learn about the second
// on the next boot and the third on the one after.
func TestTheRefusalNamesEveryStrandedSetting(t *testing.T) {
	cfg := baseConfig()
	withStepUpSettings(&cfg)
	withExternalTarget(&cfg)
	withIngestGrant(&cfg)

	err := cfg.validate(everyRole())
	if err == nil {
		t.Fatal("a deployment that stranded all three was accepted")
	}
	for _, want := range []string{EnvMFAAuthzEndpoint, EnvExternalTargets, EnvIngestCredentials} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal stops before naming %s:\n%v", want, err)
		}
	}

	cfg.Addresses[api.SurfaceCallback] = ":8082"
	if err := cfg.validate(everyRole()); err != nil {
		t.Fatalf("all three with the listener bound was refused: %v", err)
	}
}

// The default install binds no callback listener and configures none of the
// three, and it has to keep starting. The unbound default is R39's decision —
// the callback surface is the one a deployment may have to publish past its own
// perimeter, so it is opted into — and a check that made "unbound" itself an
// error would have reversed that decision rather than enforced it.
func TestNothingOnTheCallbackSurfaceNeedsNoCallbackListener(t *testing.T) {
	if err := baseConfig().validate(everyRole()); err != nil {
		t.Fatalf("the default deployment was refused: %v", err)
	}
	if _, bound := baseConfig().Addresses[api.SurfaceCallback]; bound {
		t.Error("the base configuration binds a callback listener, so this test proves nothing")
	}
}

// TestARoleThatMountsNoCallbackRouteIsNotRefused is the gate that keeps this
// check from breaking legitimate deployments.
//
// A process that runs neither decide nor consumer mounts no callback route, so
// none of the three settings is stranded *in it* even when they are all
// configured — and they are legitimately configured there: an api tier holds
// the external targets because applying a revision re-issues challenges
// (issuesChallenges), and one deployment's environment is usually one document
// handed to every tier. Refusing those tiers would refuse the split topology
// the chart renders.
func TestARoleThatMountsNoCallbackRouteIsNotRefused(t *testing.T) {
	strand := func() Config {
		cfg := baseConfig()
		withStepUpSettings(&cfg)
		withExternalTarget(&cfg)
		withIngestGrant(&cfg)
		return cfg
	}

	for _, spec := range []string{"check", "api", "console", "check,api,console"} {
		t.Run(spec, func(t *testing.T) {
			if err := strand().validate(roleSet(t, spec)); err != nil {
				t.Fatalf("--roles=%s mounts no callback route and was refused anyway: %v", spec, err)
			}
		})
	}

	// And the two that do mount one are refused, each for what it mounts and
	// not for what the other does. A consumer tier is not refused for a step-up
	// it does not serve the return of, and a decide tier is not refused for an
	// ingest route it does not mount — otherwise the gate would be decoration.
	t.Run("decide", func(t *testing.T) {
		err := strand().validate(roleSet(t, "decide"))
		if err == nil {
			t.Fatal("the decide role mounts the mfa and external returns and was not refused")
		}
		if strings.Contains(err.Error(), EnvIngestCredentials) {
			t.Errorf("the decide role was refused for the ingest route, which only the consumer "+
				"role mounts:\n%v", err)
		}
	})
	t.Run("consumer", func(t *testing.T) {
		err := strand().validate(roleSet(t, "consumer"))
		if err == nil {
			t.Fatal("the consumer role mounts the ingest route and was not refused")
		}
		for _, unwanted := range []string{EnvMFAAuthzEndpoint, EnvExternalTargets} {
			if strings.Contains(err.Error(), unwanted) {
				t.Errorf("the consumer role was refused for %s, whose route only the decide role "+
					"mounts:\n%v", unwanted, err)
			}
		}
	})
}

// CIBA is backchannel and needs no browser redirect, so it is not a trigger.
//
// It reaches the guard anyway, and this test is the reason the comment on
// surfaceRequirements can say so: [MFAConfig.validate] requires the four
// step-up variables whenever any MFA is configured, and Configured is true of a
// CIBA-only deployment. So a CIBA-only configuration cannot reach a passing
// validate without an authorization endpoint, and once it has one it is refused
// here like any other step-up. Both halves are asserted, because the claim is
// only true while the first one holds.
func TestACIBAOnlyDeploymentReachesTheGuardThroughTheStepUpQuartet(t *testing.T) {
	cfg := baseConfig()
	cfg.MFA = MFAConfig{CIBA: CIBAConfig{
		BackchannelEndpoint: "https://idp.example/ciba",
		TokenEndpoint:       "https://idp.example/token",
		ClientID:            "stamp-ciba",
		ClientSecret:        "ciba-secret",
	}}
	if !cfg.MFA.Configured() {
		t.Fatal("a CIBA client alone does not report the MFA configuration as configured")
	}

	err := cfg.validate(everyRole())
	if err == nil {
		t.Fatal("a CIBA-only deployment validated, so the step-up quartet is no longer required")
	}
	if !strings.Contains(err.Error(), EnvMFAAuthzEndpoint) {
		t.Fatalf("a CIBA-only deployment is not asked for the step-up quartet, which is what carries "+
			"it into the surface check:\n%v", err)
	}
	// The refusal above is MFAConfig.validate's, not this one's: with no
	// authorization endpoint there is nothing for the surface check to strand.
	if strings.Contains(err.Error(), EnvCallbackAddr) {
		t.Errorf("the surface check fired on a CIBA-only configuration; it is not a trigger:\n%v", err)
	}

	// With the quartet filled in — which is the only way this deployment boots
	// at all — the guard applies, and it is right to: nothing polls an
	// auth_req_id, so a CIBA verdict comes back on the POST of the same route.
	withStepUpSettings(&cfg)
	cfg.MFA.CIBA = CIBAConfig{
		BackchannelEndpoint: "https://idp.example/ciba",
		TokenEndpoint:       "https://idp.example/token",
		ClientID:            "stamp-ciba",
		ClientSecret:        "ciba-secret",
	}
	err = cfg.validate(everyRole())
	if err == nil {
		t.Fatal("a CIBA deployment with the step-up quartet and no callback listener was accepted")
	}
	if !strings.Contains(err.Error(), EnvCallbackAddr) {
		t.Errorf("the refusal is not the surface one:\n%v", err)
	}
}

// TestTheBinaryAndTheChartRefuseTheSameStrandedRelease holds the two guards
// together.
//
// Two guards that disagree are worse than one: a configuration the chart
// rejects and the binary accepts teaches an operator that the chart is fussy,
// and one the chart accepts and the binary refuses is a rollout that fails
// after the manifests were reviewed. The chart's refusal is pinned in a
// snapshot (deploy/helm/render.sh renders a values file the chart must refuse),
// so both messages exist as text and can be compared.
func TestTheBinaryAndTheChartRefuseTheSameStrandedRelease(t *testing.T) {
	chart, err := os.ReadFile(filepath.Clean(chartCallbackRefusalFile))
	if err != nil {
		t.Fatalf("read %s: %v (run deploy/helm/render.sh)", chartCallbackRefusalFile, err)
	}
	chartMsg := string(chart)

	cfg := baseConfig()
	withStepUpSettings(&cfg)
	withExternalTarget(&cfg)
	withIngestGrant(&cfg)
	binaryErr := cfg.validate(everyRole())
	if binaryErr == nil {
		t.Fatal("the binary accepted the release the chart refuses")
	}
	binaryMsg := binaryErr.Error()

	// The three triggers, each in the language of its own guard. A trigger
	// added to one side and not the other fails here.
	for _, trigger := range []struct{ values, env string }{
		{"mfa.authorizationEndpoint", EnvMFAAuthzEndpoint},
		{"documents.externalTargets", EnvExternalTargets},
		{"documents.ingestCredentials", EnvIngestCredentials},
	} {
		if !strings.Contains(chartMsg, trigger.values) {
			t.Errorf("the chart's refusal no longer names %s, so the two guards trigger on "+
				"different sets:\n  %s", trigger.values, chartMsg)
		}
		if !strings.Contains(binaryMsg, trigger.env) {
			t.Errorf("the binary's refusal does not name %s:\n%v", trigger.env, binaryMsg)
		}
	}

	// Derived rather than listed, exactly as internal/release derives it for the
	// chart: every path mounted on the callback surface is named by the binary's
	// refusal too. A route added there later is one more thing an unbound
	// listener swallows, and this stays red until both messages account for it.
	for _, path := range callbackSurfacePaths(t) {
		if !strings.Contains(binaryMsg, path) {
			t.Errorf("the binary's refusal does not name %s, which is mounted on the callback "+
				"surface and is therefore one of the things this process would have lost:\n%v",
				path, binaryMsg)
		}
		if !strings.Contains(chartMsg, path) {
			t.Errorf("the chart's refusal does not name %s:\n  %s", path, chartMsg)
		}
	}

	// Both ways out, on both sides. The second one is the legitimate deployment:
	// running none of the three is what the unbound default is for.
	for _, want := range []string{EnvCallbackAddr, EnvCallbackBaseURL, "clear the settings named above"} {
		if !strings.Contains(binaryMsg, want) {
			t.Errorf("the binary's refusal does not offer %q:\n%v", want, binaryMsg)
		}
	}

	// And the role gate is the same judgment on both sides. The chart refuses
	// only when a tier runs decide or consumer; this reads that condition out of
	// the template rather than trusting the comment above it.
	guard := chartCallbackGuard(t)
	for _, role := range []string{"decide", "consumer"} {
		if !strings.Contains(guard, `"role" "`+role+`"`) {
			t.Errorf("the chart's callback guard no longer gates on the %s role, so its refusal and "+
				"the binary's are gated differently:\n%s", role, guard)
		}
	}
	for _, role := range []string{"check", "api", "console"} {
		if strings.Contains(guard, `"role" "`+role+`"`) {
			t.Errorf("the chart's callback guard gates on the %s role, which mounts no callback "+
				"route; the binary does not refuse it and the two now disagree:\n%s", role, guard)
		}
	}
}

// chartCallbackRefusalFile is the chart's own message, rendered by
// deploy/helm/render.sh from a values file the chart must refuse and committed
// so that a Go test can read it without helm.
const chartCallbackRefusalFile = "../../deploy/helm/snapshots/no-callback.err.txt"

// chartHelpersFile is the template both refusals' conditions live in — the
// chart's in the template itself, the binary's named by the comment on
// surfaceRequirements.
const chartHelpersFile = "../../deploy/helm/stamp/templates/_helpers.tpl"

// chartCallbackGuard returns the body of the chart's stamp.callbackSurfaceValidated
// define. It is scoped rather than read whole because other helpers in the same
// file legitimately name the decide and api roles, and a substring search over
// the whole template would pass on theirs.
func chartCallbackGuard(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(chartHelpersFile))
	if err != nil {
		t.Fatalf("read %s: %v", chartHelpersFile, err)
	}
	const marker = `{{- define "stamp.callbackSurfaceValidated" -}}`
	_, body, found := strings.Cut(string(raw), marker)
	if !found {
		t.Fatalf("%s no longer defines stamp.callbackSurfaceValidated: the chart's half of this "+
			"refusal is gone, and the binary's is now the only guard again", chartHelpersFile)
	}
	return body
}

// callbackSurfacePaths reads the paths mounted on the callback surface out of
// the tracked mount table, without the method prefix a pattern carries.
func callbackSurfacePaths(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(mountTableFile))
	if err != nil {
		t.Fatalf("read %s: %v (run `go test ./internal/runtime/ -run TestTheMountTableFileIsUpToDate`, "+
			"which needs a Docker daemon)", mountTableFile, err)
	}
	var table mountTableDocument
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatalf("decode %s: %v", mountTableFile, err)
	}
	seen := map[string]bool{}
	paths := []string{}
	for _, r := range table.Routes {
		if r.Surface != string(api.SurfaceCallback) {
			continue
		}
		path := r.Pattern
		if _, rest, found := strings.Cut(path, " "); found {
			path = rest
		}
		// /healthz is mounted by api.Server on every surface rather than by a
		// role, so it belongs to no feature an operator could have configured.
		if path == "/healthz" || seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		t.Fatalf("%s lists no callback routes, so this test would pass on an empty message", mountTableFile)
	}
	return paths
}

// ---------------------------------------------------------------------------
// the M3 ingestion and directory configuration
// ---------------------------------------------------------------------------

func TestStreamSourcesRead(t *testing.T) {
	const doc = `[{
		"name": "daily_transfer_total",
		"metric": "transfer_amount",
		"adapter": "kafka",
		"window": "24h",
		"bucket_width": "1h",
		"freshness": "5m",
		"allow_deduction": true,
		"params": [{"name": "account", "type": "string"}],
		"returns": "double",
		"on_error": "deny"
	}]`

	path := filepath.Join(t.TempDir(), "stream.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write declarations: %v", err)
	}
	// A container mounts a file and a laptop pastes a literal; both are read.
	for name, spec := range map[string]string{"inline": doc, "file": path} {
		decls, err := streamSourcesFrom(spec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(decls) != 1 {
			t.Fatalf("%s: %d declarations, want 1", name, len(decls))
		}
		d := decls[0]
		if d.Name != "daily_transfer_total" || d.Metric != "transfer_amount" || d.Adapter != "kafka" {
			t.Errorf("%s: declaration = %+v", name, d)
		}
		if d.Window != 24*time.Hour || d.BucketWidth != time.Hour || d.Freshness != 5*time.Minute {
			t.Errorf("%s: window = %v, bucket = %v, freshness = %v", name, d.Window, d.BucketWidth, d.Freshness)
		}
		if !d.AllowDeduction || d.Returns != policy.TypeDouble {
			t.Errorf("%s: deduction = %v, returns = %q", name, d.AllowDeduction, d.Returns)
		}
	}
}

func TestStreamSourcesRejectAnUnknownField(t *testing.T) {
	// A misspelled `allow_deduction` is a metric that admits negative deltas
	// while its manifest says it does not, which is a control that reads as
	// configured and is not.
	if _, err := streamSourcesFrom(`[{"name":"x","metric":"m","allow_deductions":true}]`); err == nil {
		t.Fatal("a velocity declaration with an unknown field was accepted")
	}
}

func TestAVelocitySourceDefaultsToTheHTTPIngestAdapter(t *testing.T) {
	// The HTTP adapter is the one every install has — the broker is the
	// optional dependency D20 keeps optional — so it is the only default that
	// could be filled in without guessing.
	cfg := baseConfig()
	cfg.StreamSources = []stream.Declaration{{Name: "v", Metric: "m"}}
	cfg = cfg.withDefaults()
	if got := cfg.StreamSources[0].Adapter; got != DefaultIngestAdapterName {
		t.Errorf("adapter = %q, want %q", got, DefaultIngestAdapterName)
	}
	if cfg.IngestAdapterName != DefaultIngestAdapterName {
		t.Errorf("ingest adapter name = %q, want %q", cfg.IngestAdapterName, DefaultIngestAdapterName)
	}
}

func TestIngestCredentialsAndKafkaTopicsRead(t *testing.T) {
	creds, err := ingestCredentialsFrom(`[{
		"caller_id": "workload:https://idp.example#svc-payments",
		"scope": [{"source": "daily_transfer_total", "metric": "transfer_amount"}],
		"allow_deduction": true,
		"rate": {"per_second": 100, "burst": 200},
		"subject_rate": {"per_second": 5}
	}]`)
	if err != nil {
		t.Fatalf("read ingest credentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("%d credentials, want 1", len(creds))
	}
	c := creds[0]
	// The grant names the identifier the identity layer derives from a verified
	// token, not the bare subject: a `sub` is unique only inside its issuer.
	if c.CallerID != "workload:https://idp.example#svc-payments" || !c.AllowDeduction {
		t.Errorf("credential = %+v", c)
	}
	if len(c.Scope) != 1 || c.Scope[0].Source != "daily_transfer_total" {
		t.Errorf("scope = %+v", c.Scope)
	}
	if c.Rate.PerSecond != 100 || c.Rate.Burst != 200 || c.SubjectRate.PerSecond != 5 {
		t.Errorf("rates = %+v / %+v", c.Rate, c.SubjectRate)
	}

	topics, err := kafkaTopicsFrom(`[{"topic":"transfers","source":"daily_transfer_total","caller_id":"producer-1"}]`)
	if err != nil {
		t.Fatalf("read kafka topics: %v", err)
	}
	if len(topics) != 1 || topics[0].Topic != "transfers" || topics[0].CallerID != "producer-1" {
		t.Errorf("topics = %+v", topics)
	}
}

func TestIdPGroupSourcesRead(t *testing.T) {
	decls, err := idpGroupSourcesFrom(`[{
		"name": "approver_group",
		"issuer": "https://idp.example",
		"url": "https://idp.example/scim/v2/Groups",
		"credential": "s3cret",
		"members_field": "members",
		"member_id_field": "value",
		"total_field": "totalResults",
		"ttl": "1m",
		"timeout": "2s",
		"params": [{"name": "group", "type": "string"}],
		"returns": "list<string>",
		"on_error": "deny"
	}]`)
	if err != nil {
		t.Fatalf("read group sources: %v", err)
	}
	if len(decls) != 1 {
		t.Fatalf("%d declarations, want 1", len(decls))
	}
	d := decls[0]
	if d.Issuer != "https://idp.example" || d.Credential != "s3cret" {
		t.Errorf("declaration = %+v", d)
	}
	if d.TTL != time.Minute || d.Timeout != 2*time.Second {
		t.Errorf("ttl = %v, timeout = %v", d.TTL, d.Timeout)
	}
	// The directory credential is operator configuration and never crosses into
	// the schema half a policy is written against (D21).
	if got := fmt.Sprintf("%+v", d.SourceDecl()); strings.Contains(got, "s3cret") {
		t.Errorf("the schema half carries the directory credential: %s", got)
	}
}

func TestABrokerWithNoGroupOrTopicsIsRefused(t *testing.T) {
	cfg := baseConfig()
	cfg.Kafka = KafkaConfig{Brokers: []string{"broker:9092"}}
	err := cfg.validate(everyRole())
	if err == nil {
		t.Fatal("a broker with no consumer group and no topics was accepted")
	}
	for _, want := range []string{EnvKafkaGroup, EnvKafkaTopics} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s:\n%v", want, err)
		}
	}
}

// ---------------------------------------------------------------------------
// the approver issuer designation
// ---------------------------------------------------------------------------

// TestApproverIssuerDesignation is the configuration surface a multi-issuer
// deployment had no way to reach.
//
// A bare approver identifier is an identity only relative to an issuer, so a
// deployment that pins several has to say which one is meant. Taking the first
// entry would be picking which IdP's alice may approve, and leaving it empty
// makes the challenge handlers refuse — which was correct and, until this
// variable existed, permanent.
func TestApproverIssuerDesignation(t *testing.T) {
	two := func() Config {
		cfg := baseConfig()
		cfg.OIDC.Issuers = append(cfg.OIDC.Issuers,
			IssuerConfig{Issuer: "https://other.example", JWKSURL: "https://other.example/jwks"})
		return cfg
	}

	t.Run("one pinned issuer needs no designation", func(t *testing.T) {
		if got := approverIssuerFor(baseConfig()); got != "https://idp.example" {
			t.Errorf("approver issuer = %q, want the single pinned issuer", got)
		}
	})

	t.Run("several pinned issuers and no designation refuses rather than guesses", func(t *testing.T) {
		if got := approverIssuerFor(two()); got != "" {
			t.Errorf("approver issuer = %q, want empty: guessing would pick which IdP's alice may approve", got)
		}
	})

	t.Run("an explicit designation is used", func(t *testing.T) {
		cfg := two()
		cfg.ApproverIssuer = "https://other.example"
		if err := cfg.validate(everyRole()); err != nil {
			t.Fatalf("a designation naming a pinned issuer was refused: %v", err)
		}
		if got := approverIssuerFor(cfg); got != "https://other.example" {
			t.Errorf("approver issuer = %q, want the designated one", got)
		}
	})

	t.Run("designating the single pinned issuer is admitted", func(t *testing.T) {
		cfg := baseConfig()
		cfg.ApproverIssuer = "https://idp.example"
		if err := cfg.validate(everyRole()); err != nil {
			t.Fatalf("designating the one pinned issuer was refused: %v", err)
		}
	})

	t.Run("an unpinned issuer is refused at startup", func(t *testing.T) {
		cfg := two()
		cfg.ApproverIssuer = "https://elsewhere.example"
		err := cfg.validate(everyRole())
		if err == nil {
			t.Fatal("an approver issuer this deployment does not pin was accepted")
		}
		// A designated issuer whose tokens are rejected is a quorum nobody can
		// satisfy, which reads as a policy problem and is a configuration one.
		for _, want := range []string{EnvApproverIssuer, "https://elsewhere.example", EnvOIDCIssuer} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not name %s:\n%v", want, err)
			}
		}
	})

	t.Run("the designation is read from the environment", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(EnvDSN, "postgres://stamp@localhost/stamp")
		t.Setenv(EnvOIDCIssuer, "https://idp.example")
		t.Setenv(EnvOIDCJWKSURL, "https://idp.example/jwks")
		t.Setenv(EnvOIDCAudience, "stamp")
		t.Setenv(EnvApproverIssuer, "https://idp.example")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("read the environment: %v", err)
		}
		if cfg.ApproverIssuer != "https://idp.example" {
			t.Errorf("approver issuer = %q", cfg.ApproverIssuer)
		}
	})
}

// R43's decide rate limits on the deployment surface.
//
// They are written in the shape [stream.RateLimit] already gave the four
// `STAMP_INGEST_RATE_*` variables, because this deployment has one way of
// writing a token bucket down. What matters here is the reading: unset means
// the api package's default rather than "no limit", and the two spellings that
// cannot mean anything are startup failures rather than values quietly resolved
// into one of the things they might have meant.
func TestConfigFromEnvReadsTheDecideRateLimits(t *testing.T) {
	base := func(t *testing.T) {
		t.Helper()
		clearEnv(t)
		t.Setenv(EnvDSN, "postgres://stamp@localhost/stamp")
		t.Setenv(EnvOIDCIssuer, "https://idp.example")
		t.Setenv(EnvOIDCJWKSURL, "https://idp.example/jwks")
		t.Setenv(EnvOIDCAudience, "stamp")
	}

	t.Run("unset leaves the defaults to the surface", func(t *testing.T) {
		base(t)
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("ConfigFromEnv: %v", err)
		}
		// Zero here is not "no limit": it is "the operator said nothing", and the
		// decide surface reads it as its default. An operator who means no limit
		// writes a negative rate.
		if cfg.DecideRate != (stream.RateLimit{}) || cfg.DecideSubjectRate != (stream.RateLimit{}) {
			t.Errorf("decide rates = %+v / %+v, want zero so the surface defaults them",
				cfg.DecideRate, cfg.DecideSubjectRate)
		}
	})

	t.Run("the four variables are read", func(t *testing.T) {
		base(t)
		t.Setenv(EnvDecideRate, "25")
		t.Setenv(EnvDecideBurst, "40")
		t.Setenv(EnvDecideSubjectRate, "2.5")
		t.Setenv(EnvDecideSubjectRateBurst, "6")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("ConfigFromEnv: %v", err)
		}
		if want := (stream.RateLimit{PerSecond: 25, Burst: 40}); cfg.DecideRate != want {
			t.Errorf("caller rate = %+v, want %+v", cfg.DecideRate, want)
		}
		if want := (stream.RateLimit{PerSecond: 2.5, Burst: 6}); cfg.DecideSubjectRate != want {
			t.Errorf("subject rate = %+v, want %+v", cfg.DecideSubjectRate, want)
		}
	})

	t.Run("a rate that is not a number is a startup failure", func(t *testing.T) {
		base(t)
		t.Setenv(EnvDecideRate, "fast")
		if _, err := ConfigFromEnv(); err == nil {
			t.Fatal("an unparseable decide rate was accepted")
		} else if !strings.Contains(err.Error(), EnvDecideRate) {
			t.Errorf("the refusal does not name %s:\n%v", EnvDecideRate, err)
		}
	})

	t.Run("a negative burst is a startup failure", func(t *testing.T) {
		base(t)
		t.Setenv(EnvDecideSubjectRateBurst, "-1")
		if _, err := ConfigFromEnv(); err == nil {
			t.Fatal("a bucket that holds less than nothing was accepted")
		} else if !strings.Contains(err.Error(), EnvDecideSubjectRateBurst) {
			t.Errorf("the refusal does not name %s:\n%v", EnvDecideSubjectRateBurst, err)
		}
	})

	t.Run("a burst alongside a disabled rate is a startup failure", func(t *testing.T) {
		base(t)
		t.Setenv(EnvDecideRate, "-1")
		t.Setenv(EnvDecideBurst, "10")
		// This is an operator who wrote down a limit and would have got none.
		// Booting anyway would leave them believing the decide path is bounded.
		if _, err := ConfigFromEnv(); err == nil {
			t.Fatal("a burst configured alongside a rate that turns the limit off was accepted")
		} else if !strings.Contains(err.Error(), EnvDecideBurst) {
			t.Errorf("the refusal does not name %s:\n%v", EnvDecideBurst, err)
		}
	})

	t.Run("a negative rate on its own removes the limit", func(t *testing.T) {
		base(t)
		t.Setenv(EnvDecideRate, "-1")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("saying no limit out loud was refused: %v", err)
		}
		if cfg.DecideRate.PerSecond != -1 {
			t.Errorf("caller rate = %v, want the operator's -1 carried through", cfg.DecideRate.PerSecond)
		}
	})
}

// TestConfigFromEnvReadsTheChallengeApprovalAndCancellationRateLimits is the
// other three axes of R43 on the deployment surface.
//
// They are read the way the decide rates are, and validated by the same
// function, because an operator who mistyped the approval burst is in exactly
// the position the decide burst's check exists for: a limit validated on one
// surface and not another is a limit somebody can be silently without.
//
// The cancellation pair is the newest and was the last write surface with no
// budget at all. It is here rather than in a test of its own precisely because
// what it has to be is *the same as the others* — same spelling, same zero
// meaning, same refusal to boot on a bucket that cannot mean anything.
func TestConfigFromEnvReadsTheChallengeApprovalAndCancellationRateLimits(t *testing.T) {
	base := func(t *testing.T) {
		t.Helper()
		clearEnv(t)
		t.Setenv(EnvDSN, "postgres://stamp@localhost/stamp")
		t.Setenv(EnvOIDCIssuer, "https://idp.example")
		t.Setenv(EnvOIDCJWKSURL, "https://idp.example/jwks")
		t.Setenv(EnvOIDCAudience, "stamp")
	}

	t.Run("unset leaves the defaults to the handlers", func(t *testing.T) {
		base(t)
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("ConfigFromEnv: %v", err)
		}
		// Zero is "the operator said nothing", and each handler reads it as its
		// own default — which is a real number, not "unlimited". An operator who
		// means no limit writes a negative rate.
		if cfg.ChallengeIssueRate != (stream.RateLimit{}) || cfg.ApprovalSubmitRate != (stream.RateLimit{}) ||
			cfg.ChallengeIssueSubjectCeiling != (stream.RateLimit{}) ||
			cfg.CancellationRate != (stream.RateLimit{}) {
			t.Errorf("rates = %+v / %+v / %+v / %+v, want zero so the handlers default them",
				cfg.ChallengeIssueRate, cfg.ChallengeIssueSubjectCeiling, cfg.ApprovalSubmitRate,
				cfg.CancellationRate)
		}
	})

	t.Run("the eight variables are read", func(t *testing.T) {
		base(t)
		t.Setenv(EnvChallengeIssueRate, "0.1")
		t.Setenv(EnvChallengeIssueBurst, "4")
		t.Setenv(EnvChallengeIssueCeilingRate, "0.02")
		t.Setenv(EnvChallengeIssueCeilingBurst, "12")
		t.Setenv(EnvApprovalRate, "3")
		t.Setenv(EnvApprovalBurst, "30")
		t.Setenv(EnvCancellationRate, "0.5")
		t.Setenv(EnvCancellationBurst, "4")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("ConfigFromEnv: %v", err)
		}
		if want := (stream.RateLimit{PerSecond: 0.1, Burst: 4}); cfg.ChallengeIssueRate != want {
			t.Errorf("challenge issue rate = %+v, want %+v", cfg.ChallengeIssueRate, want)
		}
		// The ceiling is its own pair of variables. One knob for both would be
		// an operator raising what a caller may ask of a person and silently
		// raising what the person can be asked in total, which are different
		// questions with different right answers.
		if want := (stream.RateLimit{PerSecond: 0.02, Burst: 12}); cfg.ChallengeIssueSubjectCeiling != want {
			t.Errorf("challenge issue ceiling = %+v, want %+v", cfg.ChallengeIssueSubjectCeiling, want)
		}
		if want := (stream.RateLimit{PerSecond: 3, Burst: 30}); cfg.ApprovalSubmitRate != want {
			t.Errorf("approval rate = %+v, want %+v", cfg.ApprovalSubmitRate, want)
		}
		// Its own pair of variables again, and for the sharper version of the
		// reason above: approval submission and delay cancellation reach the same
		// lifecycle through the same seam, so one knob would look reasonable — and
		// it would mean a flood of approvals could stop an authority halting a
		// wait that is already running.
		if want := (stream.RateLimit{PerSecond: 0.5, Burst: 4}); cfg.CancellationRate != want {
			t.Errorf("cancellation rate = %+v, want %+v", cfg.CancellationRate, want)
		}
	})

	for name, tc := range map[string]struct {
		key, value string
		names      string
	}{
		"an unparseable challenge rate": {key: EnvChallengeIssueRate, value: "slow", names: EnvChallengeIssueRate},
		"a negative challenge burst":    {key: EnvChallengeIssueBurst, value: "-1", names: EnvChallengeIssueBurst},
		// The ceiling is validated by the same function as every other R43
		// budget. A limit checked on five of six surfaces is a limit somebody
		// can be silently without.
		"an unparseable ceiling rate":      {key: EnvChallengeIssueCeilingRate, value: "slow", names: EnvChallengeIssueCeilingRate},
		"a negative ceiling burst":         {key: EnvChallengeIssueCeilingBurst, value: "-1", names: EnvChallengeIssueCeilingBurst},
		"an unparseable approval rate":     {key: EnvApprovalRate, value: "fast", names: EnvApprovalRate},
		"a negative approval burst":        {key: EnvApprovalBurst, value: "-2", names: EnvApprovalBurst},
		"an unparseable cancellation rate": {key: EnvCancellationRate, value: "never", names: EnvCancellationRate},
		"a negative cancellation burst":    {key: EnvCancellationBurst, value: "-3", names: EnvCancellationBurst},
		"an approval burst with no rate": {
			key: EnvApprovalBurst, value: "10", names: EnvApprovalBurst,
		},
		// The same shape on the newest budget: an operator who wrote down a
		// bucket size next to a rate that turns the limit off got no limit, on
		// the surface this round added one to.
		"a cancellation burst with no rate": {
			key: EnvCancellationBurst, value: "5", names: EnvCancellationBurst,
		},
	} {
		t.Run(name+" is a startup failure", func(t *testing.T) {
			base(t)
			switch name {
			case "an approval burst with no rate":
				// The operator who wrote down a limit and would have got none.
				t.Setenv(EnvApprovalRate, "-1")
			case "a cancellation burst with no rate":
				t.Setenv(EnvCancellationRate, "-1")
			}
			t.Setenv(tc.key, tc.value)
			if _, err := ConfigFromEnv(); err == nil {
				t.Fatalf("%s=%q was accepted", tc.key, tc.value)
			} else if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("the refusal does not name %s:\n%v", tc.names, err)
			}
		})
	}

	t.Run("a negative rate on its own removes the limit", func(t *testing.T) {
		base(t)
		t.Setenv(EnvChallengeIssueRate, "-1")
		t.Setenv(EnvCancellationRate, "-1")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("saying no limit out loud was refused: %v", err)
		}
		if cfg.ChallengeIssueRate.PerSecond != -1 {
			t.Errorf("challenge issue rate = %v, want the operator's -1 carried through",
				cfg.ChallengeIssueRate.PerSecond)
		}
		if cfg.CancellationRate.PerSecond != -1 {
			t.Errorf("cancellation rate = %v, want the operator's -1 carried through",
				cfg.CancellationRate.PerSecond)
		}
	})
}
