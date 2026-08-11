package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
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
		EnvChallengeIssueRate, EnvChallengeIssueBurst, EnvApprovalRate, EnvApprovalBurst,
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
	if err := base.withDefaults().validate(); err != nil {
		t.Fatalf("the baseline configuration is already invalid, so this test proves nothing: %v", err)
	}

	negative := base
	negative.AuditAlertThreshold = -1
	err := negative.withDefaults().validate()
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
	cfg := baseConfig()
	cfg.MFA = MFAConfig{
		AuthorizationEndpoint: "https://idp.example/authorize",
		TokenEndpoint:         "https://idp.example/token",
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
		TokenEndpoint:         "https://idp.example/token",
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

// U2's trap, and the one #41 was made of: a step-up with nowhere to redeem its
// code is a challenge that can be opened and never completed. It fails the boot
// rather than the moment somebody has finished authenticating and is waiting for
// a page.
func TestDelegatedMFANeedsSomewhereToRedeemTheCode(t *testing.T) {
	cfg := baseConfig()
	cfg.MFA = MFAConfig{
		AllowedACRValues:      []string{"aal2"},
		AuthorizationEndpoint: "https://idp.example/authorize",
		ClientID:              "stamp-console",
		RedirectURI:           "https://stamp.example/callback",
	}
	err := cfg.validate()
	if err == nil {
		t.Fatal("a step-up with no token endpoint was accepted")
	}
	if !strings.Contains(err.Error(), EnvMFATokenEndpoint) {
		t.Errorf("the error does not name %s:\n%v", EnvMFATokenEndpoint, err)
	}
	cfg.MFA.TokenEndpoint = "https://idp.example/token"
	if err := cfg.validate(); err != nil {
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
	err := cfg.validate()
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
		if err := cfg.validate(); err != nil {
			t.Fatalf("a designation naming a pinned issuer was refused: %v", err)
		}
		if got := approverIssuerFor(cfg); got != "https://other.example" {
			t.Errorf("approver issuer = %q, want the designated one", got)
		}
	})

	t.Run("designating the single pinned issuer is admitted", func(t *testing.T) {
		cfg := baseConfig()
		cfg.ApproverIssuer = "https://idp.example"
		if err := cfg.validate(); err != nil {
			t.Fatalf("designating the one pinned issuer was refused: %v", err)
		}
	})

	t.Run("an unpinned issuer is refused at startup", func(t *testing.T) {
		cfg := two()
		cfg.ApproverIssuer = "https://elsewhere.example"
		err := cfg.validate()
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

// TestConfigFromEnvReadsTheChallengeAndApprovalRateLimits is the other two axes
// of R43 on the deployment surface.
//
// They are read the way the decide rates are, and validated by the same
// function, because an operator who mistyped the approval burst is in exactly
// the position the decide burst's check exists for: a limit validated on one
// surface and not another is a limit somebody can be silently without.
func TestConfigFromEnvReadsTheChallengeAndApprovalRateLimits(t *testing.T) {
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
		if cfg.ChallengeIssueRate != (stream.RateLimit{}) || cfg.ApprovalSubmitRate != (stream.RateLimit{}) {
			t.Errorf("rates = %+v / %+v, want zero so the handlers default them",
				cfg.ChallengeIssueRate, cfg.ApprovalSubmitRate)
		}
	})

	t.Run("the four variables are read", func(t *testing.T) {
		base(t)
		t.Setenv(EnvChallengeIssueRate, "0.1")
		t.Setenv(EnvChallengeIssueBurst, "4")
		t.Setenv(EnvApprovalRate, "3")
		t.Setenv(EnvApprovalBurst, "30")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("ConfigFromEnv: %v", err)
		}
		if want := (stream.RateLimit{PerSecond: 0.1, Burst: 4}); cfg.ChallengeIssueRate != want {
			t.Errorf("challenge issue rate = %+v, want %+v", cfg.ChallengeIssueRate, want)
		}
		if want := (stream.RateLimit{PerSecond: 3, Burst: 30}); cfg.ApprovalSubmitRate != want {
			t.Errorf("approval rate = %+v, want %+v", cfg.ApprovalSubmitRate, want)
		}
	})

	for name, tc := range map[string]struct {
		key, value string
		names      string
	}{
		"an unparseable challenge rate": {key: EnvChallengeIssueRate, value: "slow", names: EnvChallengeIssueRate},
		"a negative challenge burst":    {key: EnvChallengeIssueBurst, value: "-1", names: EnvChallengeIssueBurst},
		"an unparseable approval rate":  {key: EnvApprovalRate, value: "fast", names: EnvApprovalRate},
		"a negative approval burst":     {key: EnvApprovalBurst, value: "-2", names: EnvApprovalBurst},
		"an approval burst with no rate": {
			key: EnvApprovalBurst, value: "10", names: EnvApprovalBurst,
		},
	} {
		t.Run(name+" is a startup failure", func(t *testing.T) {
			base(t)
			if name == "an approval burst with no rate" {
				// The operator who wrote down a limit and would have got none.
				t.Setenv(EnvApprovalRate, "-1")
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
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("saying no limit out loud was refused: %v", err)
		}
		if cfg.ChallengeIssueRate.PerSecond != -1 {
			t.Errorf("challenge issue rate = %v, want the operator's -1 carried through",
				cfg.ChallengeIssueRate.PerSecond)
		}
	})
}
