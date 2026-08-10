package runtime

// config.go is the deployment surface: everything the composition root needs
// that is not in the database.
//
// It is read from the environment because that is the one injection path a
// container, a Helm chart and a laptop all have. Two rules hold it together.
//
// Nothing here has a default that would be a credential or a trust decision. A
// missing DSN, a missing issuer, a missing audience each fail the boot with a
// message naming the variable — a process that started with a guessed issuer
// would be verifying tokens against something nobody chose.
//
// Everything that is a tuning knob does have a default, and the default is the
// safe direction: fail-closed audit, no fail-open fact sources, no loopback or
// private egress, a governance floor of one approver.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// Defaults for the knobs a deployment does not set.
const (
	// DefaultMaxConns sizes the pool. A claimed audit writer pins one
	// connection for the life of the process, and every audited transaction
	// takes another, so the pgxpool default is too small on a small machine.
	DefaultMaxConns = 24
	// DefaultPEPAddr and DefaultConsoleAddr are the two surfaces an
	// all-in-one install serves. The callback surface has no default: it is
	// the one listener a deployment may have to expose beyond its perimeter,
	// so it is bound only when an operator asks for it.
	DefaultPEPAddr     = ":8080"
	DefaultConsoleAddr = ":8081"
	// DefaultReconcileInterval is how often a pending revision whose quorum is
	// in gets applied without waiting for the next approval.
	DefaultReconcileInterval = 30 * time.Second
)

// Config is one stamp process's deployment configuration.
type Config struct {
	// DSN is the Postgres connection string. Required.
	DSN string
	// MaxConns bounds the pool. Zero selects DefaultMaxConns.
	MaxConns int32
	// Roles names the database roles the grants provision.
	DBRoles store.RoleNames
	// Migrate runs the schema migrations at startup.
	Migrate bool
	// ApplyGrants provisions the per-role database roles at startup. It needs
	// a login with CREATE ROLE, which a hardened deployment may not give the
	// service, so it is separable from Migrate.
	ApplyGrants bool

	// InstanceID identifies this process in the audit writer claim. It
	// defaults to the hostname.
	InstanceID string
	// WriterID is the audit chain segment this process owns. Exactly one live
	// process may hold it: a collision fails the boot rather than retrying.
	WriterID string

	// Addresses gives the listen address per surface. A surface with no entry
	// is not listened on at all.
	Addresses map[api.Surface]string

	// OIDC is the token verification trust boundary.
	OIDC OIDCConfig

	// FactSources are the deployment's synchronous fact source transports.
	// A schema that declares a source this list does not configure is refused
	// at load rather than at call time.
	FactSources []fact.Declaration
	// Egress bounds what a fact call may reach.
	Egress fact.EgressConfig
	// AllowFactFailOpen is the operator flag R36 requires: without it a source
	// declaration asking to fail open is rejected at load.
	AllowFactFailOpen bool

	// AuditFailClosed makes the check surface deny while the audit buffer is
	// saturated. R32 requires this to be the operator's choice; the default is
	// the closed direction.
	AuditFailClosed bool
	// AuditCapacity, AuditBatchSize and AuditFlushInterval size the check-path
	// audit buffer. Zero selects the api package's defaults.
	AuditCapacity      int
	AuditBatchSize     int
	AuditFlushInterval time.Duration

	// PolicyRefreshInterval and PolicyStalenessDeadline are R24's two knobs.
	// Zero selects the engine's defaults.
	PolicyRefreshInterval   time.Duration
	PolicyStalenessDeadline time.Duration

	// DecisionTTL and MaxOutstanding bound decisions. Zero selects the
	// decision package's defaults.
	DecisionTTL    time.Duration
	MaxOutstanding int

	// GovernanceFloor is R33's operator lower bound on a revision quorum.
	GovernanceFloor revision.Floor
	// RevisionTTL bounds how long a revision may stay pending. Zero selects
	// the governance default.
	RevisionTTL time.Duration
	// ReconcileInterval is how often a resolved revision is applied without
	// waiting for another approval. Zero selects DefaultReconcileInterval.
	ReconcileInterval time.Duration
	// BootstrapWarnInterval is how often a live bootstrap token raises its
	// highest-severity warning. Zero selects the governance default.
	BootstrapWarnInterval time.Duration

	// CheckContextEntity is the entity type an AuthZEN request context binds
	// to. Empty means requests carry no context entity.
	CheckContextEntity string
	// CheckPropertyAliases renames incoming AuthZEN property keys before they
	// are looked up against the schema.
	CheckPropertyAliases map[string]string
}

// OIDCConfig is the token verification trust boundary, read from the
// environment.
type OIDCConfig struct {
	// Issuers is the pinned issuer set. At least one is required.
	Issuers []IssuerConfig
	// Audience is the audience every token must name. Required.
	Audience string
	// Algorithms is the asymmetric signing algorithm allowlist.
	Algorithms []string
	// AllowedACRValues, when non-empty, bounds an end-user token's
	// authentication context class.
	AllowedACRValues []string
	// AllowInsecureTransport permits plaintext issuer and JWKS URLs. It exists
	// for loopback development and tests.
	AllowInsecureTransport bool
}

// IssuerConfig is one trusted issuer.
type IssuerConfig struct {
	// Issuer is the exact `iss` value tokens must carry.
	Issuer string
	// JWKSURL is the key set endpoint.
	JWKSURL string
	// WorkloadClients lists the client identifiers whose tokens are workload
	// credentials rather than end-user ones.
	WorkloadClients []string
}

// The environment variables the configuration is read from.
const (
	EnvDSN         = "STAMP_DSN"
	EnvMaxConns    = "STAMP_DB_MAX_CONNS"
	EnvMigrate     = "STAMP_DB_MIGRATE"
	EnvApplyGrants = "STAMP_DB_APPLY_GRANTS"
	EnvRoleCheck   = "STAMP_DB_ROLE_CHECK"
	EnvRoleDecide  = "STAMP_DB_ROLE_DECIDE"
	EnvRoleConsume = "STAMP_DB_ROLE_CONSUMER"
	EnvRoleAdmin   = "STAMP_DB_ROLE_ADMIN"

	EnvInstanceID = "STAMP_INSTANCE_ID"
	EnvWriterID   = "STAMP_AUDIT_WRITER_ID"

	EnvPEPAddr      = "STAMP_PEP_ADDR"
	EnvConsoleAddr  = "STAMP_CONSOLE_ADDR"
	EnvCallbackAddr = "STAMP_CALLBACK_ADDR"

	EnvOIDCIssuer          = "STAMP_OIDC_ISSUER"
	EnvOIDCJWKSURL         = "STAMP_OIDC_JWKS_URL"
	EnvOIDCAudience        = "STAMP_OIDC_AUDIENCE"
	EnvOIDCWorkloadClients = "STAMP_OIDC_WORKLOAD_CLIENTS"
	EnvOIDCAlgorithms      = "STAMP_OIDC_ALGORITHMS"
	EnvOIDCACRValues       = "STAMP_OIDC_ACR_VALUES"
	EnvOIDCAllowInsecure   = "STAMP_OIDC_ALLOW_INSECURE_TRANSPORT"

	EnvFactSources       = "STAMP_FACT_SOURCES"
	EnvEgressAllow       = "STAMP_EGRESS_ALLOW"
	EnvEgressLoopback    = "STAMP_EGRESS_ALLOW_LOOPBACK"
	EnvEgressPrivate     = "STAMP_EGRESS_ALLOW_PRIVATE"
	EnvFactAllowFailOpen = "STAMP_FACT_ALLOW_FAIL_OPEN"

	EnvAuditFailClosed    = "STAMP_AUDIT_FAIL_CLOSED"
	EnvAuditCapacity      = "STAMP_AUDIT_CAPACITY"
	EnvAuditBatchSize     = "STAMP_AUDIT_BATCH_SIZE"
	EnvAuditFlushInterval = "STAMP_AUDIT_FLUSH_INTERVAL"

	EnvPolicyRefreshInterval   = "STAMP_POLICY_REFRESH_INTERVAL"
	EnvPolicyStalenessDeadline = "STAMP_POLICY_STALENESS_DEADLINE"

	EnvDecisionTTL    = "STAMP_DECISION_TTL"
	EnvMaxOutstanding = "STAMP_MAX_OUTSTANDING_DECISIONS"

	EnvFloorMinApprovers       = "STAMP_GOVERNANCE_MIN_APPROVERS"
	EnvFloorProposerMayApprove = "STAMP_GOVERNANCE_PROPOSER_MAY_APPROVE"
	EnvRevisionTTL             = "STAMP_REVISION_TTL"
	EnvReconcileInterval       = "STAMP_REVISION_RECONCILE_INTERVAL"
	EnvBootstrapWarnInterval   = "STAMP_BOOTSTRAP_WARN_INTERVAL"

	EnvCheckContextEntity   = "STAMP_CHECK_CONTEXT_ENTITY"
	EnvCheckPropertyAliases = "STAMP_CHECK_PROPERTY_ALIASES"
)

// ConfigFromEnv reads the deployment configuration from the process
// environment.
//
// Every failure is collected rather than reported one at a time: an operator
// filling in a deployment manifest should learn about all four missing
// variables at once instead of restarting the container four times.
func ConfigFromEnv() (Config, error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	cfg := Config{
		DSN:         strings.TrimSpace(os.Getenv(EnvDSN)),
		Migrate:     envBool(EnvMigrate, true, fail),
		ApplyGrants: envBool(EnvApplyGrants, true, fail),
		DBRoles: store.RoleNames{
			Check:    os.Getenv(EnvRoleCheck),
			Decide:   os.Getenv(EnvRoleDecide),
			Consumer: os.Getenv(EnvRoleConsume),
			Admin:    os.Getenv(EnvRoleAdmin),
		},
		InstanceID:              strings.TrimSpace(os.Getenv(EnvInstanceID)),
		WriterID:                strings.TrimSpace(os.Getenv(EnvWriterID)),
		MaxConns:                int32(envInt(EnvMaxConns, DefaultMaxConns, fail)), //nolint:gosec // bounded by envInt
		AllowFactFailOpen:       envBool(EnvFactAllowFailOpen, false, fail),
		AuditFailClosed:         envBool(EnvAuditFailClosed, true, fail),
		AuditCapacity:           envInt(EnvAuditCapacity, 0, fail),
		AuditBatchSize:          envInt(EnvAuditBatchSize, 0, fail),
		AuditFlushInterval:      envDuration(EnvAuditFlushInterval, 0, fail),
		PolicyRefreshInterval:   envDuration(EnvPolicyRefreshInterval, 0, fail),
		PolicyStalenessDeadline: envDuration(EnvPolicyStalenessDeadline, 0, fail),
		DecisionTTL:             envDuration(EnvDecisionTTL, 0, fail),
		MaxOutstanding:          envInt(EnvMaxOutstanding, 0, fail),
		RevisionTTL:             envDuration(EnvRevisionTTL, 0, fail),
		ReconcileInterval:       envDuration(EnvReconcileInterval, DefaultReconcileInterval, fail),
		BootstrapWarnInterval:   envDuration(EnvBootstrapWarnInterval, 0, fail),
		CheckContextEntity:      strings.TrimSpace(os.Getenv(EnvCheckContextEntity)),
		GovernanceFloor: revision.Floor{
			MinApprovers:       envInt(EnvFloorMinApprovers, revision.DefaultFloor().MinApprovers, fail),
			ProposerMayApprove: envBool(EnvFloorProposerMayApprove, false, fail),
		},
		Addresses: map[api.Surface]string{},
	}

	if cfg.DSN == "" {
		fail("%s is required: stamp has no database it could default to", EnvDSN)
	}
	// A surface is bound to its default unless the variable is present. Setting
	// it to nothing is how a PEP tier runs with no console reachable anywhere,
	// so an explicitly empty value unbinds rather than falling back.
	if addr := envAddr(EnvPEPAddr, DefaultPEPAddr); addr != "" {
		cfg.Addresses[api.SurfacePEP] = addr
	}
	if addr := envAddr(EnvConsoleAddr, DefaultConsoleAddr); addr != "" {
		cfg.Addresses[api.SurfaceConsole] = addr
	}
	if addr := envAddr(EnvCallbackAddr, ""); addr != "" {
		cfg.Addresses[api.SurfaceCallback] = addr
	}

	cfg.OIDC = OIDCConfig{
		Audience:               strings.TrimSpace(os.Getenv(EnvOIDCAudience)),
		Algorithms:             splitList(envString(EnvOIDCAlgorithms, "RS256,ES256")),
		AllowedACRValues:       splitList(os.Getenv(EnvOIDCACRValues)),
		AllowInsecureTransport: envBool(EnvOIDCAllowInsecure, false, fail),
	}
	issuer := strings.TrimSpace(os.Getenv(EnvOIDCIssuer))
	jwks := strings.TrimSpace(os.Getenv(EnvOIDCJWKSURL))
	switch {
	case issuer == "":
		fail("%s is required: token verification has no issuer it could default to", EnvOIDCIssuer)
	case jwks == "":
		fail("%s is required: %s names an issuer with no key set endpoint", EnvOIDCJWKSURL, EnvOIDCIssuer)
	default:
		cfg.OIDC.Issuers = []IssuerConfig{{
			Issuer:          issuer,
			JWKSURL:         jwks,
			WorkloadClients: splitList(os.Getenv(EnvOIDCWorkloadClients)),
		}}
	}
	if cfg.OIDC.Audience == "" {
		fail("%s is required: a token with no audience check is a token from anywhere", EnvOIDCAudience)
	}

	cfg.Egress = fact.EgressConfig{
		Allow:         splitList(os.Getenv(EnvEgressAllow)),
		AllowLoopback: envBool(EnvEgressLoopback, false, fail),
		AllowPrivate:  envBool(EnvEgressPrivate, false, fail),
	}
	decls, err := factSourcesFrom(os.Getenv(EnvFactSources))
	if err != nil {
		fail("%s: %w", EnvFactSources, err)
	}
	cfg.FactSources = decls

	aliases, err := aliasesFrom(os.Getenv(EnvCheckPropertyAliases))
	if err != nil {
		fail("%s: %w", EnvCheckPropertyAliases, err)
	}
	cfg.CheckPropertyAliases = aliases

	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return cfg, nil
}

// withDefaults fills in the values Assemble needs and the environment need not
// supply.
func (c Config) withDefaults() Config {
	if c.MaxConns <= 0 {
		c.MaxConns = DefaultMaxConns
	}
	if c.InstanceID == "" {
		c.InstanceID = hostname()
	}
	if c.WriterID == "" {
		c.WriterID = writerIDFor(c.InstanceID)
	}
	if c.ReconcileInterval <= 0 {
		c.ReconcileInterval = DefaultReconcileInterval
	}
	if len(c.OIDC.Algorithms) == 0 {
		c.OIDC.Algorithms = []string{"RS256", "ES256"}
	}
	if c.GovernanceFloor.MinApprovers <= 0 {
		c.GovernanceFloor.MinApprovers = revision.DefaultFloor().MinApprovers
	}
	return c
}

// validate refuses a configuration that could only fail later, and in a place
// where the cause would be harder to read.
func (c Config) validate() error {
	var errs []error
	if strings.TrimSpace(c.DSN) == "" {
		errs = append(errs, fmt.Errorf("a database connection string is required (%s)", EnvDSN))
	}
	if len(c.OIDC.Issuers) == 0 {
		errs = append(errs, fmt.Errorf("at least one OIDC issuer is required (%s)", EnvOIDCIssuer))
	}
	if strings.TrimSpace(c.OIDC.Audience) == "" {
		errs = append(errs, fmt.Errorf("an OIDC audience is required (%s)", EnvOIDCAudience))
	}
	if len(c.Addresses) == 0 {
		errs = append(errs, fmt.Errorf("no surface has a listen address: set at least one of %s, %s, %s",
			EnvPEPAddr, EnvConsoleAddr, EnvCallbackAddr))
	}
	for surface := range c.Addresses {
		if !surface.Valid() {
			errs = append(errs, fmt.Errorf("unknown listener surface %q", surface))
		}
	}
	return errors.Join(errs...)
}

// ---------------------------------------------------------------------------
// fact source declarations
//
// A source's transport — the call target, the TTL, the timeout — is deployment
// configuration and not part of the policy schema, which carries only the
// signature. That split is R35: a policy author names a source, an operator
// decides what that source is allowed to reach.
// ---------------------------------------------------------------------------

type factSourceJSON struct {
	Name    string      `json:"name"`
	Kind    string      `json:"kind"`
	Params  []paramJSON `json:"params,omitempty"`
	Returns string      `json:"returns"`
	OnError string      `json:"on_error,omitempty"`
	TTL     string      `json:"ttl,omitempty"`
	Timeout string      `json:"timeout,omitempty"`
	URL     string      `json:"url,omitempty"`
	Values  []any       `json:"values,omitempty"`
}

type paramJSON struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// factSourcesFrom reads the declaration list. The value is either a JSON
// document or a path to one, decided by its first character: a container hands
// this in as a mounted file, and a laptop as a literal.
func factSourcesFrom(spec string) ([]fact.Declaration, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, nil
	}
	raw := []byte(trimmed)
	if !strings.HasPrefix(trimmed, "[") {
		data, err := os.ReadFile(trimmed) //nolint:gosec // an operator-supplied configuration path
		if err != nil {
			return nil, fmt.Errorf("read fact source declarations: %w", err)
		}
		raw = data
	}
	var docs []factSourceJSON
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&docs); err != nil {
		return nil, fmt.Errorf("decode fact source declarations: %w", err)
	}
	out := make([]fact.Declaration, 0, len(docs))
	for _, d := range docs {
		decl := fact.Declaration{
			Name:    d.Name,
			Kind:    policy.SourceKind(d.Kind),
			Returns: policy.Type(d.Returns),
			OnError: policy.OnError(d.OnError),
			URL:     d.URL,
			Values:  d.Values,
		}
		for _, p := range d.Params {
			decl.Params = append(decl.Params, policy.Param{Name: p.Name, Type: policy.Type(p.Type)})
		}
		var err error
		if decl.TTL, err = parseOptionalDuration(d.TTL); err != nil {
			return nil, fmt.Errorf("source %q: ttl: %w", d.Name, err)
		}
		if decl.Timeout, err = parseOptionalDuration(d.Timeout); err != nil {
			return nil, fmt.Errorf("source %q: timeout: %w", d.Name, err)
		}
		out = append(out, decl)
	}
	return out, nil
}

func parseOptionalDuration(spec string) (time.Duration, error) {
	if strings.TrimSpace(spec) == "" {
		return 0, nil
	}
	return time.ParseDuration(spec)
}

// aliasesFrom reads the AuthZEN property alias table, written as
// "incoming=attribute,other=attr".
func aliasesFrom(spec string) (map[string]string, error) {
	entries := splitList(spec)
	if len(entries) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		from, to, ok := strings.Cut(entry, "=")
		from, to = strings.TrimSpace(from), strings.TrimSpace(to)
		if !ok || from == "" || to == "" {
			return nil, fmt.Errorf("entry %q is not of the form incoming=attribute", entry)
		}
		out[from] = to
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// environment plumbing
// ---------------------------------------------------------------------------

func envString(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// envAddr reads a listen address, where "present but empty" and "absent" mean
// different things: the first unbinds the surface, the second takes the
// default.
func envAddr(key, fallback string) string {
	raw, present := os.LookupEnv(key)
	if !present {
		return fallback
	}
	return strings.TrimSpace(raw)
}

func envBool(key string, fallback bool, fail func(string, ...any)) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		fail("%s: %q is not a boolean", key, raw)
		return fallback
	}
	return v
}

func envInt(key string, fallback int, fail func(string, ...any)) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		fail("%s: %q is not an integer", key, raw)
		return fallback
	}
	return v
}

func envDuration(key string, fallback time.Duration, fail func(string, ...any)) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		fail("%s: %q is not a duration", key, raw)
		return fallback
	}
	return v
}

func splitList(spec string) []string {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	parts := strings.Split(spec, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func hostname() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "unknown"
	}
	return host
}

// writerIDFor derives an audit writer identifier from a host name.
//
// The store holds writer identifiers to [A-Za-z0-9._-] starting alphanumeric,
// and a Kubernetes pod name is already within it, so this only has to replace
// what a hand-set hostname might carry.
func writerIDFor(instance string) string {
	var b strings.Builder
	for _, r := range instance {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	id := strings.TrimLeft(b.String(), ".-_")
	if id == "" {
		return "stamp"
	}
	if len(id) > 64 {
		id = id[:64]
	}
	return id
}
