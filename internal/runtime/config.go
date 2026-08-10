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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/fact/idpgroup"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
	"github.com/d0lim/stamp/internal/stream"
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

	// DefaultIngestAdapterName and DefaultKafkaAdapterName are the names a
	// velocity source declaration joins its ingestion adapter on. They have
	// defaults because a single-adapter deployment has nothing to disambiguate,
	// and an operator who runs both still writes the name in one place.
	DefaultIngestAdapterName = "http-ingest"
	DefaultKafkaAdapterName  = "kafka"

	// DefaultRetentionSweepInterval is how often the dedup index and the bucket
	// table are swept of rows past the retention horizon.
	//
	// Correctness does not depend on the sweep — the port refuses an event
	// older than the widest declarable window, so nothing outside the horizon
	// can affect an answer — but unbounded growth does, and the sweep is the
	// only caller those two statements have.
	DefaultRetentionSweepInterval = time.Hour
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

	// StreamSources are the deployment's velocity source declarations: which
	// metric each declared event source reads, how wide its buckets are, which
	// ingestion adapter feeds it. A schema that declares an event source this
	// list does not configure is refused at load, exactly as a synchronous one
	// is — and a deployment that configures none refuses every event source,
	// which is the shape that keeps the kind from being checked by nobody.
	StreamSources []stream.Declaration
	// IngestCredentials are the HTTP ingest grants. A credential is bound to
	// the (source, metric) pairs it may write and separately to whether it may
	// send a deduction.
	//
	// CallerID is the identifier the identity layer derives from a verified
	// token — `workload:<issuer>#<sub>` — and not the bare `sub`. A subject
	// identifier is unique only inside its issuer, so an ingest grant written
	// against a bare one would be a grant to whoever holds that name at any
	// pinned IdP.
	IngestCredentials []stream.IngestCredential
	// IngestAdapterName is the HTTP ingest adapter's name, which is what a
	// source declaration joins on. Empty selects DefaultIngestAdapterName.
	IngestAdapterName string
	// IngestRate and IngestSubjectRate are the deployment defaults a credential
	// that configured none inherits. Zero leaves that credential unlimited,
	// which is only reachable when an operator configured no limit at all.
	IngestRate        stream.RateLimit
	IngestSubjectRate stream.RateLimit
	// IngestMaxBatchEvents caps one ingest batch. Zero selects the stream
	// package's default.
	IngestMaxBatchEvents int
	// IngestMaxRequestBytes bounds an ingest request body. It is a separate
	// bound from the event cap because it is the one that applies before the
	// body has been parsed. Zero selects the api package's default.
	IngestMaxRequestBytes int64

	// Kafka is the optional broker ingestion adapter. It is optional in the
	// strong sense: with no brokers configured the deployment still ingests
	// over HTTP, which is what removes the broker from the demo bundle.
	Kafka KafkaConfig

	// RetentionSweepInterval is how often the consumer role prunes dedup rows
	// and buckets past the retention horizon. Zero selects
	// DefaultRetentionSweepInterval.
	RetentionSweepInterval time.Duration

	// IdPGroupSources are the deployment's group directory sources. The
	// directory credential lives here and nowhere else: a policy document can
	// name a source but can never name or reach what it is pointed at (D21).
	IdPGroupSources []idpgroup.Declaration
	// IdPGroupMaxTTL lowers the cap on how stale a membership answer may be.
	// Zero selects the idpgroup package's default. An operator may lower it; a
	// policy author cannot raise it.
	IdPGroupMaxTTL time.Duration

	// ApproverIssuer designates the IdP a bare approver identifier in a policy
	// belongs to.
	//
	// A policy that writes `{members: [alice]}` has named an identity only
	// relative to an issuer: OIDC promises `sub` is unique inside one issuer
	// and says nothing across two. A deployment that pins exactly one issuer
	// has already answered the question and needs none of this. A deployment
	// that pins several genuinely has not, and the challenge handlers refuse a
	// bare set until it is answered — so this is where the answer goes.
	//
	// It must name one of the pinned issuers. Naming an unpinned one would
	// designate an IdP whose tokens this process rejects, which produces a
	// quorum nobody can satisfy rather than the misconfiguration it is.
	ApproverIssuer string

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

	// AuthoringMode is which authoring paths this installation accepts policy
	// writes from (R49). Empty selects [revision.AuthoringBoth].
	//
	// It is validated rather than defaulted: a misspelling that fell back to
	// the default would open the window an operator wrote this setting down in
	// order to close, and it would do it silently. `file` closes the console's
	// policy authoring, `console` closes the file path's apply, and neither
	// closes the approval inbox, the audit views, the dry run or the lock —
	// which is why an operator who turns on `file` at install time is not
	// stuck in solo-admin governance.
	AuthoringMode revision.AuthoringMode

	// CapabilityClaim is the verified token claim the export gate reads a
	// caller's entitlements from (R48). Empty selects
	// [revision.DefaultCapabilityClaim].
	//
	// Naming the claim is not the same as granting anything: the gate stays
	// fail-closed per caller, so a token that carries no such claim — or
	// carries it without `policy.author` or `audit.read` in it — holds no
	// capability and its export is refused and audited. A deployment that
	// points this at a claim its IdP does not issue has configured the refusal
	// of every export, which is the safe direction to be wrong in.
	CapabilityClaim string

	// RevisionRate bounds how often one authoring origin may take the
	// serialization gate. A zero field selects [revision.DefaultRate].
	RevisionRate revision.Rate

	// ApplyLimits bound a file apply payload (R45). A zero field selects the
	// governance default for that field, so an operator raises the one limit
	// their repository outgrew without restating the other five.
	ApplyLimits revision.PayloadLimits

	// AuditorClaim and AuditorValues are R22's auditor standing rule, enforced
	// server-side by the audit console.
	//
	// They default to the console's role claim and its auditor spellings, so a
	// deployment that configured console navigation has configured enforcement
	// too and the two cannot silently disagree. An operator whose auditors are
	// an IdP group points AuditorClaim at the group claim and names the group
	// in AuditorValues; nothing else changes.
	AuditorClaim  string
	AuditorValues []string

	// CheckContextEntity is the entity type an AuthZEN request context binds
	// to. Empty means requests carry no context entity.
	CheckContextEntity string
	// CheckPropertyAliases renames incoming AuthZEN property keys before they
	// are looked up against the schema.
	CheckPropertyAliases map[string]string

	// ExternalTargets is the operator's webhook destination list. A policy
	// naming a target that is not on it is refused at issue (D21): the author
	// selects a destination, the operator decides what that destination is.
	ExternalTargets []challenge.ExternalTarget
	// CallbackBaseURL is this deployment's externally reachable callback base,
	// told to an external target and used to build the step-up redirect a
	// completion comes back to. Empty leaves both to out-of-band configuration.
	CallbackBaseURL string

	// MFA is the delegated step-up configuration. It is optional, and the
	// consequence of leaving it out is that the mfa challenge kind has no
	// handler at all — which is fail-closed: a policy declaring one cannot be
	// satisfied and therefore cannot be issued.
	MFA MFAConfig

	// Console is what the console-serving role hands the browser. It is
	// optional: an all-in-one install serves the console from the same origin
	// as its API and needs none of it set.
	Console ConsoleConfig
}

// ConsoleConfig is the operator configuration the console bundle boots from.
//
// It exists as its own struct because of R50. The console's API base address
// has to be configurable — D19's separability promise is empty if the bundle
// can only ever call its own origin — and it has to come from here and nowhere
// else. A query string, a fragment or a localStorage entry would all be
// writable by whoever can send an approver a link, and a console that read its
// base address from one of them would forward that approver's token to whatever
// the link named.
type ConsoleConfig struct {
	// APIBaseURL is where the bundle sends its API calls. Empty means the same
	// origin the bundle was served from, which is the single-container install.
	APIBaseURL string

	// Issuer, AuthorizationEndpoint, TokenEndpoint and ClientID are the
	// browser-side relying party. They are separate from [OIDCConfig] because
	// that one says which tokens this process accepts and this one says which
	// IdP an operator is sent to; a deployment accepting two issuers still logs
	// its operators in through one.
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	EndSessionEndpoint    string
	ClientID              string
	// Scopes overrides what the console asks for. Empty asks for openid,
	// profile and email.
	Scopes []string
	// RoleClaim names the claim the console derives navigation and default
	// landing from. Empty selects "roles".
	RoleClaim string

	// AllowInsecureTransport permits plaintext console endpoints, for loopback
	// development and tests.
	AllowInsecureTransport bool
}

// KafkaConfig is the broker ingestion adapter's deployment configuration.
//
// The topic bindings carry the caller identity rather than reading one off a
// record, because the caller namespaces the dedup key: a record that could name
// its own caller could claim another producer's namespace and suppress its
// events. Which producers may write a topic is the broker's ACLs to enforce,
// and D17 makes those mandatory rather than advisory — without them the topic
// is an unauthenticated write to somebody's velocity aggregate.
type KafkaConfig struct {
	// Brokers are the seed broker addresses. A non-empty list is what asks for
	// the adapter at all.
	Brokers []string
	// Group is the consumer group. Required when Brokers is set.
	Group string
	// Topics binds each consumed topic to a velocity source and to the caller
	// identity the broker admits as producer on it.
	Topics []stream.KafkaTopic
	// AdapterName is the name a source declaration joins on. Empty selects
	// DefaultKafkaAdapterName.
	AdapterName string
	// PollRecords caps one poll, and therefore one aggregation transaction.
	// Zero selects the stream package's default.
	PollRecords int
}

// Configured reports whether a broker adapter was asked for.
func (k KafkaConfig) Configured() bool { return len(k.Brokers) > 0 }

// validate refuses a broker configuration that could only fail at the first
// poll, which is after the process reported itself healthy.
func (k KafkaConfig) validate() []error {
	if !k.Configured() {
		return nil
	}
	var errs []error
	if strings.TrimSpace(k.Group) == "" {
		errs = append(errs, fmt.Errorf("%s is set but %s is not: a consumer with no group cannot commit a position",
			EnvKafkaBrokers, EnvKafkaGroup))
	}
	if len(k.Topics) == 0 {
		errs = append(errs, fmt.Errorf("%s is set but %s binds no topic to a source", EnvKafkaBrokers, EnvKafkaTopics))
	}
	return errs
}

// MFAConfig is the delegated MFA trust boundary and transport.
//
// It is separate from [OIDCConfig] on purpose. OIDCConfig says which tokens
// this deployment accepts at all; this says which authentication satisfies a
// step-up challenge, and the second is narrower than the first by construction.
type MFAConfig struct {
	// AllowedACRValues is the operator allowlist of authentication context
	// classes. It is what makes the whole handler exist: U0 established that an
	// IdP silently downgrades an `acr` request it cannot satisfy, so an empty
	// allowlist is a deployment where a password login satisfies a step-up.
	// [mfa.NewDelegated] refuses an empty one, and so does this configuration.
	AllowedACRValues []string
	// RequiredAMR, when non-empty, is compared against a completion that
	// reports `amr` at all. U0 found the claim empty by default, so it is never
	// required to be present.
	RequiredAMR []string

	// AuthorizationEndpoint, ClientID and RedirectURI are the step-up half
	// (D26's default demo path). All three are required for the handler to be
	// built.
	AuthorizationEndpoint string
	ClientID              string
	RedirectURI           string
	// Scopes overrides what a step-up asks for. Empty asks for `openid` only.
	Scopes []string

	// Issuer, TokenClientID and Audience pin the party a completion token must
	// come from. Empty values fall back to the deployment's OIDC issuer, the
	// step-up client and the OIDC audience, which is the arrangement a
	// single-IdP install has.
	Issuer        string
	TokenClientID string
	Audience      string

	// CIBA is the backchannel transport. It is optional and tried first when
	// configured: D26 demoted it to a contract with a client because no
	// self-hostable IdP ships the decoupled authentication server it needs, and
	// [mfa.NewFallback] drops through to the step-up on
	// [mfa.ErrInitiationUnsupported].
	CIBA CIBAConfig

	// AllowInsecureTransport permits plaintext step-up and CIBA endpoints. It
	// exists for loopback development and tests.
	AllowInsecureTransport bool
}

// Configured reports whether the deployment asked for a delegated MFA handler.
func (m MFAConfig) Configured() bool {
	return len(m.AllowedACRValues) > 0 || strings.TrimSpace(m.AuthorizationEndpoint) != "" ||
		strings.TrimSpace(m.ClientID) != "" || m.CIBA.Configured()
}

// CIBAConfig is the backchannel authentication client's configuration.
type CIBAConfig struct {
	BackchannelEndpoint string
	TokenEndpoint       string
	ClientID            string
	ClientSecret        string
	Scope               string
}

// Configured reports whether a CIBA client was asked for.
func (c CIBAConfig) Configured() bool { return strings.TrimSpace(c.BackchannelEndpoint) != "" }

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

	EnvStreamSources      = "STAMP_STREAM_SOURCES"
	EnvIngestCredentials  = "STAMP_INGEST_CREDENTIALS" //nolint:gosec // a variable name, not a credential
	EnvIngestAdapterName  = "STAMP_INGEST_ADAPTER_NAME"
	EnvIngestRate         = "STAMP_INGEST_RATE_PER_SECOND"
	EnvIngestBurst        = "STAMP_INGEST_RATE_BURST"
	EnvIngestSubjectRate  = "STAMP_INGEST_SUBJECT_RATE_PER_SECOND"
	EnvIngestSubjectBurst = "STAMP_INGEST_SUBJECT_RATE_BURST"
	EnvIngestMaxBatch     = "STAMP_INGEST_MAX_BATCH_EVENTS"
	EnvIngestMaxBytes     = "STAMP_INGEST_MAX_REQUEST_BYTES"

	EnvKafkaBrokers     = "STAMP_KAFKA_BROKERS"
	EnvKafkaGroup       = "STAMP_KAFKA_GROUP"
	EnvKafkaTopics      = "STAMP_KAFKA_TOPICS"
	EnvKafkaAdapterName = "STAMP_KAFKA_ADAPTER_NAME"
	EnvKafkaPollRecords = "STAMP_KAFKA_POLL_RECORDS"

	EnvRetentionSweepInterval = "STAMP_RETENTION_SWEEP_INTERVAL"

	EnvIdPGroupSources = "STAMP_IDP_GROUP_SOURCES"
	EnvIdPGroupMaxTTL  = "STAMP_IDP_GROUP_MAX_TTL"

	EnvApproverIssuer = "STAMP_APPROVER_ISSUER"

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

	EnvAuthoringMode   = "STAMP_AUTHORING_MODE"
	EnvCapabilityClaim = "STAMP_CAPABILITY_CLAIM"

	EnvRevisionRateWindow = "STAMP_REVISION_RATE_WINDOW"
	EnvRevisionRateBurst  = "STAMP_REVISION_RATE_BURST"

	EnvApplyMaxDocuments      = "STAMP_APPLY_MAX_DOCUMENTS"
	EnvApplyMaxDocumentBytes  = "STAMP_APPLY_MAX_DOCUMENT_BYTES"
	EnvApplyMaxTotalBytes     = "STAMP_APPLY_MAX_TOTAL_BYTES"
	EnvApplyMaxPolicies       = "STAMP_APPLY_MAX_POLICIES"
	EnvApplyMaxConditionNodes = "STAMP_APPLY_MAX_CONDITION_NODES"
	EnvApplyMaxConditionDepth = "STAMP_APPLY_MAX_CONDITION_DEPTH"

	EnvAuditorClaim  = "STAMP_AUDITOR_CLAIM"
	EnvAuditorValues = "STAMP_AUDITOR_VALUES"

	EnvCheckContextEntity   = "STAMP_CHECK_CONTEXT_ENTITY"
	EnvCheckPropertyAliases = "STAMP_CHECK_PROPERTY_ALIASES"

	EnvExternalTargets = "STAMP_EXTERNAL_TARGETS"
	EnvCallbackBaseURL = "STAMP_CALLBACK_BASE_URL"

	EnvMFAACRValues     = "STAMP_MFA_ACR_VALUES"
	EnvMFARequiredAMR   = "STAMP_MFA_REQUIRED_AMR"
	EnvMFAAuthzEndpoint = "STAMP_MFA_AUTHORIZATION_ENDPOINT"
	EnvMFAClientID      = "STAMP_MFA_CLIENT_ID"
	EnvMFARedirectURI   = "STAMP_MFA_REDIRECT_URI"
	EnvMFAScopes        = "STAMP_MFA_SCOPES"
	EnvMFAIssuer        = "STAMP_MFA_TOKEN_ISSUER"
	EnvMFATokenClientID = "STAMP_MFA_TOKEN_CLIENT_ID" //nolint:gosec // a variable name, not a credential
	EnvMFAAudience      = "STAMP_MFA_TOKEN_AUDIENCE"
	EnvMFAAllowInsecure = "STAMP_MFA_ALLOW_INSECURE_TRANSPORT"

	EnvCIBABackchannel  = "STAMP_MFA_CIBA_BACKCHANNEL_ENDPOINT"
	EnvCIBATokenURL     = "STAMP_MFA_CIBA_TOKEN_ENDPOINT" //nolint:gosec // a variable name, not a credential
	EnvCIBAClientID     = "STAMP_MFA_CIBA_CLIENT_ID"
	EnvCIBAClientSecret = "STAMP_MFA_CIBA_CLIENT_SECRET" //nolint:gosec // a variable name, not a credential
	EnvCIBAScope        = "STAMP_MFA_CIBA_SCOPE"

	// The console's operator configuration. R50 makes this the only source for
	// the API base address: there is deliberately no browser-side override.
	EnvConsoleAPIBaseURL    = "STAMP_CONSOLE_API_BASE_URL"
	EnvConsoleOIDCIssuer    = "STAMP_CONSOLE_OIDC_ISSUER"
	EnvConsoleOIDCAuthz     = "STAMP_CONSOLE_OIDC_AUTHORIZATION_ENDPOINT"
	EnvConsoleOIDCToken     = "STAMP_CONSOLE_OIDC_TOKEN_ENDPOINT" //nolint:gosec // a variable name, not a credential
	EnvConsoleOIDCEndSess   = "STAMP_CONSOLE_OIDC_END_SESSION_ENDPOINT"
	EnvConsoleOIDCClientID  = "STAMP_CONSOLE_OIDC_CLIENT_ID"
	EnvConsoleOIDCScopes    = "STAMP_CONSOLE_OIDC_SCOPES"
	EnvConsoleRoleClaim     = "STAMP_CONSOLE_ROLE_CLAIM"
	EnvConsoleAllowInsecure = "STAMP_CONSOLE_ALLOW_INSECURE_TRANSPORT"
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
		AuditorClaim:            strings.TrimSpace(os.Getenv(EnvAuditorClaim)),
		AuditorValues:           splitList(os.Getenv(EnvAuditorValues)),
		CheckContextEntity:      strings.TrimSpace(os.Getenv(EnvCheckContextEntity)),
		CapabilityClaim:         strings.TrimSpace(os.Getenv(EnvCapabilityClaim)),
		RevisionRate: revision.Rate{
			Window: envDuration(EnvRevisionRateWindow, 0, fail),
			Burst:  envInt(EnvRevisionRateBurst, 0, fail),
		},
		ApplyLimits: revision.PayloadLimits{
			MaxDocuments:      envInt(EnvApplyMaxDocuments, 0, fail),
			MaxDocumentBytes:  envInt(EnvApplyMaxDocumentBytes, 0, fail),
			MaxTotalBytes:     envInt(EnvApplyMaxTotalBytes, 0, fail),
			MaxPolicies:       envInt(EnvApplyMaxPolicies, 0, fail),
			MaxConditionNodes: envInt(EnvApplyMaxConditionNodes, 0, fail),
			MaxConditionDepth: envInt(EnvApplyMaxConditionDepth, 0, fail),
		},
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

	streamDecls, err := streamSourcesFrom(os.Getenv(EnvStreamSources))
	if err != nil {
		fail("%s: %w", EnvStreamSources, err)
	}
	cfg.StreamSources = streamDecls
	creds, err := ingestCredentialsFrom(os.Getenv(EnvIngestCredentials))
	if err != nil {
		fail("%s: %w", EnvIngestCredentials, err)
	}
	cfg.IngestCredentials = creds
	cfg.IngestAdapterName = strings.TrimSpace(os.Getenv(EnvIngestAdapterName))
	cfg.IngestRate = stream.RateLimit{
		PerSecond: envFloat(EnvIngestRate, fail),
		Burst:     envFloat(EnvIngestBurst, fail),
	}
	cfg.IngestSubjectRate = stream.RateLimit{
		PerSecond: envFloat(EnvIngestSubjectRate, fail),
		Burst:     envFloat(EnvIngestSubjectBurst, fail),
	}
	cfg.IngestMaxBatchEvents = envInt(EnvIngestMaxBatch, 0, fail)
	cfg.IngestMaxRequestBytes = int64(envInt(EnvIngestMaxBytes, 0, fail))
	cfg.RetentionSweepInterval = envDuration(EnvRetentionSweepInterval, DefaultRetentionSweepInterval, fail)

	topics, err := kafkaTopicsFrom(os.Getenv(EnvKafkaTopics))
	if err != nil {
		fail("%s: %w", EnvKafkaTopics, err)
	}
	cfg.Kafka = KafkaConfig{
		Brokers:     splitList(os.Getenv(EnvKafkaBrokers)),
		Group:       strings.TrimSpace(os.Getenv(EnvKafkaGroup)),
		Topics:      topics,
		AdapterName: strings.TrimSpace(os.Getenv(EnvKafkaAdapterName)),
		PollRecords: envInt(EnvKafkaPollRecords, 0, fail),
	}

	groups, err := idpGroupSourcesFrom(os.Getenv(EnvIdPGroupSources))
	if err != nil {
		fail("%s: %w", EnvIdPGroupSources, err)
	}
	cfg.IdPGroupSources = groups
	cfg.IdPGroupMaxTTL = envDuration(EnvIdPGroupMaxTTL, 0, fail)
	cfg.ApproverIssuer = strings.TrimSpace(os.Getenv(EnvApproverIssuer))

	// An unreadable authoring mode is a startup failure and never a fallback to
	// the permissive default: `both` is what an operator who set this variable
	// was trying not to run, so accepting a misspelling as `both` would open
	// exactly the window the setting closes, and say nothing while doing it.
	mode, err := revision.ParseAuthoringMode(strings.TrimSpace(os.Getenv(EnvAuthoringMode)))
	if err != nil {
		fail("%s: %w", EnvAuthoringMode, err)
	}
	cfg.AuthoringMode = mode

	aliases, err := aliasesFrom(os.Getenv(EnvCheckPropertyAliases))
	if err != nil {
		fail("%s: %w", EnvCheckPropertyAliases, err)
	}
	cfg.CheckPropertyAliases = aliases

	targets, err := externalTargetsFrom(os.Getenv(EnvExternalTargets))
	if err != nil {
		fail("%s: %w", EnvExternalTargets, err)
	}
	cfg.ExternalTargets = targets
	cfg.CallbackBaseURL = strings.TrimSpace(os.Getenv(EnvCallbackBaseURL))

	cfg.MFA = MFAConfig{
		AllowedACRValues:       splitList(os.Getenv(EnvMFAACRValues)),
		RequiredAMR:            splitList(os.Getenv(EnvMFARequiredAMR)),
		AuthorizationEndpoint:  strings.TrimSpace(os.Getenv(EnvMFAAuthzEndpoint)),
		ClientID:               strings.TrimSpace(os.Getenv(EnvMFAClientID)),
		RedirectURI:            strings.TrimSpace(os.Getenv(EnvMFARedirectURI)),
		Scopes:                 splitList(os.Getenv(EnvMFAScopes)),
		Issuer:                 strings.TrimSpace(os.Getenv(EnvMFAIssuer)),
		TokenClientID:          strings.TrimSpace(os.Getenv(EnvMFATokenClientID)),
		Audience:               strings.TrimSpace(os.Getenv(EnvMFAAudience)),
		AllowInsecureTransport: envBool(EnvMFAAllowInsecure, false, fail),
		CIBA: CIBAConfig{
			BackchannelEndpoint: strings.TrimSpace(os.Getenv(EnvCIBABackchannel)),
			TokenEndpoint:       strings.TrimSpace(os.Getenv(EnvCIBATokenURL)),
			ClientID:            strings.TrimSpace(os.Getenv(EnvCIBAClientID)),
			ClientSecret:        os.Getenv(EnvCIBAClientSecret),
			Scope:               strings.TrimSpace(os.Getenv(EnvCIBAScope)),
		},
	}

	cfg.Console = ConsoleConfig{
		APIBaseURL:             strings.TrimSpace(os.Getenv(EnvConsoleAPIBaseURL)),
		Issuer:                 strings.TrimSpace(os.Getenv(EnvConsoleOIDCIssuer)),
		AuthorizationEndpoint:  strings.TrimSpace(os.Getenv(EnvConsoleOIDCAuthz)),
		TokenEndpoint:          strings.TrimSpace(os.Getenv(EnvConsoleOIDCToken)),
		EndSessionEndpoint:     strings.TrimSpace(os.Getenv(EnvConsoleOIDCEndSess)),
		ClientID:               strings.TrimSpace(os.Getenv(EnvConsoleOIDCClientID)),
		Scopes:                 splitList(os.Getenv(EnvConsoleOIDCScopes)),
		RoleClaim:              strings.TrimSpace(os.Getenv(EnvConsoleRoleClaim)),
		AllowInsecureTransport: envBool(EnvConsoleAllowInsecure, false, fail),
	}

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
	if c.IngestAdapterName == "" {
		c.IngestAdapterName = DefaultIngestAdapterName
	}
	if c.Kafka.AdapterName == "" {
		c.Kafka.AdapterName = DefaultKafkaAdapterName
	}
	if c.RetentionSweepInterval <= 0 {
		c.RetentionSweepInterval = DefaultRetentionSweepInterval
	}
	// A declaration that names no adapter takes the HTTP one. That is the
	// deployment every install has — the Kafka adapter is the optional
	// dependency D20 keeps optional — so it is the only default that could be
	// filled in without guessing.
	if len(c.StreamSources) > 0 {
		decls := make([]stream.Declaration, len(c.StreamSources))
		copy(decls, c.StreamSources)
		for i := range decls {
			if decls[i].Adapter == "" {
				decls[i].Adapter = c.IngestAdapterName
			}
		}
		c.StreamSources = decls
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
	// An approver issuer that is not pinned would designate an IdP whose tokens
	// this process rejects: the quorum would open and no approval could ever
	// satisfy it, which is a policy-shaped failure with a configuration cause.
	if designated := strings.TrimSpace(c.ApproverIssuer); designated != "" {
		pinned := make([]string, 0, len(c.OIDC.Issuers))
		for _, iss := range c.OIDC.Issuers {
			pinned = append(pinned, iss.Issuer)
		}
		if !slices.Contains(pinned, designated) {
			errs = append(errs, fmt.Errorf(
				"%s designates %q, which %s does not pin: an approver issuer this process does not verify "+
					"tokens from is a quorum nobody can satisfy. pinned issuers: %s",
				EnvApproverIssuer, designated, EnvOIDCIssuer, strings.Join(pinned, ", ")))
		}
	}
	// Checked here as well as at the environment reader, because a Config built
	// in code — a test, an embedder — reaches Assemble without passing through
	// ConfigFromEnv, and the one thing this setting must never do is resolve an
	// unrecognized value to the permissive mode.
	if !c.AuthoringMode.OrDefault().Valid() {
		errs = append(errs, fmt.Errorf("%s is %q, want one of %v",
			EnvAuthoringMode, c.AuthoringMode, revision.AuthoringModes()))
	}
	errs = append(errs, c.Kafka.validate()...)
	errs = append(errs, c.MFA.validate(c.OIDC)...)
	return errors.Join(errs...)
}

// validate refuses a delegated MFA configuration that would produce a challenge
// nobody could satisfy.
//
// The last check is the one that is easy to get wrong and impossible to debug
// from the outside. [identity.Config].AllowedACRValues bounds *every* end-user
// token this deployment accepts, so if it is set at all it has to be a superset
// of the step-up classes — otherwise the callback's Verify rejects the
// completion before the mfa handler ever runs, and the operator sees a step-up
// that completes at the IdP and then bounces with a credential error rather than
// a challenge error. It has to be a superset of whatever console login returns
// too, but this side cannot know that value, so the failure is stated in the
// message rather than checked.
func (m MFAConfig) validate(oidc OIDCConfig) []error {
	if !m.Configured() {
		return nil
	}
	var errs []error
	if len(m.AllowedACRValues) == 0 {
		errs = append(errs, fmt.Errorf(
			"a delegated mfa handler needs a non-empty acr allowlist (%s): an idp downgrades an "+
				"unsatisfiable acr request silently, so an unchecked response is an unchecked authentication",
			EnvMFAACRValues))
	}
	for _, field := range []struct{ env, value string }{
		{EnvMFAAuthzEndpoint, m.AuthorizationEndpoint},
		{EnvMFAClientID, m.ClientID},
		{EnvMFARedirectURI, m.RedirectURI},
	} {
		if strings.TrimSpace(field.value) == "" {
			errs = append(errs, fmt.Errorf("delegated mfa is configured but %s is not set", field.env))
		}
	}
	if len(oidc.AllowedACRValues) > 0 {
		for _, want := range m.AllowedACRValues {
			if !slices.Contains(oidc.AllowedACRValues, want) {
				errs = append(errs, fmt.Errorf(
					"%s admits %q but the process-wide token allowlist %s does not: %s bounds every end-user "+
						"token, so a completion in that class is rejected by token verification before the mfa "+
						"handler sees it. %s must be a superset of %s and of whatever class console login returns",
					EnvMFAACRValues, want, EnvOIDCACRValues, EnvOIDCACRValues, EnvOIDCACRValues, EnvMFAACRValues))
			}
		}
	}
	return errs
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

// configDocs reads a JSON list from an operator-supplied value. The value is
// either the document itself or a path to one, decided by its first character:
// a container hands these in as a mounted file, and a laptop as a literal. A
// mounted file is the only sensible form for the two lists that carry a
// credential, and the same rule serves both so an operator learns it once.
//
// Unknown fields are refused rather than ignored. A misspelled key in a
// deployment manifest would otherwise be a setting silently left at its
// default, which for `allow_deduction` or `freshness` is a control that reads
// as configured and is not.
func configDocs[T any](label, spec string) ([]T, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, nil
	}
	raw := []byte(trimmed)
	if !strings.HasPrefix(trimmed, "[") {
		data, err := os.ReadFile(trimmed) //nolint:gosec // an operator-supplied configuration path
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", label, err)
		}
		raw = data
	}
	var docs []T
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&docs); err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	return docs, nil
}

// factSourcesFrom reads the synchronous source declaration list.
func factSourcesFrom(spec string) ([]fact.Declaration, error) {
	docs, err := configDocs[factSourceJSON]("fact source declarations", spec)
	if err != nil {
		return nil, err
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

// ---------------------------------------------------------------------------
// external targets
//
// Same split as the fact sources above, for the same reason (D21): a policy
// author names a target, and the operator decides what that target is, what key
// it is signed under and how long it may take.
// ---------------------------------------------------------------------------

type externalTargetJSON struct {
	Name          string `json:"name"`
	URL           string `json:"url"`
	Secret        string `json:"secret"`
	Timeout       string `json:"timeout,omitempty"`
	RespondWithin string `json:"respond_within,omitempty"`
}

// externalTargetsFrom reads the webhook destination list. A shared secret is
// not something a deployment should have to put in a manifest inline, which is
// what the path form is for.
func externalTargetsFrom(spec string) ([]challenge.ExternalTarget, error) {
	docs, err := configDocs[externalTargetJSON]("external targets", spec)
	if err != nil {
		return nil, err
	}
	out := make([]challenge.ExternalTarget, 0, len(docs))
	for _, d := range docs {
		target := challenge.ExternalTarget{Name: d.Name, URL: d.URL, Secret: d.Secret}
		if target.Timeout, err = parseOptionalDuration(d.Timeout); err != nil {
			return nil, fmt.Errorf("target %q: timeout: %w", d.Name, err)
		}
		if target.RespondWithin, err = parseOptionalDuration(d.RespondWithin); err != nil {
			return nil, fmt.Errorf("target %q: respond_within: %w", d.Name, err)
		}
		out = append(out, target)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// the ingestion plane
//
// Same split again, and here it is the sharpest one in the file. A velocity
// source's schema half is its name, parameters and return type; everything
// below — which metric it reads, how wide its buckets are, how far back its
// window reaches, which adapter feeds it, whether deductions are admitted — is
// deployment configuration. A policy author who could write those fields could
// point a limit at another tenant's metric, or widen the window until the limit
// stopped biting.
// ---------------------------------------------------------------------------

type streamSourceJSON struct {
	Name           string      `json:"name"`
	Metric         string      `json:"metric"`
	Adapter        string      `json:"adapter,omitempty"`
	Window         string      `json:"window"`
	BucketWidth    string      `json:"bucket_width"`
	Freshness      string      `json:"freshness,omitempty"`
	AllowDeduction bool        `json:"allow_deduction,omitempty"`
	Params         []paramJSON `json:"params,omitempty"`
	Returns        string      `json:"returns"`
	OnError        string      `json:"on_error,omitempty"`
}

// streamSourcesFrom reads the velocity source declarations.
func streamSourcesFrom(spec string) ([]stream.Declaration, error) {
	docs, err := configDocs[streamSourceJSON]("velocity source declarations", spec)
	if err != nil {
		return nil, err
	}
	out := make([]stream.Declaration, 0, len(docs))
	for _, d := range docs {
		decl := stream.Declaration{
			Name:           d.Name,
			Metric:         d.Metric,
			Adapter:        d.Adapter,
			AllowDeduction: d.AllowDeduction,
			Returns:        policy.Type(d.Returns),
			OnError:        policy.OnError(d.OnError),
		}
		for _, p := range d.Params {
			decl.Params = append(decl.Params, policy.Param{Name: p.Name, Type: policy.Type(p.Type)})
		}
		for _, field := range []struct {
			name string
			spec string
			into *time.Duration
		}{
			{"window", d.Window, &decl.Window},
			{"bucket_width", d.BucketWidth, &decl.BucketWidth},
			{"freshness", d.Freshness, &decl.Freshness},
		} {
			if *field.into, err = parseOptionalDuration(field.spec); err != nil {
				return nil, fmt.Errorf("source %q: %s: %w", d.Name, field.name, err)
			}
		}
		out = append(out, decl)
	}
	return out, nil
}

type rateLimitJSON struct {
	PerSecond float64 `json:"per_second"`
	Burst     float64 `json:"burst,omitempty"`
}

type scopeEntryJSON struct {
	Source string `json:"source"`
	Metric string `json:"metric"`
}

type ingestCredentialJSON struct {
	CallerID       string           `json:"caller_id"`
	Scope          []scopeEntryJSON `json:"scope"`
	AllowDeduction bool             `json:"allow_deduction,omitempty"`
	Rate           *rateLimitJSON   `json:"rate,omitempty"`
	SubjectRate    *rateLimitJSON   `json:"subject_rate,omitempty"`
}

// ingestCredentialsFrom reads the HTTP ingest grants.
func ingestCredentialsFrom(spec string) ([]stream.IngestCredential, error) {
	docs, err := configDocs[ingestCredentialJSON]("ingest credentials", spec)
	if err != nil {
		return nil, err
	}
	out := make([]stream.IngestCredential, 0, len(docs))
	for _, d := range docs {
		cred := stream.IngestCredential{CallerID: d.CallerID, AllowDeduction: d.AllowDeduction}
		for _, s := range d.Scope {
			cred.Scope = append(cred.Scope, stream.ScopeEntry{Source: s.Source, Metric: s.Metric})
		}
		if d.Rate != nil {
			cred.Rate = stream.RateLimit{PerSecond: d.Rate.PerSecond, Burst: d.Rate.Burst}
		}
		if d.SubjectRate != nil {
			cred.SubjectRate = stream.RateLimit{PerSecond: d.SubjectRate.PerSecond, Burst: d.SubjectRate.Burst}
		}
		out = append(out, cred)
	}
	return out, nil
}

type kafkaTopicJSON struct {
	Topic          string `json:"topic"`
	Source         string `json:"source"`
	CallerID       string `json:"caller_id"`
	AllowDeduction bool   `json:"allow_deduction,omitempty"`
}

// kafkaTopicsFrom reads the topic-to-source bindings.
func kafkaTopicsFrom(spec string) ([]stream.KafkaTopic, error) {
	docs, err := configDocs[kafkaTopicJSON]("kafka topic bindings", spec)
	if err != nil {
		return nil, err
	}
	out := make([]stream.KafkaTopic, 0, len(docs))
	for _, d := range docs {
		out = append(out, stream.KafkaTopic{
			Topic:          d.Topic,
			Source:         d.Source,
			CallerID:       d.CallerID,
			AllowDeduction: d.AllowDeduction,
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// idp group sources
//
// The credential below is the reason this list has its own reader rather than
// riding along with the synchronous sources: it is the deployment's identity at
// its own directory, it is operator configuration only, and there is no field
// in any policy document that names or reaches it (D21).
// ---------------------------------------------------------------------------

type idpGroupSourceJSON struct {
	Name          string      `json:"name"`
	Issuer        string      `json:"issuer"`
	URL           string      `json:"url"`
	Credential    string      `json:"credential,omitempty"`
	MembersField  string      `json:"members_field,omitempty"`
	MemberIDField string      `json:"member_id_field,omitempty"`
	TotalField    string      `json:"total_field,omitempty"`
	TTL           string      `json:"ttl"`
	Timeout       string      `json:"timeout"`
	Params        []paramJSON `json:"params,omitempty"`
	Returns       string      `json:"returns"`
	OnError       string      `json:"on_error,omitempty"`
}

// idpGroupSourcesFrom reads the group directory declarations.
func idpGroupSourcesFrom(spec string) ([]idpgroup.Declaration, error) {
	docs, err := configDocs[idpGroupSourceJSON]("idp group source declarations", spec)
	if err != nil {
		return nil, err
	}
	out := make([]idpgroup.Declaration, 0, len(docs))
	for _, d := range docs {
		decl := idpgroup.Declaration{
			Name:          d.Name,
			Issuer:        d.Issuer,
			URL:           d.URL,
			Credential:    d.Credential,
			MembersField:  d.MembersField,
			MemberIDField: d.MemberIDField,
			TotalField:    d.TotalField,
			Returns:       policy.Type(d.Returns),
			OnError:       policy.OnError(d.OnError),
		}
		for _, p := range d.Params {
			decl.Params = append(decl.Params, policy.Param{Name: p.Name, Type: policy.Type(p.Type)})
		}
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

// envFloat reads a rate. It has no fallback parameter because every caller
// wants the same one: an unset rate is zero, which the stream package reads as
// "no limit" — the only state an operator who configured nothing can be in.
func envFloat(key string, fail func(string, ...any)) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		fail("%s: %q is not a number", key, raw)
		return 0
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
