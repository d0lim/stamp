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

	// DefaultCheckpointInterval is how often the audit chain's heads are signed
	// into a checkpoint.
	//
	// It is a tuning knob with a safe direction rather than a trust decision:
	// the interval is the widest window in which a rewrite of the log could
	// still be covered by no external signature, so a shorter one is stricter
	// and a longer one is cheaper. Five minutes is short enough that the
	// unanchored window is smaller than most incident timelines and long enough
	// that the head scan is nowhere near the write path's cost.
	DefaultCheckpointInterval = 5 * time.Minute

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
	// AuditAlertThreshold is how many events the buffer may lose before it
	// raises the operator alert. Zero selects [api.DefaultAuditAlertThreshold],
	// which is one.
	//
	// R32 makes the sensitivity the operator's, and one is only the right
	// default for a deployment that has not yet measured its own saturation. A
	// deployment that has — U17 measured 34k check/s filling the default buffer
	// and losing most of it — is one where an alert on the first lost event
	// fires continuously and stops being read, which is the failure mode of an
	// alarm nobody can retune.
	AuditAlertThreshold int64

	// Checkpoint is the audit chain's tamper-evidence half: the signing key,
	// where signed checkpoints are published and how often one is taken. R32
	// asks for the sink and the key to be on the deployment surface; R42
	// decides how the key is allowed to get here.
	Checkpoint CheckpointConfig

	// PolicyRefreshInterval and PolicyStalenessDeadline are R24's two knobs.
	// Zero selects the engine's defaults.
	PolicyRefreshInterval   time.Duration
	PolicyStalenessDeadline time.Duration

	// DecisionTTL and MaxOutstanding bound decisions. Zero selects the
	// decision package's defaults.
	DecisionTTL    time.Duration
	MaxOutstanding int

	// DecideRate and DecideSubjectRate are R43's rate limits on decide creation,
	// per caller and per subject. A zero field selects the api package's default
	// for that field; a negative rate removes the limit.
	//
	// They are the shape [stream.RateLimit] already gave the four
	// `STAMP_INGEST_RATE_*` variables, because this deployment has one way of
	// writing down a token bucket and a second would be a second thing to learn.
	//
	// The limit they configure is **per instance**: the buckets live in this
	// process, so a fleet of N replicas admits N times what is written here. That
	// is the price of not putting a query on the decide path, and it is bounded
	// by the fact that MaxOutstanding — the absolute cap on what a subject can
	// accumulate — is counted in the database and does bind across the fleet.
	// An operator sizing a fleet divides these by the replica count.
	DecideRate        stream.RateLimit
	DecideSubjectRate stream.RateLimit

	// ChallengeIssueRate is R43's bound on challenge issuance,
	// ChallengeIssueSubjectCeiling the ceiling above it, and ApprovalSubmitRate
	// the per-approver bound on approval submission. A zero field selects the
	// owning package's default for that field; a negative rate removes the
	// limit.
	//
	// **ChallengeIssueRate is charged on (caller, subject) and not on the
	// subject alone.** It was the subject alone until #40's follow-up, and that
	// made it a weapon rather than a bound: a subject identifier is a `sub`
	// claim or an account number, not a secret, so any workload credential that
	// could name a person could hold that person's bucket empty at three
	// requests a minute and have every authorization they needed come back
	// denied — and, until the same change, recorded as denied on their history.
	// Keying the caller in means a caller can only spend its own share.
	// ChallengeIssueSubjectCeiling is what still bounds the total one person can
	// be asked for across every caller; without it, keying the caller in would
	// remove the bound rather than distribute it.
	//
	// The ceiling must not be tighter than the per-caller rate. A ceiling below
	// it binds first, every caller shares it, and the deployment is back to the
	// one subject-keyed bucket anybody could empty. mfa.NewDelegated refuses
	// that configuration rather than booting into it.
	//
	// Neither is the same knob as the re-issue interval and neither replaces it.
	// That interval is keyed on the subject *and the decision content*, so it
	// suppresses a re-evaluation of one decision and cannot see a caller
	// creating a hundred different ones — which is N different keys, N IdP
	// requests, and N prompts on one phone. These are the bounds over that.
	//
	// **ChallengeIssueRate configures the step-up handler and the webhook
	// handler; the ceiling configures only the step-up handler.** The webhook
	// handler is deliberately still keyed on the subject alone, because what a
	// refusal there protects is a machine this deployment does not operate and
	// its defence is that the *total* is bounded rather than the per-caller
	// share — challenge.External.allowNotify says so where it is keyed. Each
	// handler still defaults its rate separately when it is unset, because a
	// prompt on a person's phone and a POST to a machine are not worth the same
	// by default.
	//
	// All three limits are **per instance**, like DecideRate above and for the
	// same reason: the buckets live in the process, so a fleet of N replicas
	// admits N times what is written here, and an operator sizing a fleet
	// divides. What bounds the fleet as a whole is elsewhere — MaxOutstanding
	// for decisions, and for these, the challenge deadline and the quorum
	// threshold, which are counted in the database.
	ChallengeIssueRate           stream.RateLimit
	ChallengeIssueSubjectCeiling stream.RateLimit
	ApprovalSubmitRate           stream.RateLimit

	// CancellationRate is R43's bound on delay cancellation, per authority. A
	// zero field selects [api.DefaultCancellationRate] for that field; a
	// negative rate removes the limit.
	//
	// It is the fifth write surface and the last one to get a budget. What it
	// bounds is not the cost of a cancellation that works — that one denies the
	// decision and there is nothing left to cancel — but the cost of one that is
	// refused: a caller without standing on an existing decision makes the
	// lifecycle write an access-refused entry through a synchronous chain
	// append, on the serialized audit write path, and that is reachable for the
	// whole life of the decision rather than only while it is pending. The
	// default is tighter than ApprovalSubmitRate because the action is rarer;
	// api.DefaultCancellationRate says how much rarer and why.
	//
	// **Per instance**, like every budget above.
	CancellationRate stream.RateLimit

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

// CheckpointConfig is the audit checkpoint subsystem's deployment
// configuration.
//
// R42 decides the shape of the first two fields, and it is the reason this
// struct has no field a key's bytes could be written into. A private key handed
// over in an environment variable is a key in the process listing, in `docker
// inspect`, in the chart values that produced the manifest and in whatever
// shipped that manifest around; there is no way to inject one that way and
// still say the deployment holds it as a secret. A file is what a Kubernetes
// Secret, a Docker secret and a laptop all mount, so a path is the only
// injection path there is — and a path is not the key, so a configuration dump
// or a startup log carries the name of the key and never the key.
//
// The identifier is mandatory for the same requirement's second half. Every
// checkpoint records the key it was signed under, so a rotation is: point
// KeyFile at the new key, give it a new KeyID, and leave the retired key's
// *public* half in VerifyKeys. Checkpoints signed before the rotation stay
// verifiable and nothing has to be re-signed, which is what makes the rotation
// a restart rather than an outage. Reusing one identifier for two different
// keys is the one move that breaks that, and it is what an operator does when
// the identifier is optional and gets defaulted.
type CheckpointConfig struct {
	// KeyFile is the path the Ed25519 signing key is mounted at, in PEM
	// PKCS#8 form — what `openssl genpkey -algorithm ed25519` writes.
	KeyFile string
	// KeyID names the signing key. It is stamped on every checkpoint this
	// process produces and is required whenever a key is configured.
	KeyID string
	// VerifyKeys are additional public keys verification accepts, by
	// identifier: the retired halves of previous rotations, and — on a host
	// that holds no signing key at all, which is what an auditor running
	// `stamp audit verify` has — every key the series was ever signed under.
	VerifyKeys map[string]string
	// SinkFile is the append-only file signed checkpoints are written to. It
	// is the default sink because the guarantee has to hold in the
	// single-container deployment with no second system configured, and it is
	// the only sink shape verification can read back.
	SinkFile string
	// SinkWebhook is an optional additional destination, delivered through the
	// egress gate. It is an addition and not a replacement: a webhook cannot be
	// read back, so a deployment whose only sink is one cannot verify itself.
	SinkWebhook string
	// Interval is how often a checkpoint is taken. Zero selects
	// DefaultCheckpointInterval.
	Interval time.Duration
}

// Configured reports whether the deployment asked for audit checkpoints at all.
func (c CheckpointConfig) Configured() bool {
	return strings.TrimSpace(c.KeyFile) != "" || strings.TrimSpace(c.SinkFile) != "" ||
		strings.TrimSpace(c.SinkWebhook) != ""
}

// Sinks reports whether a destination was named.
func (c CheckpointConfig) Sinks() bool {
	return strings.TrimSpace(c.SinkFile) != "" || strings.TrimSpace(c.SinkWebhook) != ""
}

// validate refuses a half-configured checkpoint subsystem.
//
// Every case below is one where the deployment would start, report itself
// healthy, and produce no tamper evidence — with an operator who wrote a key
// path in the manifest and has every reason to believe otherwise. A control
// that is absent is recoverable; a control that is believed to be present and
// is not is the failure this refuses to boot into.
func (c CheckpointConfig) validate() []error {
	if !c.Configured() {
		return nil
	}
	var errs []error
	if strings.TrimSpace(c.KeyFile) == "" {
		errs = append(errs, fmt.Errorf(
			"%s is set but %s is not: a checkpoint sink with no signing key receives nothing, and an "+
				"unsigned head is one anybody with database access can write",
			firstSet(c.SinkFile, EnvCheckpointSinkFile, EnvCheckpointSinkWebhook), EnvCheckpointKeyFile))
	}
	if strings.TrimSpace(c.KeyFile) != "" && strings.TrimSpace(c.KeyID) == "" {
		errs = append(errs, fmt.Errorf(
			"%s is set but %s is not: a checkpoint records the key it was signed under, and a key with no "+
				"identifier cannot be rotated without invalidating everything the previous one signed",
			EnvCheckpointKeyFile, EnvCheckpointKeyID))
	}
	if !c.Sinks() {
		errs = append(errs, fmt.Errorf(
			"%s is set but no sink is: a checkpoint that never leaves the database is signed by a key the "+
				"database does not hold and stored where the database can overwrite it. set %s",
			EnvCheckpointKeyFile, EnvCheckpointSinkFile))
	}
	return errs
}

// firstSet reports which of two sink variables the operator actually set, so
// the refusal names the one in their manifest.
func firstSet(sinkFile, fileEnv, webhookEnv string) string {
	if strings.TrimSpace(sinkFile) != "" {
		return fileEnv
	}
	return webhookEnv
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

	// AuthorizationEndpoint, ClientID, RedirectURI and TokenEndpoint are the
	// step-up half (D26's default demo path). All four are required for the
	// handler to be built: without the token endpoint the redirect comes back
	// with a code nothing can redeem, which is the half of #41 that made the
	// default path unwalkable.
	AuthorizationEndpoint string
	ClientID              string
	RedirectURI           string
	TokenEndpoint         string
	// ClientSecretFile is where the step-up client's secret is read from, for a
	// deployment that registers a confidential client. Empty is the normal case:
	// a step-up client is public and PKCE is what proves the redeemer is the
	// requester. It is a path rather than a value because R42 admits a secret
	// only from a file or a secret reference.
	ClientSecretFile string
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

	EnvAuditFailClosed     = "STAMP_AUDIT_FAIL_CLOSED"
	EnvAuditCapacity       = "STAMP_AUDIT_CAPACITY"
	EnvAuditBatchSize      = "STAMP_AUDIT_BATCH_SIZE"
	EnvAuditFlushInterval  = "STAMP_AUDIT_FLUSH_INTERVAL"
	EnvAuditAlertThreshold = "STAMP_AUDIT_ALERT_THRESHOLD"

	// The audit checkpoint surface. The signing key is named by a path and
	// never by its value: there is deliberately no variable that carries key
	// material, because a key in the environment is a key in the process
	// listing and in whatever produced the manifest (R42).
	EnvCheckpointKeyFile     = "STAMP_AUDIT_CHECKPOINT_KEY_FILE"
	EnvCheckpointKeyID       = "STAMP_AUDIT_CHECKPOINT_KEY_ID"
	EnvCheckpointVerifyKeys  = "STAMP_AUDIT_CHECKPOINT_VERIFY_KEYS"
	EnvCheckpointSinkFile    = "STAMP_AUDIT_CHECKPOINT_SINK_FILE"
	EnvCheckpointSinkWebhook = "STAMP_AUDIT_CHECKPOINT_SINK_WEBHOOK"
	EnvCheckpointInterval    = "STAMP_AUDIT_CHECKPOINT_INTERVAL"

	EnvPolicyRefreshInterval   = "STAMP_POLICY_REFRESH_INTERVAL"
	EnvPolicyStalenessDeadline = "STAMP_POLICY_STALENESS_DEADLINE"

	EnvDecisionTTL    = "STAMP_DECISION_TTL"
	EnvMaxOutstanding = "STAMP_MAX_OUTSTANDING_DECISIONS"

	EnvDecideRate             = "STAMP_DECIDE_RATE_PER_SECOND"
	EnvDecideBurst            = "STAMP_DECIDE_RATE_BURST"
	EnvDecideSubjectRate      = "STAMP_DECIDE_SUBJECT_RATE_PER_SECOND"
	EnvDecideSubjectRateBurst = "STAMP_DECIDE_SUBJECT_RATE_BURST"

	EnvChallengeIssueRate         = "STAMP_CHALLENGE_ISSUE_RATE_PER_SECOND"
	EnvChallengeIssueBurst        = "STAMP_CHALLENGE_ISSUE_RATE_BURST"
	EnvChallengeIssueCeilingRate  = "STAMP_CHALLENGE_ISSUE_SUBJECT_CEILING_PER_SECOND"
	EnvChallengeIssueCeilingBurst = "STAMP_CHALLENGE_ISSUE_SUBJECT_CEILING_BURST"
	EnvApprovalRate               = "STAMP_APPROVAL_RATE_PER_SECOND"
	EnvApprovalBurst              = "STAMP_APPROVAL_RATE_BURST"
	EnvCancellationRate           = "STAMP_CANCELLATION_RATE_PER_SECOND"
	EnvCancellationBurst          = "STAMP_CANCELLATION_RATE_BURST"

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
	EnvMFATokenEndpoint = "STAMP_MFA_TOKEN_ENDPOINT"     //nolint:gosec // a variable name, not a credential
	EnvMFAClientSecret  = "STAMP_MFA_CLIENT_SECRET_FILE" //nolint:gosec // a path to a credential, not one
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
		DecideRate: stream.RateLimit{
			PerSecond: envFloat(EnvDecideRate, fail),
			Burst:     envFloat(EnvDecideBurst, fail),
		},
		DecideSubjectRate: stream.RateLimit{
			PerSecond: envFloat(EnvDecideSubjectRate, fail),
			Burst:     envFloat(EnvDecideSubjectRateBurst, fail),
		},
		ChallengeIssueRate: stream.RateLimit{
			PerSecond: envFloat(EnvChallengeIssueRate, fail),
			Burst:     envFloat(EnvChallengeIssueBurst, fail),
		},
		ChallengeIssueSubjectCeiling: stream.RateLimit{
			PerSecond: envFloat(EnvChallengeIssueCeilingRate, fail),
			Burst:     envFloat(EnvChallengeIssueCeilingBurst, fail),
		},
		ApprovalSubmitRate: stream.RateLimit{
			PerSecond: envFloat(EnvApprovalRate, fail),
			Burst:     envFloat(EnvApprovalBurst, fail),
		},
		CancellationRate: stream.RateLimit{
			PerSecond: envFloat(EnvCancellationRate, fail),
			Burst:     envFloat(EnvCancellationBurst, fail),
		},
		RevisionTTL:           envDuration(EnvRevisionTTL, 0, fail),
		ReconcileInterval:     envDuration(EnvReconcileInterval, DefaultReconcileInterval, fail),
		BootstrapWarnInterval: envDuration(EnvBootstrapWarnInterval, 0, fail),
		AuditorClaim:          strings.TrimSpace(os.Getenv(EnvAuditorClaim)),
		AuditorValues:         splitList(os.Getenv(EnvAuditorValues)),
		CheckContextEntity:    strings.TrimSpace(os.Getenv(EnvCheckContextEntity)),
		CapabilityClaim:       strings.TrimSpace(os.Getenv(EnvCapabilityClaim)),
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

	// The alert threshold is read on its own rather than through envInt because
	// the two values envInt would accept and this setting cannot express have to
	// be refused rather than resolved. Zero is already how an absent variable
	// spells "take the default", so an operator who wrote it meant something
	// else; a negative count would raise the alert before a single event had
	// been lost. Either one leaves an operator believing they moved a
	// sensitivity they did not, which is the direction R32 exists to close.
	if raw := strings.TrimSpace(os.Getenv(EnvAuditAlertThreshold)); raw != "" {
		switch n, err := strconv.Atoi(raw); {
		case err != nil:
			fail("%s: %q is not an integer", EnvAuditAlertThreshold, raw)
		case n <= 0:
			fail("%s: %q is not a positive number of lost events. leave it unset for the default of %d",
				EnvAuditAlertThreshold, raw, api.DefaultAuditAlertThreshold)
		default:
			cfg.AuditAlertThreshold = int64(n)
		}
	}

	cfg.Checkpoint = checkpointFromEnv(fail)

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

	// A rate that cannot mean anything is a startup failure rather than a value
	// quietly resolved into one of the two things it might have meant. The two
	// shapes that cannot mean anything are a negative bucket size, and a bucket
	// size configured alongside a rate that turns the limit off — the second is
	// an operator who wrote down a limit and got none, which is the direction
	// worth refusing to boot in.
	//
	// Every R43 budget is checked by the same function, because an operator who
	// mistyped the approval burst is in exactly the position the decide burst's
	// check exists for, and a limit validated on four of R43's five write
	// surfaces is a limit somebody can be silently without on the fifth.
	checkRate(EnvDecideRate, EnvDecideBurst, cfg.DecideRate, fail)
	checkRate(EnvDecideSubjectRate, EnvDecideSubjectRateBurst, cfg.DecideSubjectRate, fail)
	checkRate(EnvChallengeIssueRate, EnvChallengeIssueBurst, cfg.ChallengeIssueRate, fail)
	checkRate(EnvChallengeIssueCeilingRate, EnvChallengeIssueCeilingBurst, cfg.ChallengeIssueSubjectCeiling, fail)
	checkRate(EnvApprovalRate, EnvApprovalBurst, cfg.ApprovalSubmitRate, fail)
	checkRate(EnvCancellationRate, EnvCancellationBurst, cfg.CancellationRate, fail)

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
		TokenEndpoint:          strings.TrimSpace(os.Getenv(EnvMFATokenEndpoint)),
		ClientSecretFile:       strings.TrimSpace(os.Getenv(EnvMFAClientSecret)),
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
	if c.Checkpoint.Interval <= 0 {
		c.Checkpoint.Interval = DefaultCheckpointInterval
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
//
// It takes the active roles because its last check is the only one that is not
// a property of the configuration alone: which routes this process mounts
// decides which settings can be stranded in it. See surfaceRequirements.
func (c Config) validate(roles Set) error {
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
	// Negative is checked here as well as at the environment reader, for the
	// same reason the authoring mode is: a Config built in code reaches Assemble
	// without passing through ConfigFromEnv, and a threshold below zero would
	// put the buffer into the alert on its first drop while reading as a
	// deliberately raised one.
	if c.AuditAlertThreshold < 0 {
		errs = append(errs, fmt.Errorf("%s is %d: an alert threshold cannot be a negative number of lost events",
			EnvAuditAlertThreshold, c.AuditAlertThreshold))
	}
	if !c.AuthoringMode.OrDefault().Valid() {
		errs = append(errs, fmt.Errorf("%s is %q, want one of %v",
			EnvAuthoringMode, c.AuthoringMode, revision.AuthoringModes()))
	}
	errs = append(errs, c.Kafka.validate()...)
	errs = append(errs, c.Checkpoint.validate()...)
	errs = append(errs, c.MFA.validate(c.OIDC)...)
	errs = append(errs, c.surfaceRequirements(roles)...)
	return errors.Join(errs...)
}

// surfaceRequirements refuses a configuration whose features complete on a
// surface this process does not listen on.
//
// It is a different axis from everything above it, and it lives here rather
// than in the per-setting validators for exactly that reason. [MFAConfig] and
// [KafkaConfig] and [CheckpointConfig] each check that their own settings are
// internally coherent — the four step-up variables together, a broker with a
// group and topics. This one asks a question none of them can answer alone:
// the route that setting completes on is mounted on a surface, and a surface is
// a listener some *other* setting binds. Scattering it into the four validators
// would put four copies of the Addresses lookup in four places and leave the
// fifth feature that needs a surface with no copy at all.
//
// The callback surface is unbound by default and deliberately so (R39): it is
// the one surface a deployment may have to publish past its own perimeter, so
// it is opted into rather than out of. Three things complete on it and on no
// other surface, and every one of them is configured somewhere other than
// STAMP_*_ADDR — which is how a deployment ends up asking for all three and
// binding none:
//
//	delegated step-up MFA       the IdP returns the subject to
//	                            GET /decisions/{id}/challenges/{ordinal}/mfa
//	                            (internal/api/mfa.go, mounted under the decide
//	                            role in wiring.go)
//	external challenge targets  the target acknowledges the notification and
//	                            answers later on POST /external/{id}/{ordinal}.
//	                            The round trip is two legs on purpose
//	                            (internal/challenge/external.go), so the verdict
//	                            cannot come back on the outbound call instead
//	HTTP velocity ingest        a producer's batches arrive on
//	                            POST /ingest/v1/events under the consumer role
//
// Nothing else catches it. [api.New] mounts a route on a surface the process
// does not serve rather than refusing to start, because a role a process does
// not run is not an error — and the consequence is that "mounted" and
// "reachable" come apart with nothing between them. The process is healthy,
// /readyz is green, and the subject's browser arrives at a listener this
// deployment never bound.
//
// This is the same refusal deploy/helm/stamp/templates/_helpers.tpl makes at
// render time (stamp.callbackSurfaceValidated), on purpose and condition for
// condition. Two guards that disagree are worse than either alone: a
// configuration the chart rejects and the binary accepts teaches an operator
// that the chart is being fussy, and one the chart accepts and the binary
// refuses is a rollout that fails after the manifests were reviewed. The chart
// is the guard for a Helm install and this one is the guard for everything else
// — the demo runs on docker-compose, and `stamp --roles=all` on a laptop runs
// on neither. The one place they differ is degenerate and known: the chart
// triggers on a documents.* Secret being *named*, this triggers on the document
// having parsed to at least one entry, so an empty list is refused by the chart
// and admitted here. A document that declares no target strands nothing, so
// this side is the one that is right about it, and the chart is stricter in the
// direction that costs an operator a rendering error rather than a broken
// deployment.
//
// CIBA is not one of the three, and that is a reading of the code rather than
// an omission: it is a backchannel push, its Initiate returns no authorization
// URL, and internal/challenge/mfa/ciba.go ignores the redirect URI the
// delegated handler hands it. It still reaches this guard, through the step-up
// settings — [MFAConfig.validate] requires the four step-up variables whenever
// [MFAConfig.Configured] is true, and Configured is true of a CIBA-only
// deployment — so a deployment that configures CIBA and nothing else cannot
// reach a passing validate without an authorization endpoint, and with one it
// is refused here. That turns out to be the right answer for a second reason:
// nothing in the binary polls an auth_req_id, so a CIBA verdict is handed back
// on the POST of the same route, on the same surface.
//
// The conditions are per role and not per setting alone, so that a process
// running neither decide nor consumer — a `--roles=check` PEP tier, an
// api-only authoring tier — is not refused for settings that reach no listener
// in it. Those settings are not useless there: an api tier holds the external
// targets because applying a revision re-issues challenges (see
// issuesChallenges), and the target answers on the *decide* tier's callback
// listener, which is a different process with its own address. Refusing the api
// tier for a listener it was never going to bind would be refusing a legitimate
// deployment shape.
//
// Rejected: booting and reporting this through /readyz instead. Unready is for
// a dependency that is arriving — a schema mid-migration, a broker coming back
// — and a listener nobody configured never arrives. Standing unready with
// nothing to wait for is a way of holding an operator's configuration error
// open indefinitely rather than answering it.
func (c Config) surfaceRequirements(roles Set) []error {
	if strings.TrimSpace(c.Addresses[api.SurfaceCallback]) != "" {
		return nil
	}
	var stranded []string
	if roles.Has(RoleDecide) {
		if strings.TrimSpace(c.MFA.AuthorizationEndpoint) != "" {
			stranded = append(stranded, fmt.Sprintf(
				"delegated step-up MFA (%s) — the IdP returns the subject to "+
					"GET /decisions/{id}/challenges/{ordinal}/mfa, so the browser lands on a listener "+
					"nothing binds and the step-up can never be completed, and step-up is the path a "+
					"decision takes by default (D26)", EnvMFAAuthzEndpoint))
		}
		if len(c.ExternalTargets) > 0 {
			stranded = append(stranded, fmt.Sprintf(
				"external challenge targets (%s) — a target acknowledges the notification and answers "+
					"later on POST /external/{id}/{ordinal}, so no verdict can arrive and every external "+
					"challenge times out into a deny", EnvExternalTargets))
		}
	}
	if roles.Has(RoleConsumer) && len(c.IngestCredentials) > 0 {
		stranded = append(stranded, fmt.Sprintf(
			"HTTP velocity ingest (%s) — a producer's batches arrive on POST /ingest/v1/events, so those "+
				"grants authenticate producers against a route this process does not serve and the "+
				"velocity facts answer from buckets no event ever reached", EnvIngestCredentials))
	}
	if len(stranded) == 0 {
		return nil
	}
	return []error{fmt.Errorf(
		"%s binds no listener, and this process (--roles=%s) configures what completes on the callback "+
			"surface and on no other: %s. nothing downstream catches this — a route is mounted on a "+
			"surface the process does not serve rather than refusing to start, so this process would "+
			"otherwise come up and report itself healthy. set %s and publish that address as %s, or "+
			"clear the settings named above and run without what they ask for",
		EnvCallbackAddr, roles.String(), strings.Join(stranded, "; "), EnvCallbackAddr, EnvCallbackBaseURL)}
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
		// A step-up that cannot redeem its code is a challenge nobody can
		// complete. It is refused at boot rather than at the moment somebody has
		// finished authenticating and is waiting for a page.
		{EnvMFATokenEndpoint, m.TokenEndpoint},
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

// ---------------------------------------------------------------------------
// audit checkpoints
//
// The one part of the deployment surface whose secret is not read here at all.
// Every other credential on this surface — the CIBA client secret, an external
// target's shared secret, a directory credential — is a value a manifest can
// carry. The checkpoint signing key is not, and the reason is what the key is
// for: it signs the statement the database is not allowed to be able to make.
// A key that travelled through the same channel as the deployment manifest is a
// key whoever can write the manifest can sign with, and the whole value of the
// checkpoint is that it was signed by something the database — and the person
// who can rewrite it — does not hold.
// ---------------------------------------------------------------------------

// CheckpointConfigFromEnv reads the audit checkpoint configuration on its own.
//
// `stamp audit verify` needs exactly this surface and none of the rest: it
// serves nothing, so making it supply an issuer, an audience and a listen
// address before it could read a checkpoint file would be configuration for its
// own sake — and configuration an auditor running the command from a laptop
// does not have. It is the same reader [ConfigFromEnv] uses, so the command and
// the process that wrote the checkpoints cannot drift apart on what a variable
// means.
func CheckpointConfigFromEnv() (CheckpointConfig, error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	cfg := checkpointFromEnv(fail)
	if len(errs) > 0 {
		return CheckpointConfig{}, errors.Join(errs...)
	}
	return cfg, nil
}

func checkpointFromEnv(fail func(string, ...any)) CheckpointConfig {
	keys, err := checkpointVerifyKeysFrom(os.Getenv(EnvCheckpointVerifyKeys))
	if err != nil {
		fail("%s: %w", EnvCheckpointVerifyKeys, err)
	}
	return CheckpointConfig{
		KeyFile:     strings.TrimSpace(os.Getenv(EnvCheckpointKeyFile)),
		KeyID:       strings.TrimSpace(os.Getenv(EnvCheckpointKeyID)),
		VerifyKeys:  keys,
		SinkFile:    strings.TrimSpace(os.Getenv(EnvCheckpointSinkFile)),
		SinkWebhook: strings.TrimSpace(os.Getenv(EnvCheckpointSinkWebhook)),
		Interval:    envDuration(EnvCheckpointInterval, DefaultCheckpointInterval, fail),
	}
}

// checkpointVerifyKeysFrom reads the retired public keys, written as
// "key-id=/path/to/key.pub,other-id=/path/to/other.pub".
//
// A public key is not a secret, so unlike the signing key it could have been
// carried inline. It is a path anyway: the two halves of one rotation should be
// configured the same way, and an operator who has to remember that one of them
// is a path and the other is a literal is an operator who will paste the wrong
// one into the wrong variable exactly once.
func checkpointVerifyKeysFrom(spec string) (map[string]string, error) {
	entries := splitList(spec)
	if len(entries) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		id, path, ok := strings.Cut(entry, "=")
		id, path = strings.TrimSpace(id), strings.TrimSpace(path)
		if !ok || id == "" || path == "" {
			return nil, fmt.Errorf("entry %q is not of the form key-id=/path/to/public-key.pem", entry)
		}
		if _, dup := out[id]; dup {
			// Two answers for one identifier is a rotation nobody can read: a
			// checkpoint naming that key has two public keys and no rule for
			// which one decides.
			return nil, fmt.Errorf("key id %q is given twice", id)
		}
		out[id] = path
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

// checkRate refuses the two token-bucket spellings that have no meaning.
func checkRate(rateKey, burstKey string, r stream.RateLimit, fail func(string, ...any)) {
	if r.Burst < 0 {
		fail("%s: %g is negative, and a bucket cannot hold less than nothing", burstKey, r.Burst)
	}
	if r.Burst > 0 && r.PerSecond < 0 {
		fail("%s: %g turns the limit off, so the %s of %g would never be charged",
			rateKey, r.PerSecond, burstKey, r.Burst)
	}
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
