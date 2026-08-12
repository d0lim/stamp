package runtime

// wiring.go is the composition root: the one place that knows every subsystem
// and the order they have to be built in.
//
// Nothing below decides anything. Each unit's package holds its own rules, and
// what happens here is only assembly — which is why the file reads as a list.
// Two properties of the assembly are not incidental, though.
//
// Almost the whole dependency graph is built whatever roles are selected, and
// what --roles decides is which routes are mounted and which loops run — a
// decision made once, by the registry. A stamp process talks to one database
// and holds one audit writer no matter which subsystems it runs, so building
// half a graph would buy nothing and would mean every constructor had to
// tolerate a nil neighbour.
//
// The exception is credentials, and it is R42's second clause rather than an
// optimisation: a process does not hold a secret it has no use for. Which
// secrets those are is stated in credentials.go, and the two things that follow
// from it are here — the configuration is narrowed before anything is
// constructed, and a role that never calls a group directory gets
// [idpgroup.Gate] in place of [idpgroup.Sources]. The gate is not a weaker
// check: it refuses every schema the caller refuses, from the same code.
//
// The audit writer claim is exclusive and its failure is fatal. Two processes
// on one writer identifier collide on the audit chain's primary key, which is a
// correctness failure rather than contention, so a collision fails the boot
// instead of being retried.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/d0lim/stamp/console"
	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/challenge/mfa"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/fact/idpgroup"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
	"github.com/d0lim/stamp/internal/stream"
)

// App is one assembled stamp process.
type App struct {
	cfg    Config
	roles  Set
	logger *slog.Logger

	store      *store.Store
	writer     *store.AuditWriter
	checkpoint *checkpointPlane
	facts      *fact.Registry
	// groups is the calling group plane, and is nil on a process whose roles
	// resolve no group: that one holds an [idpgroup.Gate] instead, which
	// answers the schema gate and nothing else. See credentials.go.
	groups     *idpgroup.Sources
	events     *ingestPlane
	buffer     *api.AuditBuffer
	challenges *challenge.Registry

	check      *engine.CheckService
	decide     *decidePlane
	governance *revision.Service

	registry  *Registry
	server    *api.Server
	listeners *api.Listeners

	bootstrapToken string

	closeOnce sync.Once
}

// Assemble builds every subsystem and mounts the routes the active roles call
// for. It does not bind a listener; see [App.Listen].
func Assemble(ctx context.Context, cfg Config, roles Set, logger *slog.Logger) (*App, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}

	// After validate and before anything is built: the whole deployment's
	// configuration is checked wherever it is read, and only this process's
	// share of its secrets survives into the graph below (R42).
	app := &App{cfg: withoutUnusedCredentials(cfg, roles), roles: roles, logger: logger}
	if err := app.build(ctx); err != nil {
		app.Close()
		return nil, err
	}
	return app, nil
}

func (a *App) build(ctx context.Context) error {
	cfg := a.cfg

	// --- persistence -------------------------------------------------------
	s, err := store.Open(ctx, store.Config{DSN: cfg.DSN, MaxConns: cfg.MaxConns, Roles: cfg.DBRoles})
	if err != nil {
		return err
	}
	a.store = s
	if cfg.Migrate {
		if err := s.Migrate(ctx); err != nil {
			return err
		}
	}
	if cfg.ApplyGrants {
		if err := s.ApplyGrants(ctx); err != nil {
			return fmt.Errorf("%w\n\nset %s=false when the service login may not create roles", err, EnvApplyGrants)
		}
	}

	// The claim is exclusive for the life of the process and holds one pooled
	// connection. A collision is reported as-is: retrying it would either spin
	// forever or start a process whose audit appends fail one at a time.
	writer, err := s.ClaimWriter(ctx, cfg.WriterID, cfg.InstanceID)
	if err != nil {
		return fmt.Errorf("%w\n\neach stamp process needs its own %s", err, EnvWriterID)
	}
	a.writer = writer

	// --- audit and identity ------------------------------------------------
	buffer, err := api.NewAuditBuffer(api.AuditConfig{
		Writer:         writer,
		Capacity:       cfg.AuditCapacity,
		BatchSize:      cfg.AuditBatchSize,
		FlushInterval:  cfg.AuditFlushInterval,
		AlertThreshold: cfg.AuditAlertThreshold,
		FailClosed:     cfg.AuditFailClosed,
		OnAlert: func(stats api.AuditStats) {
			a.logger.Error("audit buffer is losing events",
				slog.Int64("dropped", stats.Dropped),
				slog.Bool("fail_closed", stats.FailClosed),
				slog.String("last_error", stats.LastError))
		},
	})
	if err != nil {
		return err
	}
	a.buffer = buffer

	issuers := make([]identity.IssuerConfig, len(cfg.OIDC.Issuers))
	for i, ic := range cfg.OIDC.Issuers {
		issuers[i] = identity.IssuerConfig{
			Issuer:          ic.Issuer,
			JWKSURL:         ic.JWKSURL,
			WorkloadClients: ic.WorkloadClients,
		}
	}
	verifier, err := identity.New(ctx, identity.Config{
		Issuers:                issuers,
		Audience:               cfg.OIDC.Audience,
		Algorithms:             cfg.OIDC.Algorithms,
		AllowedACRValues:       cfg.OIDC.AllowedACRValues,
		AllowInsecureTransport: cfg.OIDC.AllowInsecureTransport,
	})
	if err != nil {
		return err
	}
	// The buffer is the audit sink as well as the check surface's recorder: an
	// authentication attempt that never became a judgment is still something
	// R40 requires the chain to contain.
	middleware, err := identity.NewMiddleware(identity.MiddlewareConfig{Verifier: verifier, Audit: buffer})
	if err != nil {
		return err
	}

	// --- fact plane --------------------------------------------------------
	//
	// One egress gate serves every outbound call this process makes. It is
	// built here rather than beside each caller because a second gate is a
	// second place the loopback and private opt-ins can disagree, and a
	// destination admitted by one rule set and refused by another is a rule set
	// nobody can read.
	gate, err := fact.NewGate(cfg.Egress)
	if err != nil {
		return err
	}

	factAudit := fact.AuditorFunc(func(_ context.Context, f *fact.Failure) {
		a.logger.Warn("fact lookup failed",
			slog.String("source", f.Source),
			slog.String("reason", f.AuditReason()),
			slog.Bool("fails_closed", f.FailsClosed()))
	})
	facts, err := fact.NewRegistry(cfg.FactSources, fact.Config{
		Egress:        cfg.Egress,
		AllowFailOpen: cfg.AllowFactFailOpen,
		Audit:         factAudit,
	})
	if err != nil {
		return err
	}
	a.facts = facts
	resolver, err := api.NewFactResolver(facts)
	if err != nil {
		return err
	}

	// --- the resolver stack ------------------------------------------------
	//
	// The evaluator states one [engine.SourceResolver] and gets one batch
	// answered. Three planes serve that one statement, so they are chained
	// rather than registered side by side: each answers the names it owns and
	// delegates the rest onward in a single batch, which is what keeps the
	// engine's one-batch-before-evaluation contract — and the timeout and cache
	// reasoning built on top of it — intact all the way down.
	//
	// The order is by narrowness. Group directories own the fewest names,
	// velocity sources the next fewest, and the synchronous registry is the
	// terminal plane that either answers or refuses.
	events, err := a.ingestion(cfg, resolver)
	if err != nil {
		return err
	}
	a.events = events

	velocityGate := schemaGate(unconfiguredKind{
		kind: policy.SourceEvent,
		why:  "this deployment configures no velocity sources",
	})
	behindGroups := engine.SourceResolver(resolver)
	if events != nil {
		behindGroups = events.sources
		velocityGate = events.sources
	}

	// The group plane is the one place a role decides what gets built, and the
	// two halves answer the schema gate identically — see credentials.go. A
	// process that never resolves a group holds no directory credential, opens
	// no client to a directory and does not preflight one at boot; what it
	// keeps is the refusal.
	var groups challenge.GroupResolver
	var groupGate schemaGate
	sources := behindGroups
	if callsDirectories(a.roles) {
		full, gerr := idpgroup.NewSources(cfg.IdPGroupSources, idpgroup.SourcesConfig{
			Gate:          gate,
			Issuers:       issuers,
			AllowFailOpen: cfg.AllowFactFailOpen,
			MaxTTL:        cfg.IdPGroupMaxTTL,
			Fallback:      behindGroups,
			Audit:         factAudit,
		})
		if gerr != nil {
			return gerr
		}
		a.groups = full
		groups = full
		groupGate = full
		sources = full
	} else {
		gateOnly, gerr := idpgroup.NewGate(cfg.IdPGroupSources, idpgroup.GateConfig{
			Issuers:       issuers,
			AllowFailOpen: cfg.AllowFactFailOpen,
			MaxTTL:        cfg.IdPGroupMaxTTL,
		})
		if gerr != nil {
			return gerr
		}
		groupGate = gateOnly
	}

	// --- evaluation --------------------------------------------------------
	//
	// The gate list has one entry per source plane and never fewer, whatever
	// this process's roles: snapshot.go's rule is that a plane missing from it
	// is not a laxer check for its kind but no check at all.
	loader := &snapshotSource{store: s, gates: []schemaGate{facts, velocityGate, groupGate}}
	check, err := engine.NewCheckService(ctx, engine.CheckConfig{
		Loader:            loader,
		RefreshInterval:   cfg.PolicyRefreshInterval,
		StalenessDeadline: cfg.PolicyStalenessDeadline,
		Resolver:          sources,
	})
	if err != nil {
		return err
	}
	a.check = check

	// --- decisions ---------------------------------------------------------
	quorum, err := challenge.NewQuorum(challenge.QuorumConfig{
		Audit: writer, DB: s.Pool(), Groups: groups, ApproverIssuer: approverIssuerFor(cfg),
	})
	if err != nil {
		return err
	}
	handlers, err := a.challengeHandlers(quorum, gate, groups)
	if err != nil {
		return err
	}
	challenges, err := challenge.NewRegistry(handlers...)
	if err != nil {
		return err
	}
	a.challenges = challenges
	plane, err := newDecidePlane(ctx, decision.Config{
		Store:          s,
		Audit:          writer,
		Challenges:     challenges,
		TTL:            cfg.DecisionTTL,
		MaxOutstanding: cfg.MaxOutstanding,
	}, loader, sources, cfg.PolicyRefreshInterval)
	if err != nil {
		return err
	}
	a.decide = plane
	sweeper, err := decision.NewSweeper(decision.SweeperConfig{
		Service: plane.Service(),
		OnError: func(err error) { a.logger.Error("expiry sweep failed", slog.String("error", err.Error())) },
	})
	if err != nil {
		return err
	}

	// --- governance --------------------------------------------------------
	revalidator, err := decision.NewRevalidator(decision.RevalidatorConfig{Challenges: challenges})
	if err != nil {
		return err
	}
	governance, err := revision.New(revision.Config{
		Store:       s,
		Audit:       writer,
		Challenges:  challenges,
		Revalidator: revalidator,
		Resolver:    sources,
		Floor:       cfg.GovernanceFloor,
		TTL:         cfg.RevisionTTL,
		WarnEvery:   cfg.BootstrapWarnInterval,
		Authoring:   cfg.AuthoringMode,
		Rate:        cfg.RevisionRate,
		Limits:      cfg.ApplyLimits,
		// The export gate is fail-closed when it has no capability source, and
		// an unconfigured deployment refusing every export is the correct
		// direction but not a usable one: the endpoint would be mounted and
		// answer nobody. Reading a verified token claim is the implementation
		// every deployment already has the machinery for, and it keeps the
		// fail-closed shape where it belongs — per caller. A token without the
		// claim, or with a claim naming neither capability, still holds
		// nothing, and its export is still refused and still audited.
		Capabilities: revision.ClaimCapabilities{Claim: cfg.CapabilityClaim},
	})
	if err != nil {
		return err
	}
	a.governance = governance

	// Installing the reserved governance policy is the authoring tier's job. A
	// check-only process must not write policy, and a deployment that runs no
	// authoring tier has nobody to hand the bootstrap token to.
	if roles := a.roles; roles.Has(RoleAPI) {
		token, ierr := governance.Install(ctx)
		if ierr != nil {
			return ierr
		}
		a.bootstrapToken = token
	}

	// --- surfaces ----------------------------------------------------------
	checkAPI, err := api.NewCheckAPI(api.CheckAPIConfig{
		Service:         check,
		Audit:           buffer,
		ContextEntity:   cfg.CheckContextEntity,
		PropertyAliases: cfg.CheckPropertyAliases,
	})
	if err != nil {
		return err
	}
	dryRun, err := api.NewDryRunAPI(api.DryRunAPIConfig{Service: check})
	if err != nil {
		return err
	}
	// The decide surface takes the plane and not `plane.Service()`. The plane
	// rebuilds its service when the effective policy set moves, so a surface
	// holding the service this process booted with would keep creating decisions
	// — and issuing challenges — from a revision that is no longer in force.
	//
	// It reads its schema from the same plane for the same reason, and because a
	// decide-only process runs no check tier to borrow one from.
	decisions, err := api.NewDecisions(api.DecisionsConfig{
		Decisions: plane,
		Access:    plane,
		Schema:    plane,
		// The same two knobs the check surface reads, from the same
		// configuration: a PEP that asks the two questions with one body must
		// have the body mean one thing.
		ContextEntity:   cfg.CheckContextEntity,
		PropertyAliases: cfg.CheckPropertyAliases,
		// The same buffer the check surface writes through. A rate-limit refusal
		// never reaches the decision service — that is what makes it cheap — so
		// the surface is the only place it can be recorded, and the buffer is the
		// seam that does not put a transaction on the path taken by a caller who
		// is already sending too much.
		Audit:       buffer,
		Rate:        cfg.DecideRate,
		SubjectRate: cfg.DecideSubjectRate,
	})
	if err != nil {
		return err
	}
	// Every collecting surface submits through the same seam: an approval, an
	// mfa completion, a delay cancellation and a webhook verdict are one code
	// path with four doors, and the revision reconcile that has to follow the
	// last approval has to follow all four for the same reason.
	submitter := &reconciling{inner: plane, governance: governance, logger: a.logger}
	approvals, err := api.NewApprovals(api.ApprovalsConfig{
		Decisions: submitter,
		Reviews:   quorum,
		Rate:      cfg.ApprovalSubmitRate,
		// The same buffer the decide surface writes its rate refusals through. A
		// submission shed under the budget never reaches the lifecycle — that is
		// what makes it cheap — so this surface is the only place it can be
		// recorded.
		Audit: buffer,
	})
	if err != nil {
		return err
	}
	cancellations, err := api.NewCancellations(api.CancellationsConfig{
		Decisions: submitter,
		Rate:      cfg.CancellationRate,
		// The same buffer again, and here it is load-bearing rather than
		// consistent. The refusal this surface records is the one that used to
		// reach the lifecycle and write a chain append per attempt; recording it
		// with a second synchronous append would leave the append count where it
		// was and call the difference a rate limit.
		Audit: buffer,
	})
	if err != nil {
		return err
	}
	// The inbox's "waiting on me" filter is the quorum handler's own target
	// test (R21). It is wired to the same handler the approval endpoints use,
	// because a list produced by a second opinion about who may approve would
	// show people decisions they cannot submit against.
	inbox, err := api.NewInbox(api.InboxConfig{Quorums: quorum})
	if err != nil {
		return err
	}
	auditConsole, err := api.NewAuditConsole(api.AuditConsoleConfig{
		History: store.NewHistory(s.Pool()),
		// The plane, not the service it currently holds. Capturing the service
		// here would pin this surface to the one this process booted with, and
		// the two reads of R40's rule — this one and the PEP's — would be asking
		// two different services the same question. Nothing observable turns on
		// it today, because every method a read reaches goes to the store, the
		// audit writer and the challenge registry, which a rebuild carries over
		// unchanged; the evaluator is the only thing that moves and no read
		// touches it. It is written this way so that stays true by construction
		// rather than by inspection.
		Access:   plane,
		Auditors: api.AuditorRule{Claim: cfg.AuditorClaim, Values: cfg.AuditorValues},
		Audit:    writer,
	})
	if err != nil {
		return err
	}
	callbacks, err := api.NewCallbacks(api.CallbacksConfig{Decisions: submitter})
	if err != nil {
		return err
	}
	// The decision service is both the submitter and the redeemer: redeeming an
	// IdP redirect is routing it to the challenge that sent it, and the
	// lifecycle is what knows which challenge that is.
	mfaCallback, err := api.NewMFA(api.MFAConfig{
		Decisions: submitter,
		Tokens:    verifier,
		Redeemer:  plane,
	})
	if err != nil {
		return err
	}
	policies, err := api.NewPolicies(api.PoliciesConfig{
		Governance: governance,
		Policies: api.PolicyListerFunc(func(ctx context.Context) ([]store.PolicyRecord, error) {
			return store.EffectivePolicies(ctx, s.Pool())
		}),
		Schema: api.SchemaReaderFunc(func(ctx context.Context) (store.SchemaRecord, error) {
			return store.LatestSchema(ctx, s.Pool())
		}),
		Bootstrap: governance.Bootstrap(),
		// The governance service is the file authoring path: it already holds
		// the authoring mode, the payload limits, the serialization gate and
		// the export capability, and it satisfies the two-method seam the
		// surface asks for. Leaving this nil is what a deployment that deferred
		// R45-R49 looks like from outside — apply and export answering "this
		// deployment serves no file authoring path" — and this one has not.
		Files: governance,
	})
	if err != nil {
		return err
	}

	// --- audit checkpoints -------------------------------------------------
	//
	// Built on every process, whatever its roles, because the warning a
	// deployment with no checkpoints has to see is a fact about the deployment
	// and not about this process's role selection — and because a misconfigured
	// key file should fail the boot of whichever process reads it first, rather
	// than only the one that happens to run the loop.
	checkpoints, err := a.checkpoints(gate)
	if err != nil {
		return err
	}
	a.checkpoint = checkpoints

	// --- components --------------------------------------------------------
	registry := NewRegistry()
	if err := registry.Add(Component{
		// The buffer serves every surface: the check path's judgments and the
		// identity layer's authentication records both go through it, so it
		// runs wherever a listener does.
		Name:  "audit-buffer",
		Roles: knownRoles(),
		Run:   buffer.Run,
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		Name:   "check-api",
		Roles:  []Role{RoleCheck},
		Routes: checkAPI.Routes(),
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		Name:  "policy-refresh",
		Roles: []Role{RoleCheck},
		Run:   check.Run,
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		// The decide tier's own half of the PEP surface, and the only routes
		// this role puts there: creating a decision is what the decide tier is,
		// and a check tier that could create one would hold the state the split
		// exists to keep out of it.
		Name:   "decide-api",
		Roles:  []Role{RoleDecide},
		Routes: decisions.Routes(),
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		Name: "approval-api",
		// The inbox rides with the approval endpoints rather than with the
		// authoring tier: it reads the same challenge rows, refuses on the same
		// rule, and a deployment that serves approvals without the list they
		// come from would give an approver a submit button and no way to find
		// what needs one.
		Roles:  []Role{RoleDecide},
		Routes: append(approvals.Routes(), inbox.Routes()...),
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		// The audit console is on the decide tier because that is where the
		// decision record and the audit chain are. Auditor standing is enforced
		// in the handler from operator configuration (R22) — the mount is not
		// the control.
		Name:   "audit-console-api",
		Roles:  []Role{RoleDecide},
		Routes: auditConsole.Routes(),
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		// The cancellation is a console action behind an end-user credential:
		// stopping a wait is a person exercising an authority, and the mount
		// table admits nothing else there.
		Name:   "cancellation-api",
		Roles:  []Role{RoleDecide},
		Routes: cancellations.Routes(),
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		// Both callbacks are on the callback listener, which is the one surface
		// a deployment may have to expose past its perimeter. Neither takes a
		// header credential: an external target authenticates with a signature
		// over a server-issued nonce, and an mfa completion carries a verified
		// token in its body. They are one component because they are one
		// exposure decision.
		Name:   "callback-api",
		Roles:  []Role{RoleDecide},
		Routes: append(callbacks.Routes(), mfaCallback.Routes()...),
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		Name:  "decide-refresh",
		Roles: []Role{RoleDecide},
		Run:   plane.Run,
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		Name:  "expiry-sweeper",
		Roles: []Role{RoleDecide},
		Run:   sweeper.Run,
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		Name:   "policy-api",
		Roles:  []Role{RoleAPI},
		Routes: append(policies.Routes(), dryRun.Routes()...),
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		Name:  "governance-bootstrap",
		Roles: []Role{RoleAPI},
		Run:   governance.Bootstrap().Run,
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		Name:  "revision-reconciler",
		Roles: []Role{RoleAPI},
		Run:   a.reconcileLoop,
	}); err != nil {
		return err
	}
	if checkpoints != nil {
		if err := registry.Add(Component{
			// The api role, and only it.
			//
			// A checkpoint is not a per-request or per-tier operation: one row
			// binds *every* writer's head at a moment, so it describes the whole
			// installation and one producer says everything there is to say.
			// Running it on check or decide would attach a scan of every segment
			// head and a global advisory lock to the two tiers that scale
			// horizontally, so each added replica would buy another serialized
			// writer against a series that needed one.
			//
			// The api role is where the installation-wide duties already are —
			// the reserved governance policy is installed there, and the revision
			// reconciler runs there — and it is the tier an operator runs one or
			// a few of. Several replicas stay correct rather than merely
			// tolerated: creation is serialized by an advisory lock, and the
			// repair pass at the head of each tick pulls whatever another replica
			// recorded into this host's copy of the sink, so every copy converges
			// on the whole series instead of each holding its own fraction.
			Name:  "audit-checkpointer",
			Roles: []Role{RoleAPI},
			Run:   a.runCheckpoints,
		}); err != nil {
			return err
		}
		if !a.roles.Has(RoleAPI) {
			// Not a warning: on a role-split deployment this is every check and
			// decide process, and the tier that does record them is configured
			// and running. It is said once so that an operator reading this
			// process's log does not conclude the deployment takes none.
			a.logger.Info("audit checkpoints are configured but are recorded by the api role, which this "+
				"process does not run",
				slog.String("roles", a.roles.String()))
		}
	}
	consoleShell, err := a.consoleShell()
	if err != nil {
		return err
	}
	if err := registry.Add(Component{
		// The console serves static assets and one configuration document, and
		// nothing else: D19's separability promise is that the console consumes
		// the public API and has no private endpoints of its own, so the only
		// thing this role adds to the console surface is the bundle and the
		// answer to "where is the API".
		Name:   "console",
		Roles:  []Role{RoleConsole},
		Routes: consoleShell.Routes(),
	}); err != nil {
		return err
	}
	if events != nil {
		ingestAPI, ierr := api.NewIngestAPI(api.IngestConfig{
			Adapter:         events.ingest,
			MaxRequestBytes: cfg.IngestMaxRequestBytes,
		})
		if ierr != nil {
			return ierr
		}
		if err := registry.Add(Component{
			// The ingest route is the consumer role's push half. It is mounted
			// without regard to whether this process runs the consumer loop:
			// [stream.Ingest.Submit] writes through the aggregator directly, so
			// a tier that mounts the route and polls no broker still ingests.
			// The route is on the callback surface behind a workload
			// credential — an event producer is a population that sits outside
			// the perimeter and is not the population that asks check
			// questions.
			Name:   "ingest-api",
			Roles:  []Role{RoleConsumer},
			Routes: ingestAPI.Routes(),
		}); err != nil {
			return err
		}
	}
	if err := registry.Add(Component{
		// The pull half. With a broker configured this is the Kafka consumer
		// loop; without one it is the HTTP ingest adapter's Run, which has
		// nothing to poll and waits for shutdown — a port that could not
		// accommodate both shapes would be a port describing a consumer loop.
		Name:  "event-consumer",
		Roles: []Role{RoleConsumer},
		Run:   a.consumeEvents,
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		// Correctness does not depend on this loop — the port refuses an event
		// older than the widest declarable window, so nothing it deletes could
		// still affect an answer — but the size of two tables that only ever
		// grow does.
		Name:  "retention-sweeper",
		Roles: []Role{RoleConsumer},
		Run:   a.sweepRetention,
	}); err != nil {
		return err
	}
	a.registry = registry

	// Readiness is answered by the schema gate on every tier, including the one
	// that migrates: the migrating tier has already applied everything by the
	// time it gets here, so the gate opens on its first probe, and a tier
	// configured not to migrate is exactly the one that has to wait. Which
	// tiers those are is deployment configuration, so the gate is not
	// conditional on it.
	readiness, gerr := newSchemaVersionGate(a.store, a.logger)
	if gerr != nil {
		return gerr
	}
	server, err := api.New(api.Config{
		Identity: middleware, Addresses: cfg.Addresses, Ready: readiness.ready,
	})
	if err != nil {
		return err
	}
	a.server = server
	return registry.Mount(a.roles, server)
}

// approverIssuerFor designates the IdP this deployment's approvers log in to.
//
// A bare approver identifier in a policy — `{members: [alice]}` — is an
// identity only relative to an issuer: OIDC promises `sub` is unique inside one
// issuer and says nothing across two, so on a deployment that pins several,
// `alice` at one IdP and `alice` at another are different people wearing one
// name. The challenge handlers refuse a bare set until they are told which
// issuer is meant, and this is where the deployment says so.
//
// The explicit designation wins, and [Config.validate] has already refused one
// that is not in the pinned set — a designated issuer whose tokens this process
// rejects would open quorums nobody could ever satisfy.
//
// Absent one, an install that pinned exactly one issuer has already answered
// the question and restating it would be configuration for its own sake. An
// install that pinned several and designated none genuinely has not answered
// it, and returning empty is what makes those handlers refuse rather than
// guess. Guessing — taking the first entry — would be picking which IdP's alice
// may approve.
func approverIssuerFor(cfg Config) string {
	if designated := strings.TrimSpace(cfg.ApproverIssuer); designated != "" {
		return designated
	}
	if len(cfg.OIDC.Issuers) == 1 {
		return cfg.OIDC.Issuers[0].Issuer
	}
	return ""
}

// ingestPlane is this process's event ingestion plane: the bucket aggregator,
// the adapters in front of it, the velocity sources that read back out of it,
// and the adapter whose loop the consumer role runs.
//
// It is nil on a deployment that declares no velocity sources — there is
// nothing to aggregate, and an aggregator over no metrics is refused by its own
// constructor rather than tolerated as an empty one.
type ingestPlane struct {
	aggregator *stream.Aggregator
	ingest     *stream.Ingest
	sources    *stream.Sources
	// consumer is the adapter the consumer role's loop runs. With a broker
	// configured it is the Kafka adapter; otherwise it is the HTTP ingest
	// adapter, whose Run waits for shutdown because its transport is the
	// request handler.
	consumer stream.Adapter
}

// ingestion assembles the event plane.
//
// The build order is fixed by the package and worth naming: declarations, then
// the aggregator, then the adapters, then the sources. Each adapter is
// constructed against the real declarations and the real sink, so the sources
// can be resolved against the real adapters rather than against placeholders
// that would then have to be swapped — which is the dance that ends up copied
// into production wiring and quietly diverging from the test that proved it.
func (a *App) ingestion(cfg Config, fallback engine.SourceResolver) (*ingestPlane, error) {
	if len(cfg.StreamSources) == 0 {
		return nil, nil
	}

	aggregator, err := stream.NewAggregator(stream.AggregatorConfig{
		Store:   a.store,
		Metrics: stream.MetricSpecsFor(cfg.StreamSources),
	})
	if err != nil {
		return nil, err
	}

	ingest, err := stream.NewIngest(stream.IngestConfig{
		Name:               cfg.IngestAdapterName,
		Declarations:       cfg.StreamSources,
		Sink:               aggregator,
		Credentials:        cfg.IngestCredentials,
		DefaultRate:        cfg.IngestRate,
		DefaultSubjectRate: cfg.IngestSubjectRate,
		MaxBatchEvents:     cfg.IngestMaxBatchEvents,
	})
	if err != nil {
		return nil, err
	}

	plane := &ingestPlane{aggregator: aggregator, ingest: ingest, consumer: ingest}
	adapters := []stream.Adapter{ingest}
	if cfg.Kafka.Configured() {
		kafka, kerr := stream.NewKafka(stream.KafkaConfig{
			Name:         cfg.Kafka.AdapterName,
			Brokers:      cfg.Kafka.Brokers,
			Group:        cfg.Kafka.Group,
			Topics:       cfg.Kafka.Topics,
			Declarations: cfg.StreamSources,
			PollRecords:  cfg.Kafka.PollRecords,
			OnReject:     a.recordDroppedRecord,
		})
		if kerr != nil {
			return nil, kerr
		}
		adapters = append(adapters, kafka)
		plane.consumer = kafka
	}

	plane.sources, err = stream.NewSources(cfg.StreamSources, stream.SourcesConfig{
		Aggregator: aggregator,
		Adapters:   adapters,
		Fallback:   fallback,
		Audit: fact.AuditorFunc(func(_ context.Context, f *fact.Failure) {
			a.logger.Warn("velocity lookup failed",
				slog.String("source", f.Source),
				slog.String("reason", f.AuditReason()),
				slog.Bool("fails_closed", f.FailsClosed()))
		}),
	})
	if err != nil {
		return nil, err
	}
	return plane, nil
}

// consumeEvents runs the ingestion adapter behind the consumer role.
func (a *App) consumeEvents(ctx context.Context) error {
	if a.events == nil {
		// A consumer tier on a deployment that declares no velocity sources has
		// nothing to poll. It stays up rather than exiting, because a component
		// that returned here would be read as a subsystem failure and would end
		// the process.
		a.logger.Info("the consumer role is active but no velocity sources are configured",
			slog.String("configure", EnvStreamSources))
		return blockUntilDone(ctx)
	}
	return a.events.consumer.Run(ctx, a.events.aggregator)
}

// recordDroppedRecord audits one ingestion record that can never be accepted.
//
// The drop itself is deliberate — a consumer stalled on one poison record stops
// updating every velocity aggregate in the deployment, which is a cheaper way
// to switch a limit off than anything in the threat model — and that is exactly
// why it goes in the audit chain rather than only in a log. An append failure
// is logged and swallowed: the consumer must not stall on the record it dropped
// to keep from stalling.
func (a *App) recordDroppedRecord(topic string, partition int32, offset int64, cause error) {
	detail := ""
	if cause != nil {
		detail = cause.Error()
	}
	a.logger.Error("an ingestion record was dropped as permanently unacceptable",
		slog.String("topic", topic),
		slog.Int64("partition", int64(partition)),
		slog.Int64("offset", offset),
		slog.String("error", detail))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.writer.Append(ctx, store.AuditEntry{
		Kind:    store.AuditKindEventRejected,
		Subject: topic,
		Payload: map[string]any{
			"topic":     topic,
			"partition": partition,
			"offset":    offset,
			"error":     detail,
		},
	}); err != nil {
		a.logger.Error("recording a dropped ingestion record failed",
			slog.String("topic", topic), slog.String("error", err.Error()))
	}
}

// sweepRetention prunes the dedup index and the bucket table.
//
// Both helpers open their own transaction, so this loop must not run inside
// one: the audit writer holds its append lock across a whole audited
// transaction, and a store call that opened a second one from inside it would
// deadlock. This loop is audited nowhere and nests inside nothing, which is
// what makes it safe to call them directly.
func (a *App) sweepRetention(ctx context.Context) error {
	ticker := time.NewTicker(a.cfg.RetentionSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			a.sweepOnce(ctx)
		}
	}
}

func (a *App) sweepOnce(ctx context.Context) {
	now := time.Now()
	events, err := a.store.PruneProcessedEvents(ctx, store.DefaultDedupRetention(), now)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			a.logger.Error("pruning processed events failed", slog.String("error", err.Error()))
		}
		return
	}
	buckets, err := a.store.PruneBuckets(ctx, store.MaxDeclarableWindow, now)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			a.logger.Error("pruning velocity buckets failed", slog.String("error", err.Error()))
		}
		return
	}
	if events > 0 || buckets > 0 {
		a.logger.Info("retention sweep",
			slog.Int64("processed_events", events), slog.Int64("buckets", buckets))
	}
}

// consoleShell builds the console serving provider.
//
// Two defaults are worth naming. The issuer falls back to the one this process
// already verifies tokens against, which is not a trust decision being guessed
// — it is the same issuer, stated once. The API base address does not fall back
// to anything: empty means same-origin, which is what the single-container
// install has, and an operator who splits the tiers sets it explicitly.
//
// A console with no relying-party configuration does not fail the boot. The
// bundle is public static content, the missing configuration cannot be
// mistaken for a permissive one, and `--roles=all` is the image's default
// command — failing here would mean every quickstart had to configure an IdP
// login before it could start. The console renders what is missing instead,
// and the log says it on the way up.
func (a *App) consoleShell() (*api.Console, error) {
	cfg := a.cfg.Console
	issuer := cfg.Issuer
	if issuer == "" && len(a.cfg.OIDC.Issuers) > 0 {
		issuer = a.cfg.OIDC.Issuers[0].Issuer
	}

	assets := console.Assets()
	if a.roles.Has(RoleConsole) {
		switch {
		case !console.Built():
			a.logger.Warn("this build carries no console bundle; the console role serves guidance instead",
				slog.String("build", "cd console && npm ci && npm run build"))
		case cfg.ClientID == "" || cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "":
			a.logger.Warn("the console has no relying party configured and cannot log anyone in",
				slog.String("configure", strings.Join([]string{
					EnvConsoleOIDCClientID, EnvConsoleOIDCAuthz, EnvConsoleOIDCToken,
				}, ", ")))
		}
	}

	return api.NewConsole(api.ConsoleConfig{
		Assets:     assets,
		APIBaseURL: cfg.APIBaseURL,
		OIDC: api.ConsoleOIDC{
			Issuer:                issuer,
			AuthorizationEndpoint: cfg.AuthorizationEndpoint,
			TokenEndpoint:         cfg.TokenEndpoint,
			EndSessionEndpoint:    cfg.EndSessionEndpoint,
			ClientID:              cfg.ClientID,
			Scopes:                cfg.Scopes,
			RoleClaim:             cfg.RoleClaim,
		},
		AllowInsecureTransport: cfg.AllowInsecureTransport,
	})
}

// challengeHandlers builds the challenge kinds this deployment serves.
//
// Three of the four are unconditional. A delay owns no configuration at all, an
// external handler needs only the egress gate — a deployment with no targets
// configured still registers it, because the refusal a policy naming an unknown
// target gets from the handler is more useful than the one it would get from an
// empty registry — and the quorum is built by the caller.
//
// The fourth is conditional, and that is the resolution of U10's first trap
// rather than a shortcut. [mfa.Config].AllowedACRValues is mandatory by design:
// an IdP downgrades an unsatisfiable `acr` request silently, so a handler with
// no allowlist is a handler whose only real check does not run, and NewDelegated
// refuses to exist without one. Making the handler unconditional would therefore
// mean every deployment — including a check-only tier that never issues a
// challenge — had to configure an IdP step-up endpoint to start. Leaving the
// kind unregistered is the fail-closed alternative: a policy declaring an mfa
// challenge gets [challenge.ErrNoHandler] at issue, and a challenge with no
// handler cannot be satisfied.
func (a *App) challengeHandlers(quorum *challenge.Quorum, gate *fact.Gate,
	groups challenge.GroupResolver,
) ([]challenge.Handler, error) {
	cfg := a.cfg
	external, err := challenge.NewExternal(challenge.ExternalConfig{
		Gate:            gate,
		Targets:         cfg.ExternalTargets,
		CallbackBaseURL: cfg.CallbackBaseURL,
		// R43's dispatch budget. It is the same operator setting the step-up
		// handler reads, because "how much may one subject cause" is one thought;
		// what the two handlers do with an unset value differs, and that is the
		// handlers' own business.
		SubjectRate: cfg.ChallengeIssueRate,
	})
	if err != nil {
		return nil, err
	}
	handlers := []challenge.Handler{
		quorum,
		// The delay takes the group resolver for the same reason the quorum
		// does: a cancellation authority is an approver set in every respect
		// that matters, and cutting a wait short is an authority somebody
		// exercises. Leaving it nil would make a group-backed canceller an
		// issue-time refusal on a deployment that has the directory configured.
		challenge.NewDelay(challenge.DelayConfig{
			Groups:         groups,
			ApproverIssuer: approverIssuerFor(cfg),
		}),
		external,
	}

	if !cfg.MFA.Configured() {
		a.logger.Info("delegated mfa is not configured; the mfa challenge kind has no handler",
			slog.String("configure", EnvMFAACRValues))
		return handlers, nil
	}
	delegated, err := a.delegatedMFA()
	if err != nil {
		return nil, err
	}
	return append(handlers, delegated), nil
}

// delegatedMFA builds the step-up handler, with the CIBA client in front of it
// when one is configured.
//
// The chain order is D26's: CIBA is tried first because it is the better
// experience when it exists, and it falls through to the step-up redirect on
// [mfa.ErrInitiationUnsupported] alone — which is what a real IdP answers when
// its CIBA grant surface is present but has no decoupled authentication server
// behind it. Every other failure stays a failure.
func (a *App) delegatedMFA() (*mfa.Delegated, error) {
	cfg := a.cfg
	// R42: a client secret arrives from a file, never from a value. Empty is the
	// normal case — a step-up client is public and PKCE is the proof.
	var clientSecret string
	if path := cfg.MFA.ClientSecretFile; path != "" {
		raw, rerr := os.ReadFile(path) //nolint:gosec // an operator-supplied secret mount path
		if rerr != nil {
			return nil, fmt.Errorf("runtime: reading %s: %w", EnvMFAClientSecret, rerr)
		}
		clientSecret = strings.TrimSpace(string(raw))
		if clientSecret == "" {
			return nil, fmt.Errorf("runtime: %s names an empty file", EnvMFAClientSecret)
		}
	}
	requests, err := identity.NewStepUp(identity.StepUpConfig{
		AuthorizationEndpoint:  cfg.MFA.AuthorizationEndpoint,
		ClientID:               cfg.MFA.ClientID,
		RedirectURI:            cfg.MFA.RedirectURI,
		TokenEndpoint:          cfg.MFA.TokenEndpoint,
		ClientSecret:           clientSecret,
		Scopes:                 cfg.MFA.Scopes,
		AllowInsecureTransport: cfg.MFA.AllowInsecureTransport,
	})
	if err != nil {
		return nil, err
	}
	stepUp, err := mfa.NewStepUp(requests)
	if err != nil {
		return nil, err
	}

	var initiator mfa.Initiator = stepUp
	if cfg.MFA.CIBA.Configured() {
		ciba, cerr := mfa.NewCIBA(mfa.CIBAConfig{
			BackchannelEndpoint:    cfg.MFA.CIBA.BackchannelEndpoint,
			TokenEndpoint:          cfg.MFA.CIBA.TokenEndpoint,
			ClientID:               cfg.MFA.CIBA.ClientID,
			ClientSecret:           cfg.MFA.CIBA.ClientSecret,
			Scope:                  cfg.MFA.CIBA.Scope,
			AllowInsecureTransport: cfg.MFA.AllowInsecureTransport,
		})
		if cerr != nil {
			return nil, cerr
		}
		if initiator, cerr = mfa.NewFallback(ciba, stepUp); cerr != nil {
			return nil, cerr
		}
	}

	// The three token pins default to the deployment's own issuer, the step-up
	// client and the check audience, which is what a single-IdP install has.
	// They are separately settable because a challenge is satisfied by the
	// authentication it asked for, not by any token this process would accept.
	issuer := cfg.MFA.Issuer
	if issuer == "" && len(cfg.OIDC.Issuers) > 0 {
		issuer = cfg.OIDC.Issuers[0].Issuer
	}
	clientID := cfg.MFA.TokenClientID
	if clientID == "" {
		clientID = cfg.MFA.ClientID
	}
	audience := cfg.MFA.Audience
	if audience == "" {
		audience = cfg.OIDC.Audience
	}

	base := strings.TrimRight(cfg.CallbackBaseURL, "/")
	return mfa.NewDelegated(mfa.Config{
		Initiator:        initiator,
		AllowedACRValues: cfg.MFA.AllowedACRValues,
		RequiredAMR:      cfg.MFA.RequiredAMR,
		// R43's two issue budgets. They are above the re-issue interval and not
		// instead of it: that interval is keyed on the decision content and so
		// cannot see a caller opening a different decision every time.
		//
		// The first is charged on (caller, subject) and the second on the
		// subject across every caller. One bucket cannot be both — a
		// subject-only bucket small enough to protect a person is a bucket any
		// caller can hold empty against that person, which is what this was
		// until #40's follow-up.
		CallerSubjectIssueRate: cfg.ChallengeIssueRate,
		SubjectIssueCeiling:    cfg.ChallengeIssueSubjectCeiling,
		Issuer:                 issuer,
		ClientID:               clientID,
		Audience:               audience,
		CallbackURL: func(in challenge.Instance) string {
			if base == "" {
				return ""
			}
			return base + api.MFACallbackPath(in.DecisionID, in.Ordinal)
		},
	})
}

// Listen binds every configured surface without serving, so a caller can learn
// the actual addresses before a request is accepted.
func (a *App) Listen() error {
	if a.listeners != nil {
		return nil
	}
	l, err := a.server.Listen()
	if err != nil {
		return err
	}
	a.listeners = l
	return nil
}

// Addr reports a surface's bound address, empty when it is not served.
func (a *App) Addr(surface api.Surface) string {
	if a.listeners == nil {
		return ""
	}
	return a.listeners.Addr(surface)
}

// Serve runs the active components and the bound listeners until the context is
// cancelled or a component fails.
//
// A failing component ends the process rather than being restarted. Every one
// of them is a loop whose failure means a dependency is gone — the audit chain,
// the database — and a stamp process that kept serving with its audit path
// stopped would be answering questions it could not record having answered.
func (a *App) Serve(ctx context.Context) error {
	if err := a.Listen(); err != nil {
		return err
	}

	runners := a.registry.Runners(a.roles)
	errCh := make(chan error, len(runners)+1)
	ctx, stop := context.WithCancel(ctx)
	defer stop()

	var wg sync.WaitGroup
	for _, c := range runners {
		wg.Add(1)
		go func(c Component) {
			defer wg.Done()
			a.logger.Info("component started", slog.String("component", c.Name))
			if err := c.Run(ctx); err != nil {
				errCh <- fmt.Errorf("component %s: %w", c.Name, err)
			}
		}(c)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := a.listeners.Serve(ctx); err != nil {
			errCh <- err
		}
	}()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
		a.logger.Error("subsystem failed", slog.String("error", runErr.Error()))
		stop()
	}
	wg.Wait()

	// The buffer holds check events that are not yet in the chain. Flushing on
	// the way out is what keeps a graceful shutdown from becoming a gap in the
	// audit log.
	flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), api.DefaultShutdownTimeout)
	defer cancel()
	if err := a.buffer.Flush(flushCtx); err != nil {
		a.logger.Error("final audit flush failed", slog.String("error", err.Error()))
		if runErr == nil {
			runErr = err
		}
	}
	return runErr
}

// Close releases everything the assembly holds. It is safe to call more than
// once and safe to call on a partially built app.
func (a *App) Close() {
	a.closeOnce.Do(func() {
		if a.listeners != nil {
			_ = a.listeners.Close()
		}
		if a.facts != nil {
			a.facts.Close()
		}
		if a.groups != nil {
			a.groups.Close()
		}
		if a.writer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = a.writer.Close(ctx)
		}
		if a.store != nil {
			a.store.Close()
		}
	})
}

// BootstrapToken is the one-time governance token, non-empty only on the start
// that issued it. R34 gives it exactly one print.
func (a *App) BootstrapToken() string { return a.bootstrapToken }

// Components reports the active component names, for the startup log.
func (a *App) Components() []string { return a.registry.ActiveNames(a.roles) }

// Store exposes the persistence handle.
func (a *App) Store() *store.Store { return a.store }

// Decisions exposes the decide path.
func (a *App) Decisions() DecisionPath { return a.decide }

// Governance exposes the revision path.
func (a *App) Governance() *revision.Service { return a.governance }

// Check exposes the check tier.
func (a *App) Check() *engine.CheckService { return a.check }

// Challenges exposes the challenge handlers this process registered.
//
// It is a read of what the deployment configured: the mfa kind is present only
// when a step-up is configured, and an operator has to be able to see that
// without inferring it from a decision that failed to issue.
func (a *App) Challenges() *challenge.Registry { return a.challenges }

// Refresh reloads the effective policy set on both planes at once, rather than
// waiting for their polls. A deployment never needs it — the polls are R24's
// freshness bound — but a caller that has just written a policy and wants to
// observe the result does.
func (a *App) Refresh(ctx context.Context) error {
	if err := a.check.Refresh(ctx); err != nil {
		return err
	}
	return a.decide.refresh(ctx)
}

// reconcileLoop applies a revision whose quorum came in while nobody was
// submitting. The approval path reconciles inline; this is for the approval
// that completes a quorum and then loses its process, and for a revision whose
// decision expired.
func (a *App) reconcileLoop(ctx context.Context) error {
	ticker := time.NewTicker(a.cfg.ReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			applied, err := a.governance.Reconcile(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				a.logger.Error("revision reconcile failed", slog.String("error", err.Error()))
				continue
			}
			for _, p := range applied {
				a.logger.Info("revision applied", slog.String("revision", p.ID))
			}
		}
	}
}

// reconciling is the seam between "the last approval landed" and "the revision
// took effect".
//
// The approval surface knows nothing about revisions — it submits evidence to a
// challenge — so the step that notices a governance decision has resolved has to
// be attached here. A reconcile failure does not fail the approval: the approval
// is recorded either way, and the timer picks the revision up.
type reconciling struct {
	inner      api.ApprovalSubmitter
	governance *revision.Service
	logger     *slog.Logger
}

func (r *reconciling) Submit(ctx context.Context, sub decision.Submission) (decision.Result, error) {
	result, err := r.inner.Submit(ctx, sub)
	if err != nil {
		return result, err
	}
	if _, rerr := r.governance.Reconcile(ctx); rerr != nil {
		r.logger.Error("revision reconcile after approval failed",
			slog.String("decision", sub.DecisionID), slog.String("error", rerr.Error()))
	}
	return result, nil
}

// notImplemented used to be here: the placeholder a slot with a later owner
// answered with. It has no users left — the console serves the real thing, and
// the event consumer, which was the last unfilled slot, now runs an ingestion
// adapter rather than waiting for one.
//
// It is not being kept for the next unit. A dead helper waiting for a use is a
// helper nobody remembers the rules of.

// blockUntilDone is what a runner with nothing to do waits on.
//
// It is not a placeholder any more. A consumer tier on a deployment that
// declares no velocity sources genuinely has nothing to poll, and it has to
// stay up: a component that returned would be read as a subsystem failure and
// would end the process.
func blockUntilDone(ctx context.Context) error {
	<-ctx.Done()
	return nil
}
