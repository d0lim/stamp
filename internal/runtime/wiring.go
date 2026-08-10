package runtime

// wiring.go is the composition root: the one place that knows every subsystem
// and the order they have to be built in.
//
// Nothing below decides anything. Each unit's package holds its own rules, and
// what happens here is only assembly — which is why the file reads as a list.
// Two properties of the assembly are not incidental, though.
//
// The whole dependency graph is built whatever roles are selected, and only the
// components are role-gated. A stamp process talks to one database and holds one
// audit writer no matter which subsystems it runs, so building half a graph
// would buy nothing and would mean every constructor had to tolerate a nil
// neighbour. What --roles decides is which routes are mounted and which loops
// run, and that decision is made once, by the registry.
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
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/challenge/mfa"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// App is one assembled stamp process.
type App struct {
	cfg    Config
	roles  Set
	logger *slog.Logger

	store      *store.Store
	writer     *store.AuditWriter
	facts      *fact.Registry
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

	app := &App{cfg: cfg, roles: roles, logger: logger}
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
		Writer:        writer,
		Capacity:      cfg.AuditCapacity,
		BatchSize:     cfg.AuditBatchSize,
		FlushInterval: cfg.AuditFlushInterval,
		FailClosed:    cfg.AuditFailClosed,
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
	facts, err := fact.NewRegistry(cfg.FactSources, fact.Config{
		Egress:        cfg.Egress,
		AllowFailOpen: cfg.AllowFactFailOpen,
		Audit: fact.AuditorFunc(func(_ context.Context, f *fact.Failure) {
			a.logger.Warn("fact lookup failed",
				slog.String("reason", f.AuditReason()),
				slog.Bool("fails_closed", f.FailsClosed()))
		}),
	})
	if err != nil {
		return err
	}
	a.facts = facts
	resolver, err := api.NewFactResolver(facts)
	if err != nil {
		return err
	}

	// --- evaluation --------------------------------------------------------
	loader := &snapshotSource{store: s, facts: facts}
	check, err := engine.NewCheckService(ctx, engine.CheckConfig{
		Loader:            loader,
		RefreshInterval:   cfg.PolicyRefreshInterval,
		StalenessDeadline: cfg.PolicyStalenessDeadline,
		Resolver:          resolver,
	})
	if err != nil {
		return err
	}
	a.check = check

	// --- decisions ---------------------------------------------------------
	quorum, err := challenge.NewQuorum(challenge.QuorumConfig{Audit: writer, DB: s.Pool()})
	if err != nil {
		return err
	}
	handlers, err := a.challengeHandlers(quorum)
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
	}, loader, resolver, cfg.PolicyRefreshInterval)
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
		Resolver:    resolver,
		Floor:       cfg.GovernanceFloor,
		TTL:         cfg.RevisionTTL,
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
	// Every collecting surface submits through the same seam: an approval, an
	// mfa completion, a delay cancellation and a webhook verdict are one code
	// path with four doors, and the revision reconcile that has to follow the
	// last approval has to follow all four for the same reason.
	submitter := &reconciling{inner: plane, governance: governance, logger: a.logger}
	approvals, err := api.NewApprovals(api.ApprovalsConfig{Decisions: submitter, Reviews: quorum})
	if err != nil {
		return err
	}
	cancellations, err := api.NewCancellations(api.CancellationsConfig{Decisions: submitter})
	if err != nil {
		return err
	}
	callbacks, err := api.NewCallbacks(api.CallbacksConfig{Decisions: submitter})
	if err != nil {
		return err
	}
	mfaCallback, err := api.NewMFA(api.MFAConfig{Decisions: submitter, Tokens: verifier})
	if err != nil {
		return err
	}
	policies, err := api.NewPolicies(api.PoliciesConfig{
		Governance: governance,
		Policies: api.PolicyListerFunc(func(ctx context.Context) ([]store.PolicyRecord, error) {
			return store.EffectivePolicies(ctx, s.Pool())
		}),
		Bootstrap: governance.Bootstrap(),
	})
	if err != nil {
		return err
	}

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
		Name:   "approval-api",
		Roles:  []Role{RoleDecide},
		Routes: approvals.Routes(),
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
	if err := registry.Add(Component{
		// The console shell is U14's. The route is registered so that role
		// selection is testable and so that a console-only process answers
		// something other than a 404 at its own path.
		Name:  "console",
		Roles: []Role{RoleConsole},
		Routes: []api.Route{{
			Name:    "console-shell",
			Surface: api.SurfaceConsole,
			Pattern: "GET /console/",
			Auth:    api.AuthUser,
			Handler: notImplemented("console"),
		}},
	}); err != nil {
		return err
	}
	if err := registry.Add(Component{
		// The event ingest and bucket aggregation are U12's. The slot exists so
		// the role is real from the first release rather than appearing later.
		Name:  "event-consumer",
		Roles: []Role{RoleConsumer},
		Run:   blockUntilDone,
	}); err != nil {
		return err
	}
	a.registry = registry

	server, err := api.New(api.Config{Identity: middleware, Addresses: cfg.Addresses})
	if err != nil {
		return err
	}
	a.server = server
	return registry.Mount(a.roles, server)
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
func (a *App) challengeHandlers(quorum *challenge.Quorum) ([]challenge.Handler, error) {
	cfg := a.cfg
	gate, err := fact.NewGate(cfg.Egress)
	if err != nil {
		return nil, err
	}
	external, err := challenge.NewExternal(challenge.ExternalConfig{
		Gate:            gate,
		Targets:         cfg.ExternalTargets,
		CallbackBaseURL: cfg.CallbackBaseURL,
	})
	if err != nil {
		return nil, err
	}
	handlers := []challenge.Handler{quorum, challenge.NewDelay(challenge.DelayConfig{}), external}

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
	requests, err := identity.NewStepUp(identity.StepUpConfig{
		AuthorizationEndpoint:  cfg.MFA.AuthorizationEndpoint,
		ClientID:               cfg.MFA.ClientID,
		RedirectURI:            cfg.MFA.RedirectURI,
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
		Issuer:           issuer,
		ClientID:         clientID,
		Audience:         audience,
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

// notImplemented is the placeholder a slot with a later owner answers with. It
// is deliberately not a 404: the route is registered here, and an operator has
// to be able to tell "this build does not serve that yet" from "this process
// does not run that subsystem".
func notImplemented(component string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Stamp-Component", component)
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = io.WriteString(w, "not implemented\n")
	})
}

func blockUntilDone(ctx context.Context) error {
	<-ctx.Done()
	return nil
}
