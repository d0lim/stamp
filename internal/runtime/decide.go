package runtime

// decide.go keeps the decide path's evaluator current.
//
// [decision.Config] takes a built evaluator rather than a loader, deliberately:
// the two evaluator invariants live in that type and a service that took a
// function could be handed one that bypasses them. The consequence is that a
// service holds the policy set it was built with forever, so a long-running
// decide tier would keep issuing challenges from the version it booted on. The
// plane closes that by rebuilding the service when the snapshot revision moves —
// the same poll-and-swap the check tier does, expressed one level up because
// the swappable thing here is the service and not the evaluator.
//
// The plane loads its own snapshot rather than sharing the check tier's. Policy
// normalization rewrites the condition tree in place, so a policy value reached
// from two goroutines is a data race; two loads produce two decoded copies and
// the question does not arise.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
)

// DecisionPath is the decide-side entry points a surface or a test drives.
type DecisionPath interface {
	Decide(ctx context.Context, req decision.Request) (decision.Result, error)
	Submit(ctx context.Context, sub decision.Submission) (decision.Result, error)
	Redeem(ctx context.Context, cb decision.Callback) (challenge.Redemption, error)
	Get(ctx context.Context, caller *identity.Subject, id string) (decision.Result, error)
}

// decidePlane is a decision service that follows the effective policy set.
type decidePlane struct {
	base     decision.Config
	loader   engine.SnapshotLoader
	resolver engine.SourceResolver
	interval time.Duration

	mu       sync.RWMutex
	revision engine.Revision
	svc      *decision.Service
	// schema is the held snapshot's schema. It is kept rather than discarded
	// with the snapshot because a surface that takes an access request has to
	// interpret its properties against the declarations the evaluation will
	// read, and the decide path had no way to see them.
	schema *policy.Schema
}

var _ DecisionPath = (*decidePlane)(nil)

// newDecidePlane builds the plane and loads the policy set once. The initial
// load must succeed, for the same reason the check tier's must: an instance
// that started without a policy set would report a policy problem for what is a
// boot problem.
func newDecidePlane(ctx context.Context, base decision.Config, loader engine.SnapshotLoader,
	resolver engine.SourceResolver, interval time.Duration,
) (*decidePlane, error) {
	if loader == nil {
		return nil, errors.New("runtime: the decide plane requires a snapshot loader")
	}
	p := &decidePlane{base: base, loader: loader, resolver: resolver, interval: interval}
	if p.interval <= 0 {
		p.interval = engine.DefaultRefreshInterval
	}
	if err := p.refresh(ctx); err != nil {
		return nil, fmt.Errorf("runtime: initial decide policy load: %w", err)
	}
	return p, nil
}

// refresh polls once and rebuilds the service when the revision moved.
func (p *decidePlane) refresh(ctx context.Context) error {
	snap, rev, err := p.loader.LoadSnapshot(ctx)
	if err != nil {
		return err
	}
	if snap == nil {
		return errors.New("runtime: snapshot loader returned no snapshot")
	}

	p.mu.RLock()
	unchanged := p.svc != nil && p.revision == rev
	p.mu.RUnlock()
	if unchanged {
		return nil
	}

	var opts []engine.Option
	if p.resolver != nil {
		opts = append(opts, engine.WithSourceResolver(p.resolver))
	}
	cfg := p.base
	cfg.Evaluator = engine.NewDecideEvaluator(snap, opts...)
	svc, err := decision.New(cfg)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.svc, p.revision, p.schema = svc, rev, snap.Schema()
	p.mu.Unlock()
	return nil
}

// Run polls until the context is cancelled. A failing poll does not stop the
// loop: the service already held keeps serving, which is the same staged
// failure the check tier makes.
func (p *decidePlane) Run(ctx context.Context) error {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = p.refresh(ctx)
		}
	}
}

// Service returns the service as it currently stands.
func (p *decidePlane) Service() *decision.Service {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.svc
}

// Schema returns the schema of the policy set the plane currently judges on, so
// that a surface interprets a request against the same declarations the
// evaluation will read. The caller must not modify it. Nil means no policy set
// is held, which a constructed plane never reports — the initial load must
// succeed — and which a surface still has to answer for rather than crash on.
//
// It deliberately does not reach for the check tier's schema. A decide-only
// process runs no check service, and asking for one here would make the two
// roles inseparable to serve one read.
func (p *decidePlane) Schema() *policy.Schema {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.schema
}

// Decide creates a decision against the currently held policy set.
func (p *decidePlane) Decide(ctx context.Context, req decision.Request) (decision.Result, error) {
	return p.Service().Decide(ctx, req)
}

// Submit hands evidence to a challenge.
func (p *decidePlane) Submit(ctx context.Context, sub decision.Submission) (decision.Result, error) {
	return p.Service().Submit(ctx, sub)
}

// Redeem turns a challenge's own redirect into the makings of a submission.
//
// It goes through the plane for the reason [decidePlane.Get] does: a revision
// that swaps the service between the redemption and the submission that follows
// it must not leave the two talking to different services.
func (p *decidePlane) Redeem(ctx context.Context, cb decision.Callback) (challenge.Redemption, error) {
	return p.Service().Redeem(ctx, cb)
}

// Get returns a decision to a caller R40 entitles to see it.
//
// The rule itself — creator or targeted approver, and the audited refusal — is
// [decision.Service.Get]'s, and going through the plane rather than through a
// captured service is what keeps the read on the same service the writes use
// after a revision swaps it.
func (p *decidePlane) Get(ctx context.Context, caller *identity.Subject, id string) (decision.Result, error) {
	return p.Service().Get(ctx, caller, id)
}
