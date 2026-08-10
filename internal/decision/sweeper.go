package decision

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/d0lim/stamp/internal/store"

	"github.com/jackc/pgx/v5"
)

// Sweeper defaults.
const (
	// DefaultSweepInterval is how often the sweeper wakes when the deployment
	// does not say. Expiry precision is bounded by it, and it is deliberately
	// short: the column is the source of truth, so being late costs nothing but
	// the delay between a decision ending and its row saying so.
	DefaultSweepInterval = 5 * time.Second

	// DefaultSweepBatch is how many due decisions one claim takes.
	DefaultSweepBatch = 100
)

// SweeperConfig configures a Sweeper.
type SweeperConfig struct {
	// Service is the lifecycle the sweeper drives. Required.
	Service *Service

	// Interval is the wake-up period. Zero uses DefaultSweepInterval.
	Interval time.Duration

	// Batch is how many decisions one claim takes. Zero uses
	// DefaultSweepBatch.
	Batch int

	// OnError observes an error from one sweep. The loop continues regardless:
	// a sweeper that stopped on the first error would leave every later
	// decision pending forever, which is a worse failure than a noisy log.
	OnError func(error)
}

// Sweeper resolves decisions whose deadlines have passed.
//
// Expiry is a Postgres column plus this loop, not a job queue and not a timer
// per decision. The column is the truth — every entry-time check reads it, so a
// decision is over the instant it says so whether or not this loop has run —
// and the sweep is deferred cleanup that makes the row agree.
//
// Several instances may sweep the same table. Two mechanisms make that safe,
// and both are needed. The claim uses FOR UPDATE SKIP LOCKED, so instances
// working at the same moment take disjoint batches instead of queueing behind
// each other. The write is a conditional update guarded by the transition
// function, so an instance that claims a decision another has already resolved
// finds it no longer pending and does nothing. SKIP LOCKED alone would not be
// enough: locks are released at commit, and two sweeps that overlap in time but
// not in transaction can still claim the same row.
type Sweeper struct {
	svc      *Service
	interval time.Duration
	batch    int
	onError  func(error)
}

// NewSweeper builds a Sweeper.
func NewSweeper(cfg SweeperConfig) (*Sweeper, error) {
	if cfg.Service == nil {
		return nil, errors.New("decision: a sweeper needs a service")
	}
	s := &Sweeper{
		svc:      cfg.Service,
		interval: cfg.Interval,
		batch:    cfg.Batch,
		onError:  cfg.OnError,
	}
	if s.interval <= 0 {
		s.interval = DefaultSweepInterval
	}
	if s.batch <= 0 {
		s.batch = DefaultSweepBatch
	}
	return s, nil
}

// SweepReport counts what one sweep did.
type SweepReport struct {
	// Claimed is how many due decisions the claim returned.
	Claimed int
	// Expired is how many this sweep resolved as expired.
	Expired int
	// Advanced is how many had a challenge timer that this sweep settled.
	Advanced int
	// Skipped is how many were already resolved by the time this sweep tried,
	// which is the expected outcome of two sweepers meeting on one row.
	Skipped int
}

// Run sweeps until the context is cancelled. It is the Run of the registry's
// sweeper component.
func (s *Sweeper) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.drain(ctx)
		}
	}
}

// drain sweeps until a batch comes back short, so a backlog does not take one
// interval per batch to clear.
func (s *Sweeper) drain(ctx context.Context) {
	for {
		report, err := s.SweepOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if s.onError != nil {
				s.onError(err)
			}
			return
		}
		if report.Claimed < s.batch {
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// SweepOnce claims one batch of due decisions and resolves them.
//
// The claim transaction reads and commits without writing. That is not
// squeamishness about doing work inside a transaction: the writes a sweep
// performs go through the audit writer, which owns its own pinned connection
// and its own transaction, and a write on that connection would block on the
// row locks the claim transaction is holding — which cannot be released until
// the callback returns. The process would deadlock against itself. So the claim
// selects the work and the resolution does it, with the conditional update
// keeping the result exactly-once.
func (s *Sweeper) SweepOnce(ctx context.Context) (SweepReport, error) {
	now := s.svc.Now()
	var due []store.Decision
	err := s.svc.store.ClaimDue(ctx, now, s.batch,
		func(_ context.Context, _ pgx.Tx, claimed []store.Decision) error {
			due = append(due, claimed...)
			return nil
		})
	if err != nil {
		return SweepReport{}, fmt.Errorf("decision: claim due decisions: %w", err)
	}

	report := SweepReport{Claimed: len(due)}
	for _, d := range due {
		switch {
		case d.Expired(now):
			resolved, err := s.svc.resolve(ctx, d, Expire, ReasonExpired)
			switch {
			case errors.Is(err, ErrIllegalTransition):
				// Another instance resolved it between the claim and the
				// write. Next said so, which is the whole reason the write
				// goes through Next.
				report.Skipped++
			case err != nil:
				return report, err
			case resolved:
				report.Expired++
			default:
				report.Skipped++
			}
		default:
			// The row is due on a challenge timer rather than on its own
			// deadline. Only the handler knows what an elapsed timer means, so
			// the settle path asks it: a delay reports satisfied, a quorum that
			// ran out of time reports pending and is failed.
			if _, err := s.svc.advance(ctx, d.ID, now); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					report.Skipped++
					continue
				}
				return report, err
			}
			report.Advanced++
		}
	}
	return report, nil
}
