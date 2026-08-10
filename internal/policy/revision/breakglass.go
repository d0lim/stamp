package revision

// breakglass.go is the only way back from the lock, and it is deliberately
// outside the running system (R34).
//
// After the lock, governance can only be changed by a revision that passes
// through the quorum it installs. That is the guarantee, and a guarantee with an
// online escape hatch is a feature request away from being no guarantee at all.
// So the escape hatch is offline: it refuses to run while the service is up, it
// connects to the database directly, and it puts the reserved policy back into
// solo-admin mode with a fresh bootstrap token.
//
// Two liveness checks, because either alone has a hole. A held audit-writer
// claim means a stamp process is alive somewhere against this database, which
// catches the case where the operator is on a different host from the service.
// A bindable listen address catches a process that has not claimed a writer yet
// — it is starting up right now — and it is the check an operator can reason
// about locally.
//
// The reset and its audit row are one transaction. A reset that committed
// without its record would be exactly the event an attacker wants and the
// audit chain would not show it.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// ErrListenersRunning reports a break-glass attempt while the service is up.
var ErrListenersRunning = errors.New("revision: break-glass cannot run while the service is running")

// DefaultBreakGlassWriter is the audit writer identifier the procedure claims.
// It is its own segment so that the reset is chained separately from whatever
// the service was writing, and so that claiming it cannot collide with a live
// instance's writer.
const DefaultBreakGlassWriter = "breakglass"

// BreakGlassConfig configures one run of the offline recovery procedure.
type BreakGlassConfig struct {
	// Store is a direct database handle. Required.
	Store *store.Store
	// WriterID is the audit segment the reset is chained into. Empty selects
	// [DefaultBreakGlassWriter].
	WriterID string
	// Instance names the host running the procedure, for the writer claim.
	Instance string
	// Actor is the operator running it. Required: a reset with no name on it is
	// a reset nobody has to answer for.
	Actor string
	// Reason is why. Required, and recorded verbatim.
	Reason string
	// Addresses are the listen addresses the service would bind. Each is probed;
	// one that is already bound refuses the run.
	Addresses []string
	// Now is the clock. Nil uses the store's.
	Now func() time.Time
}

// BreakGlassResult is what one run produced.
type BreakGlassResult struct {
	// Token is the fresh bootstrap token, printed once. Governance is in
	// solo-admin mode again and this is the only thing that authorizes it.
	Token string
	// PolicyVersion is the version of the reserved policy the reset wrote.
	PolicyVersion int64
	// AuditSeq is the sequence number of the highest-severity record the reset
	// appended.
	AuditSeq int64
}

// BreakGlass puts governance back into solo-admin mode from outside the running
// system.
func BreakGlass(ctx context.Context, cfg BreakGlassConfig) (BreakGlassResult, error) {
	switch {
	case cfg.Store == nil:
		return BreakGlassResult{}, errors.New("revision: break-glass needs a store")
	case cfg.Actor == "":
		return BreakGlassResult{}, errors.New("revision: break-glass needs the name of the operator running it")
	case cfg.Reason == "":
		return BreakGlassResult{}, errors.New("revision: break-glass needs a reason, and it is recorded")
	}
	writerID := cfg.WriterID
	if writerID == "" {
		writerID = DefaultBreakGlassWriter
	}

	if err := refuseIfRunning(ctx, cfg.Store, cfg.Addresses); err != nil {
		return BreakGlassResult{}, err
	}

	writer, err := cfg.Store.ClaimWriter(ctx, writerID, cfg.Instance)
	if err != nil {
		return BreakGlassResult{}, err
	}
	defer func() { _ = writer.Close(context.WithoutCancel(ctx)) }()

	bootstrap, err := NewBootstrap(BootstrapConfig{Store: cfg.Store, Audit: writer, Now: cfg.Now})
	if err != nil {
		return BreakGlassResult{}, err
	}

	var out BreakGlassResult
	err = writer.InTx(ctx, func(ctx context.Context, tx pgx.Tx, ap *store.Appender) error {
		// The check runs again inside the transaction. A service that started
		// between the probe and here would be writing decisions against the
		// governance policy this is about to replace.
		if err := refuseIfClaimed(ctx, tx, writerID); err != nil {
			return err
		}
		rec, current, err := currentGovernance(ctx, tx)
		if err != nil {
			return err
		}
		previous, _ := GovernanceQuorum(current)

		reset, err := store.PutPolicy(ctx, tx, store.PolicyInput{
			Policy:        GovernancePolicy(),
			SchemaVersion: rec.SchemaVersion,
			Origin:        rec.Origin,
			Author:        cfg.Actor,
		})
		if err != nil {
			return err
		}
		out.PolicyVersion = reset.Version

		token, err := bootstrap.mint(ctx, tx, ap, true)
		if err != nil {
			return err
		}
		out.Token = token

		records, err := ap.Append(ctx, store.AuditEntry{
			Kind:    AuditKindGovernanceReset,
			Subject: GovernancePolicyID,
			Payload: map[string]any{
				SeverityKey:         SeverityCritical,
				"actor":             cfg.Actor,
				"reason":            cfg.Reason,
				"instance":          cfg.Instance,
				"policy_version":    reset.Version,
				"previous_quorum":   previous.Threshold,
				"previous_approver": previous.Approvers.Members,
				"detail": "governance was reset to solo-admin mode by the offline break-glass " +
					"procedure and a new bootstrap token was issued",
			},
		})
		if err != nil {
			return err
		}
		out.AuditSeq = records[0].Seq
		return nil
	})
	if err != nil {
		return BreakGlassResult{}, err
	}
	return out, nil
}

// currentGovernance reads the reserved policy inside a transaction.
func currentGovernance(ctx context.Context, q store.Querier) (store.PolicyRecord, *policy.Policy, error) {
	rec, err := store.EffectivePolicy(ctx, q, GovernancePolicyID)
	if errors.Is(err, store.ErrNotFound) {
		return store.PolicyRecord{}, nil, ErrNotInstalled
	}
	if err != nil {
		return store.PolicyRecord{}, nil, err
	}
	p, err := rec.Policy()
	if err != nil {
		return store.PolicyRecord{}, nil, err
	}
	return rec, p, nil
}

// refuseIfRunning is the liveness gate.
func refuseIfRunning(ctx context.Context, s *store.Store, addresses []string) error {
	if err := refuseIfClaimed(ctx, s.Pool(), ""); err != nil {
		return err
	}
	for _, addr := range addresses {
		if addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("%w: %s is already bound", ErrListenersRunning, addr)
		}
		if cerr := ln.Close(); cerr != nil {
			return fmt.Errorf("revision: release the probe listener on %s: %w", addr, cerr)
		}
	}
	return nil
}

// refuseIfClaimed reports a live audit-writer claim, which means a stamp
// process is running against this database.
//
// The advisory lock is the evidence rather than the audit_writers row: a row
// says a process once claimed the writer, and the lock says a process is holding
// it now. A crashed instance releases the lock when Postgres reaps its
// connection, which is the property that makes this usable after an outage.
func refuseIfClaimed(ctx context.Context, q store.Querier, ignoreWriterID string) error {
	rows, err := q.Query(ctx, `
		SELECT aw.writer_id, aw.instance
		FROM audit_writers aw
		WHERE aw.released_at IS NULL
		  AND aw.writer_id <> $1
		  AND EXISTS (
		      SELECT 1 FROM pg_locks l
		      WHERE l.locktype = 'advisory'
		        AND l.granted
		        AND l.objsubid = 1
		        AND l.classid = ((aw.lock_key >> 32) & 4294967295)::oid
		        AND l.objid   = (aw.lock_key & 4294967295)::oid
		  )`, ignoreWriterID)
	if err != nil {
		return fmt.Errorf("revision: check for live instances: %w", err)
	}
	defer rows.Close()
	var live []string
	for rows.Next() {
		var writerID, instance string
		if err := rows.Scan(&writerID, &instance); err != nil {
			return fmt.Errorf("revision: read a live instance: %w", err)
		}
		live = append(live, writerID+"@"+instance)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("revision: check for live instances: %w", err)
	}
	if len(live) > 0 {
		return fmt.Errorf("%w: %v still hold audit writer claims", ErrListenersRunning, live)
	}
	return nil
}
