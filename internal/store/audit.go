package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrChainConflict reports that an append collided with an existing row in the
// writer's own segment. It means either that the in-process head drifted from
// the database or that a second process is writing this segment.
//
// The collision itself cannot tell those apart, so it always stops the writer.
// What separates them is evidence gathered afterwards — the advisory claim, and
// whether the rows ahead of the head re-chain from it — which is what
// reconcileLocked goes and gets before the writer is allowed to continue.
var ErrChainConflict = errors.New("store: audit chain sequence conflict")

// ErrUnreconciled reports that a conflicted writer could not prove the rows it
// found ahead of its own head are rows it wrote itself. The writer stays
// stopped: a stopped writer is recoverable by an operator, and a chain that
// adopted somebody else's rows is not.
var ErrUnreconciled = errors.New("store: audit chain head cannot be reconciled")

// maxReconcilableDrift bounds how many rows an automatic reconciliation will
// re-chain inline.
//
// The bound is about the work, not the trust: reconciliation runs under the
// writer's append lock, so every audited write in the process waits behind it,
// and the drift it exists to repair is a single unobserved transaction. A
// segment that has run far ahead of what this process believes is not that
// case, and an operator reading the log is a better tool for it than a stalled
// append path.
const maxReconcilableDrift = 1024

// The audit record kinds this package writes or expects. The set is open —
// later units add their own — but the names are stable, because verification
// tooling and the audit console index on them.
const (
	AuditKindSchemaPut         = "policy.schema.put"
	AuditKindPolicyPut         = "policy.put"
	AuditKindPolicyDelete      = "policy.delete"
	AuditKindDecisionCreated   = "decision.created"
	AuditKindDecisionResolved  = "decision.resolved"
	AuditKindChallengeProgress = "challenge.progress"
	AuditKindApproval          = "approval.recorded"

	// AuditKindCheckBatch is one Merkle root over a batch of check-path
	// evaluations. The check path writes one of these per batch rather than one
	// row per request, which is what decouples audit append frequency from
	// request rate.
	AuditKindCheckBatch = "check.batch"

	// AuditKindCheckGap marks a window of check-path audit records that were
	// lost. Recording the loss as a chain entry is what makes the hole visible
	// at verification time instead of invisible.
	AuditKindCheckGap = "check.gap"

	// AuditKindEventRejected marks one ingestion record that can never be
	// accepted and was therefore dropped rather than retried forever.
	//
	// The drop exists because a consumer stalled on one poison record stops
	// updating every velocity aggregate in the deployment, which is a cheaper
	// way to disable a limit than any of the ones the threat model lists. That
	// makes the drop itself a security-relevant event, so it belongs in the
	// chain rather than only in a log an operator may not be keeping.
	AuditKindEventRejected = "ingest.event.rejected"

	// AuditKindAuditRefused marks an audit console read that was refused for
	// want of auditor standing (R22).
	//
	// The refusal is chained rather than logged because the audit console is
	// the one surface whose reader is trying to see everything: an attempt to
	// read the whole decision history is exactly the event an auditor of the
	// auditors needs, and a surface that recorded only successful reads would
	// leave probing invisible.
	AuditKindAuditRefused = "audit.console.refused"

	// AuditKindWriterReconciled marks the one change a writer is allowed to
	// make to its own head without an operator: adopting rows it committed but
	// never observed committing.
	//
	// It is a chain entry rather than a log line because the rows it adopts
	// were reported to their callers as failures. Without this marker an
	// auditor would read a run of records the system says never happened and
	// have nothing to tell them why — which is the same class of lie the chain
	// exists to prevent. The marker names both heads and the span adopted, so
	// the ambiguous window is bounded rather than merely admitted.
	AuditKindWriterReconciled = "audit.writer.reconciled"
)

// hashDomain separates this hash construction from any other in the system, so
// a preimage from elsewhere can never be replayed as an audit row hash.
const hashDomain = "stamp.audit.v1"

// zeroHash is the prev_hash of the first row in a segment.
var zeroHash [32]byte

// writerIDPattern is the syntax an audit writer identifier must match. It ends
// up in a primary key and in checkpoint documents that are compared across
// systems, so it is held to a plain, quoting-free syntax.
var writerIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// AuditEntry is one record to append. Payload is marshalled to canonical JSON
// before it is hashed and stored.
type AuditEntry struct {
	Kind    string
	Subject string
	Payload any
}

// AuditRecord is an appended row as it landed.
type AuditRecord struct {
	WriterID   string
	Seq        int64
	PrevHash   [32]byte
	Hash       [32]byte
	Kind       string
	Subject    string
	Payload    json.RawMessage
	RecordedAt time.Time
}

// AuditWriter owns one segment of the audit chain.
//
// Ownership is exclusive and is taken at startup by ClaimWriter. Appends are
// serialized within the process because a hash chain is inherently sequential:
// each row's prev_hash is the previous row's hash, so two concurrent appends to
// one segment would either collide on the primary key or fork the chain. That
// serialization is per writer, which is exactly the point of splitting the
// chain — instances do not contend with each other, only with themselves.
//
// The lock is held across the whole audited transaction, not just the insert.
// Releasing it earlier would let a rolled-back transaction consume a sequence
// number and leave a permanent gap, and a gap is indistinguishable from a
// deletion at verification time. The decide path this serializes is low volume
// by design, and the check path writes one batched Merkle root per batch rather
// than one row per request.
type AuditWriter struct {
	store    *Store
	id       string
	lockKey  int64
	conn     *pgxpool.Conn
	mu       sync.Mutex
	headSeq  int64
	headHash [32]byte
	broken   bool
	closed   bool
}

// ClaimWriter takes exclusive ownership of an audit writer identifier.
//
// The claim is a session-scoped advisory lock on a dedicated connection. A
// process that dies releases it as soon as Postgres reaps the connection, which
// a lease row in a table cannot do without a heartbeat and a timeout that is
// always either too eager or too slow.
//
// The claim holds one pooled connection for as long as the writer lives, since
// a session advisory lock dies with its session. A process runs one writer, so
// that is one connection; a test or tool that claims several must size the pool
// for them plus the connections its own queries need.
//
// A collision returns ErrWriterTaken and is not retried, here or by callers.
// U0 measured what a retry would buy: two processes on one writer_id fail on
// the (writer_id, seq) primary key, which is a correctness failure rather than
// contention, and a boot that retries past it either spins forever or starts a
// process whose audit appends fail one at a time under load. Failing the boot
// puts the misconfiguration in front of the operator at the only moment it is
// cheap to fix.
func (s *Store) ClaimWriter(ctx context.Context, writerID, instance string) (*AuditWriter, error) {
	if !writerIDPattern.MatchString(writerID) {
		return nil, fmt.Errorf("store: audit writer id %q must be 1-64 chars of [A-Za-z0-9._-] starting alphanumeric", writerID)
	}

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: acquire writer connection: %w", err)
	}
	release := func() { conn.Release() }

	lockKey := advisoryKey("stamp:audit-writer:" + writerID)
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&got); err != nil {
		release()
		return nil, fmt.Errorf("store: claim writer %q: %w", writerID, err)
	}
	if !got {
		release()
		return nil, fmt.Errorf("store: writer %q is held by another live process: %w", writerID, ErrWriterTaken)
	}

	const claim = `
		INSERT INTO audit_writers (writer_id, lock_key, instance, claimed_at, released_at)
		VALUES ($1, $2, $3, now(), NULL)
		ON CONFLICT (writer_id) DO UPDATE
		SET instance = EXCLUDED.instance, claimed_at = now(), released_at = NULL`
	if _, err := conn.Exec(ctx, claim, writerID, lockKey, instance); err != nil {
		_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, lockKey)
		release()
		return nil, fmt.Errorf("store: record writer claim %q: %w", writerID, err)
	}

	w := &AuditWriter{store: s, id: writerID, lockKey: lockKey, conn: conn}
	if err := w.reloadHeadLocked(ctx, conn); err != nil {
		_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, lockKey)
		release()
		return nil, err
	}
	return w, nil
}

// ID reports the writer identifier this writer owns.
func (w *AuditWriter) ID() string { return w.id }

// Head reports the sequence number and hash of the last row this writer
// appended.
func (w *AuditWriter) Head() (seq int64, hash [32]byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.headSeq, w.headHash
}

// Close releases the claim. After Close the identifier may be claimed again,
// by this process or another.
func (w *AuditWriter) Close(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	defer w.conn.Release()

	var firstErr error
	if _, err := w.conn.Exec(ctx,
		`UPDATE audit_writers SET released_at = now() WHERE writer_id = $1`, w.id); err != nil {
		firstErr = fmt.Errorf("store: release writer %q: %w", w.id, err)
	}
	if _, err := w.conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, w.lockKey); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("store: unlock writer %q: %w", w.id, err)
	}
	return firstErr
}

// VerifyHold reports whether this process still holds the advisory lock on its
// writer identifier. A lost hold does not corrupt anything by itself — the
// primary key still stops a second writer from forking the segment — but it
// means the next append may fail, and an operator would rather know first.
func (w *AuditWriter) VerifyHold(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.verifyHoldLocked(ctx)
}

func (w *AuditWriter) verifyHoldLocked(ctx context.Context) error {
	if w.closed {
		return fmt.Errorf("store: writer %q is closed", w.id)
	}
	var held bool
	// A single-argument advisory lock is recorded with the key split across
	// classid (high 32 bits) and objid (low 32 bits), so the comparison has to
	// be made in the same decomposition rather than on the key as a whole.
	err := w.conn.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_locks
			WHERE locktype = 'advisory'
			  AND granted
			  AND pid = pg_backend_pid()
			  AND objsubid = 1
			  AND classid = (($1::bigint >> 32) & 4294967295)::oid
			  AND objid   = ($1::bigint & 4294967295)::oid
		)`, w.lockKey).Scan(&held)
	if err != nil {
		return fmt.Errorf("store: check writer hold %q: %w", w.id, err)
	}
	if !held {
		return fmt.Errorf("store: writer %q no longer holds its claim: %w", w.id, ErrWriterTaken)
	}
	return nil
}

// ReloadHead re-reads the segment head from the database and clears a broken
// writer. It exists for the one case where the in-process head can legitimately
// drift: a commit whose outcome was never observed. Calling it discards
// whatever the process believed and adopts what the database holds.
//
// It checks nothing. That is deliberate and is why it is not the automatic
// recovery path: adopting whatever the database holds is the right move for an
// operator who has already established what happened, and the wrong move for an
// append that has just collided, because the collision cannot tell a commit
// this process lost sight of from a second writer forking the segment. The
// append path goes through reconcileLocked, which shares this method's head
// read and refuses the cases this one would accept.
func (w *AuditWriter) ReloadHead(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.reloadHeadLocked(ctx, w.store.pool); err != nil {
		return err
	}
	w.broken = false
	return nil
}

func (w *AuditWriter) reloadHeadLocked(ctx context.Context, q Querier) error {
	var seq int64
	var hash []byte
	err := q.QueryRow(ctx,
		`SELECT seq, hash FROM audit_log WHERE writer_id = $1 ORDER BY seq DESC LIMIT 1`,
		w.id).Scan(&seq, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		w.headSeq = 0
		w.headHash = zeroHash
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: read head of writer %q: %w", w.id, err)
	}
	if len(hash) != len(zeroHash) {
		return fmt.Errorf("store: head of writer %q has a %d-byte hash: %w", w.id, len(hash), ErrChainBroken)
	}
	w.headSeq = seq
	copy(w.headHash[:], hash)
	return nil
}

// reconcileLocked tries to bring a conflicted writer back into agreement with
// the database, and reports why it would not when it does not.
//
// The conflict it repairs has exactly one benign cause: a transaction that
// committed on the server while this process was losing the connection or its
// context, so the rows landed and the head never advanced. Every other cause —
// a second process on this writer id, a hand-written row, a rewritten segment —
// produces the same primary-key violation, so reconciliation is only allowed
// once the benign cause has been positively established rather than assumed:
//
//   - The advisory claim must still be held. While it is, no other live process
//     can be appending to this segment, which is what separates the drift this
//     repairs from the fork it must not paper over.
//   - Every row ahead of the believed head must re-chain from that believed
//     head and hash to its own contents. Rows this process wrote do; rows
//     invented by anything else do not, unless they were built with the head
//     this process was holding — which is the same thing as having been written
//     through this writer.
//   - The reconciliation must itself be appended to the chain before the writer
//     is declared healthy. A repair that could not be recorded does not happen.
//
// Anything else leaves the writer stopped. A stopped writer is an outage an
// operator can see and unwind; a chain that quietly absorbed somebody else's
// rows is a document that has stopped meaning anything.
//
// Nothing here rewrites or skips a row: the adopted rows are already committed
// and already linked, and the marker extends the chain from them. Nothing here
// re-runs the transaction that collided either — that decision belongs to the
// caller, and only [AuditWriter.Append], whose transaction holds nothing but
// its own rows, is allowed to make it.
func (w *AuditWriter) reconcileLocked(ctx context.Context) error {
	believedSeq, believedHash := w.headSeq, w.headHash

	if err := w.verifyHoldLocked(ctx); err != nil {
		return fmt.Errorf("store: %w: the claim on writer %q could not be confirmed: %w",
			ErrUnreconciled, w.id, err)
	}

	tail, err := w.readTail(ctx, believedSeq)
	if err != nil {
		return err
	}
	if len(tail) == 0 {
		// Nothing landed past what the writer already knew, so the collision
		// was not a lost commit. Something removed a row, or the segment is
		// being written from outside this process.
		return fmt.Errorf("store: %w: writer %q collided at seq %d but the log holds nothing past it",
			ErrUnreconciled, w.id, believedSeq+1)
	}
	if len(tail) > maxReconcilableDrift {
		return fmt.Errorf("store: %w: writer %q is %d rows behind the log, more than one lost transaction can explain",
			ErrUnreconciled, w.id, len(tail))
	}

	prev, expected := believedHash, believedSeq+1
	for _, rec := range tail {
		if rec.Seq != expected {
			return fmt.Errorf("store: %w: writer %q found seq %d where %d should be",
				ErrUnreconciled, w.id, rec.Seq, expected)
		}
		if rec.PrevHash != prev {
			return fmt.Errorf("store: %w: writer %q found a row at seq %d linking to %x, not to %x",
				ErrUnreconciled, w.id, rec.Seq, rec.PrevHash, prev)
		}
		if got := recordHash(rec); got != rec.Hash {
			return fmt.Errorf("store: %w: writer %q found a row at seq %d whose stored hash %x is not the hash of its contents %x",
				ErrUnreconciled, w.id, rec.Seq, rec.Hash, got)
		}
		prev, expected = rec.Hash, rec.Seq+1
	}

	adopted := tail[len(tail)-1]
	w.headSeq, w.headHash = adopted.Seq, adopted.Hash
	err = w.inTxLocked(ctx, func(ctx context.Context, _ pgx.Tx, ap *Appender) error {
		_, aerr := ap.Append(ctx, AuditEntry{
			Kind:    AuditKindWriterReconciled,
			Subject: w.id,
			Payload: map[string]any{
				"believed_seq":  believedSeq,
				"believed_hash": fmt.Sprintf("%x", believedHash),
				"adopted_seq":   adopted.Seq,
				"adopted_hash":  fmt.Sprintf("%x", adopted.Hash),
				"adopted_rows":  len(tail),
				"reason":        "rows committed without the commit being observed",
			},
		})
		return aerr
	})
	if err != nil {
		// The head goes back to what the writer believed so that a later
		// attempt repeats the whole check rather than starting from a head it
		// never got to record adopting.
		w.headSeq, w.headHash = believedSeq, believedHash
		return fmt.Errorf("store: writer %q could not record its reconciliation: %w", w.id, err)
	}

	w.broken = false
	return nil
}

// readTail reads the rows of this segment past seq, in order, whole enough to
// re-chain and re-hash.
func (w *AuditWriter) readTail(ctx context.Context, seq int64) ([]AuditRecord, error) {
	rows, err := w.store.pool.Query(ctx, `
		SELECT seq, prev_hash, hash, kind, subject, payload::text, recorded_at
		FROM audit_log
		WHERE writer_id = $1 AND seq > $2
		ORDER BY seq
		LIMIT $3`, w.id, seq, maxReconcilableDrift+1)
	if err != nil {
		return nil, fmt.Errorf("store: read tail of writer %q: %w", w.id, err)
	}
	defer rows.Close()

	var out []AuditRecord
	for rows.Next() {
		var (
			rec      AuditRecord
			prevHash []byte
			hash     []byte
			payload  string
		)
		if err := rows.Scan(&rec.Seq, &prevHash, &hash, &rec.Kind, &rec.Subject, &payload, &rec.RecordedAt); err != nil {
			return nil, fmt.Errorf("store: scan tail of writer %q: %w", w.id, err)
		}
		if len(prevHash) != len(zeroHash) || len(hash) != len(zeroHash) {
			return nil, fmt.Errorf("store: %w: writer %q has a malformed hash at seq %d",
				ErrUnreconciled, w.id, rec.Seq)
		}
		canonical, cerr := canonicalJSONBytes([]byte(payload))
		if cerr != nil {
			return nil, fmt.Errorf("store: %w: writer %q has an unreadable payload at seq %d: %w",
				ErrUnreconciled, w.id, rec.Seq, cerr)
		}
		rec.WriterID = w.id
		rec.Payload = canonical
		copy(rec.PrevHash[:], prevHash)
		copy(rec.Hash[:], hash)
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read tail of writer %q: %w", w.id, err)
	}
	return out, nil
}

// Appender appends rows to a segment inside an already-open transaction. It is
// only reachable from InTx, which is what guarantees the writer's lock is held
// and that the head advances only if the transaction commits.
type Appender struct {
	writer *AuditWriter
	tx     pgx.Tx
	seq    int64
	prev   [32]byte
	staged []AuditRecord
}

// Append writes entries into the transaction, extending the chain.
func (a *Appender) Append(ctx context.Context, entries ...AuditEntry) ([]AuditRecord, error) {
	out := make([]AuditRecord, 0, len(entries))
	for _, e := range entries {
		payload, err := canonicalJSON(e.Payload)
		if err != nil {
			return nil, fmt.Errorf("store: canonicalize audit payload for %q: %w", e.Kind, err)
		}
		if e.Kind == "" {
			return nil, errors.New("store: audit entry kind is empty")
		}
		rec := AuditRecord{
			WriterID: a.writer.id,
			Seq:      a.seq + 1,
			PrevHash: a.prev,
			Kind:     e.Kind,
			Subject:  e.Subject,
			Payload:  payload,
			// Postgres timestamptz resolves to microseconds. Truncating before
			// hashing means the value that is hashed is the value that comes
			// back out, which is what lets verification recompute the hash.
			RecordedAt: a.writer.store.Now().Truncate(time.Microsecond),
		}
		rec.Hash = recordHash(rec)

		const insert = `
			INSERT INTO audit_log (writer_id, seq, prev_hash, hash, kind, subject, payload, recorded_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
		_, err = a.tx.Exec(ctx, insert,
			rec.WriterID, rec.Seq, rec.PrevHash[:], rec.Hash[:],
			rec.Kind, rec.Subject, []byte(rec.Payload), rec.RecordedAt)
		if err != nil {
			if isUniqueViolation(err) {
				a.writer.broken = true
				return nil, fmt.Errorf("store: append to segment %q at seq %d: %w",
					rec.WriterID, rec.Seq, ErrChainConflict)
			}
			return nil, fmt.Errorf("store: append audit row: %w", err)
		}

		a.seq = rec.Seq
		a.prev = rec.Hash
		a.staged = append(a.staged, rec)
		out = append(out, rec)
	}
	return out, nil
}

// InTx runs fn in a transaction with the writer's append lock held, and
// advances the segment head only after the transaction commits.
//
// This is the seam every audited write goes through. A caller that needs a
// state transition and its audit row in one transaction — which decide and
// governance both do — writes both inside fn.
func (w *AuditWriter) InTx(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx, ap *Appender) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return fmt.Errorf("store: writer %q is closed", w.id)
	}
	if w.broken {
		// A conflicted writer used to stay conflicted for the life of the
		// process, because the method that clears the state had no caller. It
		// gets one attempt to reconcile here — at the start of the next write,
		// with that write's context, rather than on the failing call's way out
		// with the context that had just been cancelled.
		if err := w.reconcileLocked(ctx); err != nil {
			return fmt.Errorf("store: writer %q is stopped after a conflict: %w: %w", w.id, ErrChainConflict, err)
		}
	}

	return w.inTxLocked(ctx, fn)
}

func (w *AuditWriter) inTxLocked(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx, ap *Appender) error) error {
	ap := &Appender{writer: w, seq: w.headSeq, prev: w.headHash}
	err := w.store.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		ap.tx = tx
		return fn(ctx, tx, ap)
	})
	if err != nil {
		return err
	}
	if n := len(ap.staged); n > 0 {
		last := ap.staged[n-1]
		w.headSeq = last.Seq
		w.headHash = last.Hash
	}
	return nil
}

// Append writes entries in a transaction of their own. Use InTx when the audit
// row has to land with something else.
//
// A sequence conflict is retried exactly once. The first append after a commit
// this process lost sight of is the one that discovers the drift, and without
// the retry that append is lost even though the writer is healthy again by the
// time the next one arrives — which, on the flush that runs at shutdown, is a
// record that never gets written at all.
//
// The retry lives here and not in InTx because it is only safe here: this
// transaction contains nothing but these rows and it rolled back whole, so
// running it again writes what it was always going to write. An InTx closure
// belongs to a caller who never agreed to be run twice.
func (w *AuditWriter) Append(ctx context.Context, entries ...AuditEntry) ([]AuditRecord, error) {
	out, err := w.appendOnce(ctx, entries...)
	if errors.Is(err, ErrChainConflict) {
		out, err = w.appendOnce(ctx, entries...)
	}
	return out, err
}

func (w *AuditWriter) appendOnce(ctx context.Context, entries ...AuditEntry) ([]AuditRecord, error) {
	var out []AuditRecord
	err := w.InTx(ctx, func(ctx context.Context, _ pgx.Tx, ap *Appender) error {
		recs, err := ap.Append(ctx, entries...)
		out = recs
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CheckBatch is one batch of check-path evaluations, summarized as a Merkle
// root over the per-request digests.
//
// One row per batch rather than one per request is deliberate: the check path
// is the high-volume path and its audit volume must be a function of batching
// policy, not of traffic.
type CheckBatch struct {
	From   time.Time
	To     time.Time
	Count  int
	Root   [32]byte
	Digest string // optional label for the digest scheme, for later readers
}

// AppendCheckBatch appends one batched Merkle root row.
func (w *AuditWriter) AppendCheckBatch(ctx context.Context, b CheckBatch) (AuditRecord, error) {
	recs, err := w.Append(ctx, AuditEntry{
		Kind: AuditKindCheckBatch,
		Payload: map[string]any{
			"from":   b.From.UTC().Format(time.RFC3339Nano),
			"to":     b.To.UTC().Format(time.RFC3339Nano),
			"count":  b.Count,
			"root":   fmt.Sprintf("%x", b.Root),
			"digest": b.Digest,
		},
	})
	if err != nil {
		return AuditRecord{}, err
	}
	return recs[0], nil
}

// CheckGap records a window of check-path audit records that were lost, so the
// hole is visible in the chain rather than invisible.
type CheckGap struct {
	From    time.Time
	To      time.Time
	Dropped int64
	Reason  string
}

// AppendCheckGap appends a loss marker.
func (w *AuditWriter) AppendCheckGap(ctx context.Context, g CheckGap) (AuditRecord, error) {
	recs, err := w.Append(ctx, AuditEntry{
		Kind: AuditKindCheckGap,
		Payload: map[string]any{
			"from":    g.From.UTC().Format(time.RFC3339Nano),
			"to":      g.To.UTC().Format(time.RFC3339Nano),
			"dropped": g.Dropped,
			"reason":  g.Reason,
		},
	})
	if err != nil {
		return AuditRecord{}, err
	}
	return recs[0], nil
}

// MerkleRoot computes the root over a list of leaf payloads. An empty list
// hashes to the zero-length root so that "no requests in this window" is still
// a well-defined batch.
//
// Leaves and internal nodes are domain-separated with distinct prefixes, which
// is what stops a second-preimage attack that passes an internal node off as a
// leaf.
func MerkleRoot(leaves [][]byte) [32]byte {
	if len(leaves) == 0 {
		return sha256.Sum256([]byte(hashDomain + ":merkle:empty"))
	}
	level := make([][32]byte, len(leaves))
	for i, leaf := range leaves {
		level[i] = sha256.Sum256(append([]byte(hashDomain+":merkle:leaf\x00"), leaf...))
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			// An odd node is promoted rather than duplicated. Duplicating it
			// makes two different leaf lists produce the same root.
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			var buf bytes.Buffer
			buf.WriteString(hashDomain + ":merkle:node\x00")
			buf.Write(level[i][:])
			buf.Write(level[i+1][:])
			next = append(next, sha256.Sum256(buf.Bytes()))
		}
		level = next
	}
	return level[0]
}

// ---------------------------------------------------------------------------
// hashing
// ---------------------------------------------------------------------------

// recordHash is the chain hash of one row.
//
// Every variable-length field is length-prefixed. Concatenating them raw would
// let two different records share a preimage — a kind of "ab" with subject "c"
// and a kind of "a" with subject "bc" — which is precisely the freedom an
// attacker rewriting the log would want.
func recordHash(r AuditRecord) [32]byte {
	h := sha256.New()
	writeTagged(h, []byte(hashDomain))
	writeTagged(h, []byte(r.WriterID))
	writeInt64(h, r.Seq)
	h.Write(r.PrevHash[:])
	writeTagged(h, []byte(r.Kind))
	writeTagged(h, []byte(r.Subject))
	writeTagged(h, r.Payload)
	writeInt64(h, r.RecordedAt.UTC().UnixMicro())
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeTagged(w io.Writer, b []byte) {
	writeUint64(w, uint64(len(b)))
	_, _ = w.Write(b)
}

func writeUint64(w io.Writer, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	_, _ = w.Write(buf[:])
}

// writeInt64 encodes a signed value as its full 64-bit pattern. Sequence
// numbers and microsecond timestamps are non-negative in practice, but the hash
// must cover every bit either way rather than reject a value it did not expect.
func writeInt64(w io.Writer, v int64) {
	writeUint64(w, uint64(v)) //nolint:gosec // the hash covers the bit pattern, not a numeric range
}

// canonicalJSON renders a payload in a form that survives a jsonb round trip.
//
// The payload column is jsonb, which normalizes on the way in — key order,
// whitespace and number formatting are all Postgres's to choose. Hashing the
// bytes handed to the driver would therefore produce a hash that verification
// could never recompute from what it reads back. Marshalling through Go's
// generic decoder instead gives a form that is a fixed point of that round
// trip: sorted keys, no insignificant whitespace, and numbers already reduced
// to the float64 shape Postgres's numeric output re-parses to.
func canonicalJSON(v any) (json.RawMessage, error) {
	if v == nil {
		return json.RawMessage("{}"), nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canonicalJSONBytes(raw)
}

func canonicalJSONBytes(raw []byte) (json.RawMessage, error) {
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	out, err := json.Marshal(generic)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// ---------------------------------------------------------------------------
// verification
// ---------------------------------------------------------------------------

// FaultKind names a class of audit-chain defect.
type FaultKind string

// The defects verification can report.
const (
	// FaultHashMismatch means a row's stored hash is not the hash of its own
	// contents: the row was modified in place.
	FaultHashMismatch FaultKind = "hash_mismatch"

	// FaultPrevMismatch means a row does not link to the row before it: a row
	// was removed, replaced, or inserted.
	FaultPrevMismatch FaultKind = "prev_mismatch"

	// FaultSequenceGap means a sequence number is missing from a segment.
	FaultSequenceGap FaultKind = "sequence_gap"

	// FaultCheckpointGap means the checkpoint series skips a sequence number,
	// or the sink and the database disagree about which checkpoints exist.
	FaultCheckpointGap FaultKind = "checkpoint_gap"

	// FaultCheckpointSignature means a checkpoint's signature does not verify
	// under the configured key.
	FaultCheckpointSignature FaultKind = "checkpoint_signature"

	// FaultCheckpointChain means a checkpoint does not link to its predecessor.
	FaultCheckpointChain FaultKind = "checkpoint_chain"

	// FaultHeadMismatch means a writer's head at checkpoint time does not match
	// what the log now says it was. This is the fault a wholesale re-chaining
	// of the log produces: the internal links are all consistent again, but the
	// signed head from before the rewrite no longer matches.
	FaultHeadMismatch FaultKind = "head_mismatch"

	// FaultMissingRow means a checkpoint names a row the log no longer has.
	FaultMissingRow FaultKind = "missing_row"
)

// Fault is one defect found by verification.
type Fault struct {
	Kind     FaultKind
	WriterID string
	Seq      int64
	Detail   string
}

func (f Fault) String() string {
	if f.WriterID == "" {
		return fmt.Sprintf("%s at seq %d: %s", f.Kind, f.Seq, f.Detail)
	}
	return fmt.Sprintf("%s at %s/%d: %s", f.Kind, f.WriterID, f.Seq, f.Detail)
}

// SegmentSummary is one writer's segment as verification found it.
type SegmentSummary struct {
	WriterID string
	Rows     int64
	HeadSeq  int64
	HeadHash [32]byte
}

// ChainReport is the result of re-chaining the audit log.
type ChainReport struct {
	Rows     int64
	Segments []SegmentSummary
	Faults   []Fault
}

// OK reports whether verification found nothing.
func (r *ChainReport) OK() bool { return len(r.Faults) == 0 }

// Err returns ErrChainBroken with the fault list attached, or nil.
func (r *ChainReport) Err() error {
	if r.OK() {
		return nil
	}
	parts := make([]string, 0, len(r.Faults))
	for _, f := range r.Faults {
		parts = append(parts, f.String())
	}
	return fmt.Errorf("%w: %d fault(s): %v", ErrChainBroken, len(r.Faults), parts)
}

// VerifyChain re-chains every segment of the audit log and reports what does
// not add up.
//
// This catches modification and deletion, because both break either a row's own
// hash or its link to the row before it. It does not on its own catch a
// wholesale rewrite — an attacker with write access can recompute every hash —
// which is what the signed checkpoints are for. VerifyCheckpoints is the other
// half.
func (s *Store) VerifyChain(ctx context.Context) (*ChainReport, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT writer_id, seq, prev_hash, hash, kind, subject, payload::text, recorded_at
		FROM audit_log
		ORDER BY writer_id, seq`)
	if err != nil {
		return nil, fmt.Errorf("store: read audit log: %w", err)
	}
	defer rows.Close()

	report := &ChainReport{}
	var (
		current  string
		expected int64
		prev     [32]byte
		count    int64
		lastHash [32]byte
		lastSeq  int64
	)
	flush := func() {
		if current == "" {
			return
		}
		report.Segments = append(report.Segments, SegmentSummary{
			WriterID: current, Rows: count, HeadSeq: lastSeq, HeadHash: lastHash,
		})
	}

	for rows.Next() {
		var (
			writerID   string
			seq        int64
			prevHash   []byte
			hash       []byte
			kind       string
			subject    string
			payload    string
			recordedAt time.Time
		)
		if err := rows.Scan(&writerID, &seq, &prevHash, &hash, &kind, &subject, &payload, &recordedAt); err != nil {
			return nil, fmt.Errorf("store: scan audit row: %w", err)
		}
		if writerID != current {
			flush()
			current, expected, prev, count = writerID, 1, zeroHash, 0
		}
		report.Rows++
		count++

		if seq != expected {
			report.Faults = append(report.Faults, Fault{
				Kind: FaultSequenceGap, WriterID: writerID, Seq: seq,
				Detail: fmt.Sprintf("expected seq %d", expected),
			})
		}
		if !bytes.Equal(prevHash, prev[:]) {
			report.Faults = append(report.Faults, Fault{
				Kind: FaultPrevMismatch, WriterID: writerID, Seq: seq,
				Detail: fmt.Sprintf("stored prev_hash %x, chain says %x", prevHash, prev),
			})
		}

		canonical, cerr := canonicalJSONBytes([]byte(payload))
		if cerr != nil {
			report.Faults = append(report.Faults, Fault{
				Kind: FaultHashMismatch, WriterID: writerID, Seq: seq,
				Detail: fmt.Sprintf("payload is not valid JSON: %v", cerr),
			})
			canonical = json.RawMessage(payload)
		}
		var storedPrev [32]byte
		copy(storedPrev[:], prevHash)
		want := recordHash(AuditRecord{
			WriterID: writerID, Seq: seq, PrevHash: storedPrev,
			Kind: kind, Subject: subject, Payload: canonical, RecordedAt: recordedAt,
		})
		if !bytes.Equal(hash, want[:]) {
			report.Faults = append(report.Faults, Fault{
				Kind: FaultHashMismatch, WriterID: writerID, Seq: seq,
				Detail: fmt.Sprintf("stored hash %x, recomputed %x", hash, want),
			})
		}

		copy(prev[:], hash)
		copy(lastHash[:], hash)
		lastSeq = seq
		expected = seq + 1
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read audit log: %w", err)
	}
	flush()
	sort.Slice(report.Segments, func(i, j int) bool {
		return report.Segments[i].WriterID < report.Segments[j].WriterID
	})
	return report, nil
}

// Heads reads the current head of every segment.
func (s *Store) Heads(ctx context.Context) ([]WriterHead, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (writer_id) writer_id, seq, hash
		FROM audit_log
		ORDER BY writer_id, seq DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: read segment heads: %w", err)
	}
	defer rows.Close()

	var heads []WriterHead
	for rows.Next() {
		var h WriterHead
		var hash []byte
		if err := rows.Scan(&h.WriterID, &h.Seq, &hash); err != nil {
			return nil, fmt.Errorf("store: scan segment head: %w", err)
		}
		copy(h.Hash[:], hash)
		heads = append(heads, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read segment heads: %w", err)
	}
	sort.Slice(heads, func(i, j int) bool { return heads[i].WriterID < heads[j].WriterID })
	return heads, nil
}
