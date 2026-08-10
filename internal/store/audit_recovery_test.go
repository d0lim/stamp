package store_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/d0lim/stamp/internal/store"
)

// The failure these tests are about is the one an audit writer cannot see
// through: a transaction that commits on the server while the client never
// learns that it did. The writer's head stays where it was, the next append
// picks a sequence number the log already holds, and the primary key stops it.
// Before this file existed that was the end of the writer — the state was only
// clearable by a method with no caller.
//
// Reproducing it needs the commit to actually land and the client to actually
// miss it, so these tests put a proxy on the wire rather than a hook in the
// store: nothing in the production path knows it is being tested, and what is
// exercised is the real pgx commit path against a real Postgres.

// ---------------------------------------------------------------------------
// the wire
// ---------------------------------------------------------------------------

// commitBreaker proxies the Postgres protocol and can lose exactly one commit.
//
// When armed, it forwards the next COMMIT to the server, reads the server's
// reply through to the ReadyForQuery that ends it — so the commit is known to
// have been applied — and then drops the connection without any of that reply
// reaching the client. That is precisely what a cancelled context or a reset
// connection does to a commit in flight, minus the timing.
type commitBreaker struct {
	ln     net.Listener
	target string
	armed  atomic.Bool
	broke  atomic.Bool
}

func newCommitBreaker(t *testing.T, dsn string) *commitBreaker {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := &commitBreaker{ln: ln, target: u.Host}
	t.Cleanup(func() { _ = ln.Close() })
	go b.accept()
	return b
}

// dsn rewrites a connection string to point at the proxy.
func (b *commitBreaker) dsn(t *testing.T, original string) string {
	t.Helper()
	u, err := url.Parse(original)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Host = b.ln.Addr().String()
	return u.String()
}

func (b *commitBreaker) accept() {
	for {
		client, err := b.ln.Accept()
		if err != nil {
			return
		}
		go b.handle(client)
	}
}

func (b *commitBreaker) handle(client net.Conn) {
	server, err := net.Dial("tcp", b.target)
	if err != nil {
		_ = client.Close()
		return
	}
	closeBoth := func() {
		_ = client.Close()
		_ = server.Close()
	}
	defer closeBoth()

	// Set once the COMMIT has been forwarded, which is always before its reply
	// can come back, because the request is written before it is answered.
	var losing atomic.Bool
	done := make(chan struct{}, 2)

	// client -> server
	go func() {
		defer func() { done <- struct{}{} }()
		r := bufio.NewReader(client)
		// The startup packet carries no type byte; everything after it does.
		if err := relayUntyped(r, server); err != nil {
			return
		}
		for {
			kind, body, err := readTyped(r)
			if err != nil {
				return
			}
			if kind == 'Q' && strings.EqualFold(strings.TrimRight(string(body), "\x00"), "commit") &&
				b.armed.CompareAndSwap(true, false) {
				losing.Store(true)
				b.broke.Store(true)
			}
			if err := writeTyped(server, kind, body); err != nil {
				return
			}
		}
	}()

	// server -> client
	go func() {
		defer func() { done <- struct{}{} }()
		r := bufio.NewReader(server)
		for {
			kind, body, err := readTyped(r)
			if err != nil {
				return
			}
			if losing.Load() {
				// Swallow the commit's reply. Once the server says it is ready
				// again the commit has been applied, and the client has been
				// told none of it.
				if kind == 'Z' {
					closeBoth()
					return
				}
				continue
			}
			if err := writeTyped(client, kind, body); err != nil {
				return
			}
		}
	}()

	<-done
}

// relayUntyped forwards one length-prefixed message that carries no type byte.
func relayUntyped(r *bufio.Reader, w io.Writer) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 4 || n > 1<<20 {
		return fmt.Errorf("startup message of %d bytes", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func readTyped(r *bufio.Reader) (byte, []byte, error) {
	kind, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 4 || n > 1<<24 {
		return 0, nil, fmt.Errorf("message of %d bytes", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return kind, body, nil
}

func writeTyped(w io.Writer, kind byte, body []byte) error {
	buf := make([]byte, 5+len(body))
	buf[0] = kind
	binary.BigEndian.PutUint32(buf[1:], uint32(len(body)+4))
	copy(buf[5:], body)
	_, err := w.Write(buf)
	return err
}

// ---------------------------------------------------------------------------
// the failure
// ---------------------------------------------------------------------------

// brokenByLostCommit builds a writer whose head has drifted the only way it
// can: one append committed and the writer was told it had failed.
func brokenByLostCommit(t *testing.T) (*store.Store, *store.AuditWriter, int64) {
	t.Helper()
	ctx := context.Background()

	direct, dsn := migratedStore(t)
	breaker := newCommitBreaker(t, dsn)
	s := openStore(t, breaker.dsn(t, dsn))
	w := claimWriter(t, s, "w0")

	if _, err := w.Append(ctx, store.AuditEntry{Kind: "test.event", Payload: map[string]any{"i": 0}}); err != nil {
		t.Fatalf("first append: %v", err)
	}
	before, _ := w.Head()

	breaker.armed.Store(true)
	_, err := w.Append(ctx, store.AuditEntry{Kind: "test.lost", Subject: "lost", Payload: map[string]any{"i": 1}})
	if err == nil {
		t.Fatal("the append whose commit was dropped on the wire reported success")
	}
	if !breaker.broke.Load() {
		t.Fatalf("the proxy never saw a commit to lose; append failed with %v", err)
	}

	// The row is in the log. The writer does not know it.
	var landed int64
	if err := direct.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE writer_id = 'w0' AND kind = 'test.lost'`).Scan(&landed); err != nil {
		t.Fatalf("count landed rows: %v", err)
	}
	if landed != 1 {
		t.Fatalf("the dropped commit did not land: %d rows", landed)
	}
	if head, _ := w.Head(); head != before {
		t.Fatalf("head = %d, want the stale %d: the writer observed a commit it should not have", head, before)
	}
	return direct, w, before
}

// TestLostCommitDriftsTheHeadAndStopsTheWriter pins the mechanism itself,
// separately from the repair, so that a change to the repair cannot quietly
// take the reproduction with it.
func TestLostCommitDriftsTheHeadAndStopsTheWriter(t *testing.T) {
	ctx := context.Background()
	_, w, stale := brokenByLostCommit(t)

	// InTx is the raw seam, without the one retry Append is allowed. The next
	// write picks stale+1, which the lost commit already used, and the primary
	// key stops it.
	err := w.InTx(ctx, func(ctx context.Context, _ pgx.Tx, ap *store.Appender) error {
		_, aerr := ap.Append(ctx, store.AuditEntry{Kind: "test.event", Payload: map[string]any{"i": 2}})
		return aerr
	})
	if !errors.Is(err, store.ErrChainConflict) {
		t.Fatalf("write after a lost commit: %v, want ErrChainConflict", err)
	}
	if head, _ := w.Head(); head != stale {
		t.Fatalf("head = %d after a conflict, want it left at %d", head, stale)
	}
}

// TestConflictedInTxIsNotRetriedForTheCaller keeps the retry where it is safe.
// A caller's closure writes state of its own, and re-running it behind the
// caller's back is not something this seam can promise; the reconciliation is
// what the next call gets, not a second run of this one.
func TestConflictedInTxIsNotRetriedForTheCaller(t *testing.T) {
	ctx := context.Background()
	_, w, _ := brokenByLostCommit(t)

	runs := 0
	err := w.InTx(ctx, func(ctx context.Context, _ pgx.Tx, ap *store.Appender) error {
		runs++
		_, aerr := ap.Append(ctx, store.AuditEntry{Kind: "test.event", Payload: map[string]any{}})
		return aerr
	})
	if !errors.Is(err, store.ErrChainConflict) {
		t.Fatalf("conflicted InTx: %v, want ErrChainConflict", err)
	}
	if runs != 1 {
		t.Fatalf("the caller's closure ran %d times, want once", runs)
	}
	// The writer is reconciled by the next call, not by this one.
	if err := w.InTx(ctx, func(ctx context.Context, _ pgx.Tx, ap *store.Appender) error {
		_, aerr := ap.Append(ctx, store.AuditEntry{Kind: "test.event", Payload: map[string]any{}})
		return aerr
	}); err != nil {
		t.Fatalf("the write after the conflicted one: %v", err)
	}
}

// TestWriterReconcilesAfterALostCommit is the regression: the writer that used
// to be dead for the life of the process takes the next write.
func TestWriterReconcilesAfterALostCommit(t *testing.T) {
	ctx := context.Background()
	direct, w, stale := brokenByLostCommit(t)

	// The first append after the drift collides, reconciles, and lands. A lost
	// commit costs the chain nothing.
	rec, err := w.Append(ctx, store.AuditEntry{Kind: "test.event", Subject: "after", Payload: map[string]any{"i": 3}})
	if err != nil {
		t.Fatalf("append after a lost commit: %v", err)
	}
	if rec[0].Seq != stale+3 {
		t.Fatalf("seq = %d, want %d: the lost row and the reconciliation marker both sit between",
			rec[0].Seq, stale+3)
	}

	// The chain is whole: no gap where the unobserved commit landed, no link
	// broken by the writer resuming.
	if report := verifyChain(t, direct); !report.OK() {
		t.Fatalf("chain broken after reconciliation: %v", report.Err())
	}

	// The rows the writer never observed committing are still readable, and
	// still say what they said.
	var lost int64
	if err := direct.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE writer_id = 'w0' AND kind = 'test.lost'`).Scan(&lost); err != nil {
		t.Fatalf("count lost rows: %v", err)
	}
	if lost != 1 {
		t.Fatalf("the unobserved commit's row went missing: %d", lost)
	}

	// And the repair is in the log rather than only in the process's memory.
	var payload string
	err = direct.Pool().QueryRow(ctx,
		`SELECT payload::text FROM audit_log WHERE writer_id = 'w0' AND kind = $1`,
		store.AuditKindWriterReconciled).Scan(&payload)
	if err != nil {
		t.Fatalf("read the reconciliation marker: %v", err)
	}
	var marker struct {
		BelievedSeq int64 `json:"believed_seq"`
		AdoptedSeq  int64 `json:"adopted_seq"`
		AdoptedRows int   `json:"adopted_rows"`
	}
	if err := json.Unmarshal([]byte(payload), &marker); err != nil {
		t.Fatalf("marker payload %q: %v", payload, err)
	}
	if marker.BelievedSeq != stale || marker.AdoptedSeq != stale+1 || marker.AdoptedRows != 1 {
		t.Fatalf("marker = %+v, want the window %d..%d named exactly", marker, stale, stale+1)
	}
}

// TestReconciliationRefusesRowsItCannotProveItWrote is the other half of the
// contract. A writer that adopted anything it found ahead of its head would
// turn a forked segment into a segment that verifies, which is worse than a
// writer that stops.
func TestReconciliationRefusesRowsItCannotProveItWrote(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	appendN(t, w, 2)
	head, _ := w.Head()

	// A row at the sequence number the writer is about to use, chained from the
	// right place but not hashed from its own contents: what anything other
	// than this writer produces.
	if _, err := s.Pool().Exec(ctx, `
		INSERT INTO audit_log (writer_id, seq, prev_hash, hash, kind, subject, payload, recorded_at)
		SELECT 'w0', $1, hash, decode(repeat('ab',32),'hex'), 'squatter', '', '{}'::jsonb, now()
		FROM audit_log WHERE writer_id = 'w0' AND seq = $2`, head+1, head); err != nil {
		t.Fatalf("squat sequence: %v", err)
	}

	_, err := w.Append(ctx, store.AuditEntry{Kind: "test.event", Payload: map[string]any{}})
	if !errors.Is(err, store.ErrUnreconciled) {
		t.Fatalf("append onto a squatted sequence: %v, want ErrUnreconciled", err)
	}
	if !errors.Is(err, store.ErrChainConflict) {
		t.Fatalf("append onto a squatted sequence: %v, want it to still read as a chain conflict", err)
	}
	if head2, _ := w.Head(); head2 != head {
		t.Fatalf("head = %d, want it left at %d: a refused reconciliation moved the head", head2, head)
	}

	// No marker was written, because no reconciliation happened.
	var markers int64
	if err := s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE kind = $1`, store.AuditKindWriterReconciled).Scan(&markers); err != nil {
		t.Fatalf("count markers: %v", err)
	}
	if markers != 0 {
		t.Fatalf("a refused reconciliation still recorded %d marker(s)", markers)
	}
}

// TestReconciliationRefusesWhenTheClaimIsGone covers the case the conflict
// cannot distinguish on its own: the collision may be a second writer on this
// segment, and the only evidence that it is not is the claim.
func TestReconciliationRefusesWhenTheClaimIsGone(t *testing.T) {
	ctx := context.Background()
	direct, w, _ := brokenByLostCommit(t)

	// Drop the advisory lock out from under the writer, which is what a
	// connection reset or a hand-run pg_advisory_unlock_all does.
	var pid int32
	if err := direct.Pool().QueryRow(ctx, `
		SELECT pid FROM pg_locks
		WHERE locktype = 'advisory' AND granted AND objsubid = 1
		LIMIT 1`).Scan(&pid); err != nil {
		t.Fatalf("find the claim: %v", err)
	}
	if _, err := direct.Pool().Exec(ctx,
		`SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatalf("terminate the claim's backend: %v", err)
	}

	if _, err := w.Append(ctx, store.AuditEntry{Kind: "test.event", Payload: map[string]any{}}); !errors.Is(err, store.ErrUnreconciled) {
		t.Fatalf("append with no claim: %v, want ErrUnreconciled", err)
	}
}
