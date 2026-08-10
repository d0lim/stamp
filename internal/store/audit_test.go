package store_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/store"
)

func appendN(t *testing.T, w *store.AuditWriter, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if _, err := w.Append(ctx, store.AuditEntry{
			Kind:    "test.event",
			Subject: fmt.Sprintf("s%d", i),
			Payload: map[string]any{"i": i, "note": "hello"},
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func verifyChain(t *testing.T, s *store.Store) *store.ChainReport {
	t.Helper()
	report, err := s.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	return report
}

func hasFault(report *store.ChainReport, kind store.FaultKind) bool {
	for _, f := range report.Faults {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func TestAppendAndVerifyChain(t *testing.T) {
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	appendN(t, w, 10)

	report := verifyChain(t, s)
	if !report.OK() {
		t.Fatalf("clean chain failed verification: %v", report.Err())
	}
	if report.Rows != 10 {
		t.Fatalf("verified %d rows, want 10", report.Rows)
	}
	if len(report.Segments) != 1 || report.Segments[0].HeadSeq != 10 {
		t.Fatalf("segments = %+v, want one segment with head 10", report.Segments)
	}
	headSeq, headHash := w.Head()
	if headSeq != 10 || headHash != report.Segments[0].HeadHash {
		t.Fatalf("writer head (%d, %x) disagrees with the log head (%d, %x)",
			headSeq, headHash, report.Segments[0].HeadSeq, report.Segments[0].HeadHash)
	}
}

// Modifying a row behind the storage API has to be visible. This is the whole
// claim the audit log makes.
func TestModifiedRowFailsVerification(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	appendN(t, w, 5)

	if report := verifyChain(t, s); !report.OK() {
		t.Fatalf("chain was already broken before tampering: %v", report.Err())
	}

	if _, err := s.Pool().Exec(ctx,
		`UPDATE audit_log SET payload = '{"i": 999}'::jsonb WHERE writer_id = 'w0' AND seq = 3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	report := verifyChain(t, s)
	if report.OK() {
		t.Fatal("a modified payload passed verification")
	}
	if !hasFault(report, store.FaultHashMismatch) {
		t.Fatalf("faults = %v, want a hash mismatch", report.Faults)
	}
	if !errors.Is(report.Err(), store.ErrChainBroken) {
		t.Fatalf("Err() = %v, want ErrChainBroken", report.Err())
	}
}

func TestModifiedSubjectFailsVerification(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	appendN(t, w, 3)

	if _, err := s.Pool().Exec(ctx,
		`UPDATE audit_log SET subject = 'someone-else' WHERE writer_id = 'w0' AND seq = 2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if report := verifyChain(t, s); !hasFault(report, store.FaultHashMismatch) {
		t.Fatalf("faults = %v, want a hash mismatch", report.Faults)
	}
}

func TestDeletedRowFailsVerification(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	appendN(t, w, 6)

	if _, err := s.Pool().Exec(ctx,
		`DELETE FROM audit_log WHERE writer_id = 'w0' AND seq = 4`); err != nil {
		t.Fatalf("delete: %v", err)
	}

	report := verifyChain(t, s)
	if report.OK() {
		t.Fatal("a deleted row passed verification")
	}
	if !hasFault(report, store.FaultSequenceGap) {
		t.Errorf("faults = %v, want a sequence gap", report.Faults)
	}
	if !hasFault(report, store.FaultPrevMismatch) {
		t.Errorf("faults = %v, want a broken link", report.Faults)
	}
}

// Deleting the tail of a segment leaves every remaining link intact, so this is
// the case internal verification cannot catch on its own. It is here to record
// that limit; the checkpoint tests are what close it.
func TestDeletedTailPassesChainVerification(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	appendN(t, w, 5)

	if _, err := s.Pool().Exec(ctx, `DELETE FROM audit_log WHERE writer_id = 'w0' AND seq = 5`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if report := verifyChain(t, s); !report.OK() {
		t.Fatalf("a truncated segment should still re-chain cleanly, got %v", report.Err())
	}
}

func TestConcurrentWritersVerify(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)

	const writers = 8
	const perWriter = 25

	ws := make([]*store.AuditWriter, writers)
	for i := range ws {
		ws[i] = claimWriter(t, s, fmt.Sprintf("w%d", i))
	}

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i, w := range ws {
		wg.Add(1)
		go func(i int, w *store.AuditWriter) {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				if _, err := w.Append(ctx, store.AuditEntry{
					Kind:    "test.concurrent",
					Subject: fmt.Sprintf("w%d-%d", i, j),
					Payload: map[string]any{"writer": i, "n": j},
				}); err != nil {
					errs <- err
					return
				}
			}
		}(i, w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent append: %v", err)
	}

	report := verifyChain(t, s)
	if !report.OK() {
		t.Fatalf("concurrent writers produced a chain that does not verify: %v", report.Err())
	}
	if report.Rows != writers*perWriter {
		t.Fatalf("verified %d rows, want %d", report.Rows, writers*perWriter)
	}
	if len(report.Segments) != writers {
		t.Fatalf("got %d segments, want %d", len(report.Segments), writers)
	}
	for _, seg := range report.Segments {
		if seg.Rows != perWriter || seg.HeadSeq != perWriter {
			t.Errorf("segment %s has %d rows and head %d, want %d of each",
				seg.WriterID, seg.Rows, seg.HeadSeq, perWriter)
		}
	}
}

// Writer identifiers are exclusively owned. A second claimant fails at
// acquisition rather than at the first append, because failing at the append is
// a correctness failure discovered under load.
func TestWriterIDIsExclusive(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)

	first := claimWriter(t, s, "w0")

	_, err := s.ClaimWriter(ctx, "w0", "second-instance")
	if err == nil {
		t.Fatal("a second process claimed a live writer id")
	}
	if !errors.Is(err, store.ErrWriterTaken) {
		t.Fatalf("second claim failed with %v, want ErrWriterTaken", err)
	}

	// A different identifier is fine, and so is the same one after release.
	other, err := s.ClaimWriter(ctx, "w1", "second-instance")
	if err != nil {
		t.Fatalf("claiming a free writer id failed: %v", err)
	}
	if err := other.Close(ctx); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := first.Close(ctx); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	reclaimed, err := s.ClaimWriter(ctx, "w0", "third-instance")
	if err != nil {
		t.Fatalf("reclaiming a released writer id failed: %v", err)
	}
	defer func() { _ = reclaimed.Close(ctx) }()

	// A reclaim picks the chain up where it was left, rather than restarting.
	appendN(t, reclaimed, 2)
	if seq, _ := reclaimed.Head(); seq != 2 {
		t.Fatalf("head after reclaim = %d, want 2", seq)
	}
}

func TestWriterIDMustBeWellFormed(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	for _, id := range []string{"", "has space", "-leading", "w0;DROP", "quoted\"id"} {
		if _, err := s.ClaimWriter(ctx, id, "test"); err == nil {
			t.Errorf("writer id %q was accepted", id)
		}
	}
}

func TestWriterHoldIsVerifiable(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	if err := w.VerifyHold(ctx); err != nil {
		t.Fatalf("a freshly claimed writer does not report its own hold: %v", err)
	}
}

func TestMerkleRootDistinguishesLeafOrderAndContent(t *testing.T) {
	a := store.MerkleRoot([][]byte{[]byte("one"), []byte("two"), []byte("three")})
	b := store.MerkleRoot([][]byte{[]byte("one"), []byte("three"), []byte("two")})
	if a == b {
		t.Fatal("reordering leaves did not change the root")
	}
	c := store.MerkleRoot([][]byte{[]byte("one"), []byte("two"), []byte("three")})
	if a != c {
		t.Fatal("the same leaves produced two different roots")
	}
	// An odd tail must not be duplicated into a shorter list's root.
	d := store.MerkleRoot([][]byte{[]byte("one"), []byte("two"), []byte("three"), []byte("three")})
	if a == d {
		t.Fatal("a duplicated odd leaf collided with the shorter list")
	}
	if store.MerkleRoot(nil) == a {
		t.Fatal("the empty root collided with a populated one")
	}
}

// The check path writes one row per batch, not one per request. This records
// that the batch row is a normal chain entry, so it verifies like any other.
func TestCheckBatchIsOneChainRow(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "checker")

	leaves := make([][]byte, 500)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("request-%d", i))
	}
	now := s.Now()
	rec, err := w.AppendCheckBatch(ctx, store.CheckBatch{
		From:  now.Add(-time.Second),
		To:    now,
		Count: len(leaves),
		Root:  store.MerkleRoot(leaves),
	})
	if err != nil {
		t.Fatalf("append check batch: %v", err)
	}
	if rec.Seq != 1 {
		t.Fatalf("check batch landed at seq %d, want 1", rec.Seq)
	}

	var rows int64
	if err := s.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&rows); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if rows != 1 {
		t.Fatalf("%d audit rows for a 500-request batch, want 1", rows)
	}
	if report := verifyChain(t, s); !report.OK() {
		t.Fatalf("batch row does not verify: %v", report.Err())
	}
}

func TestCheckGapMarkerIsRecorded(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "checker")

	now := s.Now()
	if _, err := w.AppendCheckGap(ctx, store.CheckGap{
		From: now.Add(-time.Minute), To: now, Dropped: 1234, Reason: "audit buffer full",
	}); err != nil {
		t.Fatalf("append gap marker: %v", err)
	}

	var kind, payload string
	if err := s.Pool().QueryRow(ctx,
		`SELECT kind, payload::text FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&kind, &payload); err != nil {
		t.Fatalf("read gap marker: %v", err)
	}
	if kind != store.AuditKindCheckGap {
		t.Fatalf("kind = %q, want %q", kind, store.AuditKindCheckGap)
	}
	if !strings.Contains(payload, "1234") {
		t.Fatalf("gap marker payload %q does not record how many records were lost", payload)
	}
	if report := verifyChain(t, s); !report.OK() {
		t.Fatalf("gap marker does not verify: %v", report.Err())
	}
}
