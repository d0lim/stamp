package bench_test

// Audit insert throughput is not a check-path number and is not comparable to
// one. What the plan asks for is a conversion: one batch root row covers some
// number of check requests, so the rate at which root rows reach the chain
// times that cover is the check rate the audit path can keep up with.
//
// The cover is read from the code that decides it — `api.DefaultAuditBatchSize`,
// imported here rather than restated — because a benchmark holding its own copy
// of a constant reports the truth exactly until somebody changes the constant,
// which is the moment it matters.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/d0lim/stamp/bench"
	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/store"
)

// BenchmarkAuditRootInsert measures how fast one writer can append batch root
// rows to its own segment of the chain.
//
// One writer, not several. A segment belongs to exactly one process — S2
// established that two writers on one segment is a correctness failure, not a
// slow path — so the rate one process can sustain is what a single-instance
// deployment gets, and scaling it means adding instances.
//
// The root is computed once, outside the loop. What is measured is the append:
// the chain read of the segment head, the hash, and the insert. Hashing the
// leaves is the flusher's CPU work rather than the chain's, and folding it in
// here would report a slower insert rate than the chain actually has.
func BenchmarkAuditRootInsert(b *testing.B) {
	h := newHarness(b, options{})
	ctx := context.Background()

	// A second writer identifier: the process under measurement already holds
	// its own, and taking that one would be the collision U4 fails the boot on.
	writer, err := h.app.Store().ClaimWriter(ctx, "bench-audit-writer", "bench")
	if err != nil {
		b.Fatalf("claim audit writer: %v", err)
	}
	b.Cleanup(func() {
		if err := writer.Close(ctx); err != nil {
			b.Errorf("close audit writer: %v", err)
		}
	})

	cover := api.DefaultAuditBatchSize
	leaves := make([][]byte, cover)
	for i := range leaves {
		digest := sha256.Sum256(fmt.Appendf(nil, "bench-leaf-%d", i))
		leaves[i] = digest[:]
	}
	root := store.MerkleRoot(leaves)

	result := drive(loadSpec{
		concurrency: 1,
		warmup:      benchCfg.warmup,
		window:      benchCfg.duration,
	}, func(_, _ int) (bool, error) {
		now := time.Now().UTC()
		_, err := writer.AppendCheckBatch(ctx, store.CheckBatch{
			From:   now,
			To:     now,
			Count:  cover,
			Root:   root,
			Digest: api.AuditDigestScheme,
		})
		return err == nil, err
	})

	run := result.run("audit_root_insert",
		"one writer appending batch root rows to its own chain segment", 1)
	covered := run.QPS * float64(cover)
	run.Audit = &bench.AuditConversion{
		RootInsertsPerSec:   run.QPS,
		CoverPerRoot:        cover,
		CoverSource:         "api.DefaultAuditBatchSize",
		CoveredChecksPerSec: covered,
		Formula: fmt.Sprintf(
			"covered checks/s = root inserts/s x checks per root = %.1f x %d = %.0f",
			run.QPS, cover, covered),
	}
	record(run)
	reportToGo(b, run)
}
