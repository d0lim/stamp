package store_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/d0lim/stamp/internal/store"
)

func verifierFor(signer *store.CheckpointSigner) *store.CheckpointVerifier {
	return store.NewCheckpointVerifier(map[string]ed25519.PublicKey{signer.KeyID(): signer.Public()})
}

func hasCheckpointFault(report *store.CheckpointReport, kind store.FaultKind) bool {
	for _, f := range report.Faults {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

// The default sink is an append-only local file, and what lands in it is a
// signed checkpoint.
func TestCheckpointIsSignedAndAppendedToFileSink(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	w := claimWriter(t, s, "w0")
	appendN(t, w, 4)

	signer := testSigner(t)
	sink := fileSink(t)
	cp, err := s.Checkpointer(signer, sink).Checkpoint(ctx)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if cp.Seq != 1 {
		t.Fatalf("first checkpoint has seq %d, want 1", cp.Seq)
	}
	if len(cp.Heads) != 1 || cp.Heads[0].WriterID != "w0" || cp.Heads[0].Seq != 4 {
		t.Fatalf("heads = %+v, want w0 at seq 4", cp.Heads)
	}
	if len(cp.Signature) != ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(cp.Signature), ed25519.SignatureSize)
	}

	raw, err := os.ReadFile(sink.Path())
	if err != nil {
		t.Fatalf("read sink file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("sink holds %d lines, want 1", len(lines))
	}
	var fromFile store.Checkpoint
	if err := json.Unmarshal([]byte(lines[0]), &fromFile); err != nil {
		t.Fatalf("decode sink line: %v", err)
	}
	if err := verifierFor(signer).Verify(fromFile); err != nil {
		t.Fatalf("the checkpoint in the file does not verify: %v", err)
	}

	// A second checkpoint appends rather than replaces, and links to the first.
	appendN(t, w, 2)
	cp2, err := s.Checkpointer(signer, sink).Checkpoint(ctx)
	if err != nil {
		t.Fatalf("second checkpoint: %v", err)
	}
	if cp2.PrevHash != cp.HeadsHash {
		t.Fatal("the second checkpoint does not link to the first")
	}
	held, err := sink.Checkpoints(ctx)
	if err != nil {
		t.Fatalf("read sink: %v", err)
	}
	if len(held) != 2 {
		t.Fatalf("sink holds %d checkpoints, want 2", len(held))
	}

	report, err := s.Checkpointer(signer, sink).VerifyCheckpoints(ctx, verifierFor(signer))
	if err != nil {
		t.Fatalf("verify checkpoints: %v", err)
	}
	if !report.OK() {
		t.Fatalf("a clean checkpoint series failed verification: %v", report.Err())
	}
}

// This is the attack the segmented chain cannot survive on its own: whoever can
// write to the database can also rebuild every hash. Rebuilding produces a log
// that re-chains perfectly, and only the signed head held outside the database
// disagrees.
func TestRechainedLogIsDetectedAgainstCheckpoint(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	signer := testSigner(t)
	sink := fileSink(t)

	w := claimWriter(t, s, "w0")
	appendN(t, w, 6)
	if _, err := s.Checkpointer(signer, sink).Checkpoint(ctx); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}

	// Rewrite history: drop the log and rebuild a chain of the same length
	// through the real append path, so every hash and link is genuinely valid.
	if _, err := s.Pool().Exec(ctx, `DELETE FROM audit_log`); err != nil {
		t.Fatalf("wipe log: %v", err)
	}
	if err := w.ReloadHead(ctx); err != nil {
		t.Fatalf("reload head: %v", err)
	}
	for i := 0; i < 6; i++ {
		if _, err := w.Append(ctx, store.AuditEntry{
			Kind:    "test.event",
			Subject: "rewritten",
			Payload: map[string]any{"i": i},
		}); err != nil {
			t.Fatalf("re-append: %v", err)
		}
	}

	if report := verifyChain(t, s); !report.OK() {
		t.Fatalf("the rewritten log should re-chain cleanly — that is the point: %v", report.Err())
	}

	report, err := s.Checkpointer(signer, sink).VerifyCheckpoints(ctx, verifierFor(signer))
	if err != nil {
		t.Fatalf("verify checkpoints: %v", err)
	}
	if report.OK() {
		t.Fatal("a wholesale re-chaining passed checkpoint verification")
	}
	if !hasCheckpointFault(report, store.FaultHeadMismatch) {
		t.Fatalf("faults = %v, want a head mismatch", report.Faults)
	}
	if !errors.Is(report.Err(), store.ErrChainBroken) {
		t.Fatalf("Err() = %v, want ErrChainBroken", report.Err())
	}
}

// A shorter rewrite loses the checkpointed row entirely.
func TestTruncatedLogIsDetectedAgainstCheckpoint(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	signer := testSigner(t)
	sink := fileSink(t)

	w := claimWriter(t, s, "w0")
	appendN(t, w, 5)
	if _, err := s.Checkpointer(signer, sink).Checkpoint(ctx); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if _, err := s.Pool().Exec(ctx, `DELETE FROM audit_log WHERE seq > 2`); err != nil {
		t.Fatalf("truncate log: %v", err)
	}

	report, err := s.Checkpointer(signer, sink).VerifyCheckpoints(ctx, verifierFor(signer))
	if err != nil {
		t.Fatalf("verify checkpoints: %v", err)
	}
	if !hasCheckpointFault(report, store.FaultMissingRow) {
		t.Fatalf("faults = %v, want a missing row", report.Faults)
	}
}

// A missing checkpoint has to be a gap, not just a shorter history.
func TestCheckpointGapIsDetected(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	signer := testSigner(t)
	sink := fileSink(t)
	cpr := s.Checkpointer(signer, sink)

	w := claimWriter(t, s, "w0")
	for i := 0; i < 3; i++ {
		appendN(t, w, 2)
		if _, err := cpr.Checkpoint(ctx); err != nil {
			t.Fatalf("checkpoint %d: %v", i, err)
		}
	}

	// Remove the middle checkpoint from the sink, as an attacker who could
	// reach the file would.
	raw, err := os.ReadFile(sink.Path())
	if err != nil {
		t.Fatalf("read sink: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("sink holds %d checkpoints, want 3", len(lines))
	}
	kept := lines[0] + "\n" + lines[2] + "\n"
	if err := os.WriteFile(sink.Path(), []byte(kept), 0o600); err != nil {
		t.Fatalf("rewrite sink: %v", err)
	}

	report, err := cpr.VerifyCheckpoints(ctx, verifierFor(signer))
	if err != nil {
		t.Fatalf("verify checkpoints: %v", err)
	}
	if report.OK() {
		t.Fatal("a missing checkpoint passed verification")
	}
	if !hasCheckpointFault(report, store.FaultCheckpointGap) {
		t.Fatalf("faults = %v, want a checkpoint gap", report.Faults)
	}
	if !hasCheckpointFault(report, store.FaultCheckpointChain) {
		t.Fatalf("faults = %v, want a broken checkpoint link", report.Faults)
	}

	// Sync republishes what the sink is missing, which is the repair path.
	published, err := cpr.Sync(ctx)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if published != 1 {
		t.Fatalf("sync republished %d checkpoints, want 1", published)
	}
	report, err = cpr.VerifyCheckpoints(ctx, verifierFor(signer))
	if err != nil {
		t.Fatalf("verify after sync: %v", err)
	}
	if !report.OK() {
		t.Fatalf("verification still fails after a repair: %v", report.Err())
	}
}

func TestForgedCheckpointFailsSignatureCheck(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	signer := testSigner(t)
	sink := fileSink(t)

	w := claimWriter(t, s, "w0")
	appendN(t, w, 3)
	cp, err := s.Checkpointer(signer, sink).Checkpoint(ctx)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}

	// An attacker with database write access rewrites the heads. They cannot
	// re-sign, because the key is not in the database.
	forged := cp
	forged.Heads = append([]store.WriterHead(nil), cp.Heads...)
	forged.Heads[0].Seq = 99
	if err := verifierFor(signer).Verify(forged); err == nil {
		t.Fatal("a checkpoint with rewritten heads verified")
	}

	// A different key does not pass either.
	other := testSigner(t)
	if err := verifierFor(other).Verify(cp); err == nil {
		t.Fatal("a checkpoint verified under the wrong key")
	}
	if err := verifierFor(signer).Verify(cp); err != nil {
		t.Fatalf("the genuine checkpoint stopped verifying: %v", err)
	}
}

func TestCheckpointsSurviveJSONRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	signer := testSigner(t)
	sink := fileSink(t)

	w := claimWriter(t, s, "w0")
	appendN(t, w, 2)
	cp, err := s.Checkpointer(signer, sink).Checkpoint(ctx)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back store.Checkpoint
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.HeadsHash != cp.HeadsHash || back.PrevHash != cp.PrevHash || back.Seq != cp.Seq {
		t.Fatal("the checkpoint did not survive a JSON round trip")
	}
	if err := verifierFor(signer).Verify(back); err != nil {
		t.Fatalf("the round-tripped checkpoint does not verify: %v", err)
	}
}
