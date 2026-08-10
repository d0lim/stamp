package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// checkpointDomain separates checkpoint digests from row hashes, so a row hash
// can never be presented as a checkpoint digest or the reverse.
const checkpointDomain = "stamp.audit.checkpoint.v1"

// ErrNoSignature reports that a checkpoint carries no usable signature, or that
// no public key is configured for the key it names.
var ErrNoSignature = errors.New("store: checkpoint signature cannot be verified")

// WriterHead is one segment's head at a moment in time.
type WriterHead struct {
	WriterID string
	Seq      int64
	Hash     [32]byte
}

type writerHeadWire struct {
	WriterID string `json:"writer_id"`
	Seq      int64  `json:"seq"`
	Hash     string `json:"hash"`
}

// MarshalJSON renders the head with a hex hash, because a checkpoint file is
// meant to be readable by a person auditing it and by tooling that is not Go.
func (h WriterHead) MarshalJSON() ([]byte, error) {
	return json.Marshal(writerHeadWire{h.WriterID, h.Seq, hex.EncodeToString(h.Hash[:])})
}

// UnmarshalJSON parses the wire form.
func (h *WriterHead) UnmarshalJSON(b []byte) error {
	var w writerHeadWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	raw, err := hex.DecodeString(w.Hash)
	if err != nil {
		return fmt.Errorf("store: writer head hash: %w", err)
	}
	if len(raw) != len(h.Hash) {
		return fmt.Errorf("store: writer head hash is %d bytes, want %d", len(raw), len(h.Hash))
	}
	h.WriterID, h.Seq = w.WriterID, w.Seq
	copy(h.Hash[:], raw)
	return nil
}

// Checkpoint names every segment head at a moment and signs the result.
//
// This is what cross-links the per-writer chains. A row hash proves only that
// its own segment is internally consistent; anyone with write access to the
// database can rebuild all of them. The signature is made with a key the
// database does not hold and the result is exported outside the database, so
// the one thing an attacker with DB write access cannot do is produce a
// checkpoint that agrees with the log they rewrote.
type Checkpoint struct {
	Seq       int64
	CreatedAt time.Time
	Heads     []WriterHead
	HeadsHash [32]byte
	PrevHash  [32]byte
	KeyID     string
	Signature []byte
}

type checkpointWire struct {
	Seq       int64        `json:"seq"`
	CreatedAt time.Time    `json:"created_at"`
	Heads     []WriterHead `json:"heads"`
	HeadsHash string       `json:"heads_hash"`
	PrevHash  string       `json:"prev_hash"`
	KeyID     string       `json:"key_id"`
	Signature string       `json:"signature"`
}

// MarshalJSON renders the checkpoint in the form the file sink appends.
func (c Checkpoint) MarshalJSON() ([]byte, error) {
	return json.Marshal(checkpointWire{
		Seq:       c.Seq,
		CreatedAt: c.CreatedAt.UTC(),
		Heads:     c.Heads,
		HeadsHash: hex.EncodeToString(c.HeadsHash[:]),
		PrevHash:  hex.EncodeToString(c.PrevHash[:]),
		KeyID:     c.KeyID,
		Signature: hex.EncodeToString(c.Signature),
	})
}

// UnmarshalJSON parses the file sink's form.
func (c *Checkpoint) UnmarshalJSON(b []byte) error {
	var w checkpointWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	headsHash, err := hex.DecodeString(w.HeadsHash)
	if err != nil {
		return fmt.Errorf("store: checkpoint heads_hash: %w", err)
	}
	prevHash, err := hex.DecodeString(w.PrevHash)
	if err != nil {
		return fmt.Errorf("store: checkpoint prev_hash: %w", err)
	}
	sig, err := hex.DecodeString(w.Signature)
	if err != nil {
		return fmt.Errorf("store: checkpoint signature: %w", err)
	}
	if len(headsHash) != len(c.HeadsHash) || len(prevHash) != len(c.PrevHash) {
		return errors.New("store: checkpoint hash is not 32 bytes")
	}
	c.Seq, c.CreatedAt, c.Heads, c.KeyID, c.Signature = w.Seq, w.CreatedAt.UTC(), w.Heads, w.KeyID, sig
	copy(c.HeadsHash[:], headsHash)
	copy(c.PrevHash[:], prevHash)
	return nil
}

// checkpointDigest is the value that gets signed.
//
// It covers the sequence number, the timestamp, the previous digest and every
// head. Leaving the previous digest out would make each checkpoint independent,
// and a removed checkpoint would then be invisible rather than a broken link.
func checkpointDigest(seq int64, createdAt time.Time, prev [32]byte, heads []WriterHead) [32]byte {
	h := sha256.New()
	writeTagged(h, []byte(checkpointDomain))
	writeInt64(h, seq)
	writeInt64(h, createdAt.UTC().UnixMicro())
	h.Write(prev[:])
	writeUint64(h, uint64(len(heads)))
	for _, head := range heads {
		writeTagged(h, []byte(head.WriterID))
		writeInt64(h, head.Seq)
		h.Write(head.Hash[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// CheckpointSigner signs checkpoints with an application-held Ed25519 key.
type CheckpointSigner struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewCheckpointSigner builds a signer. keyID is recorded on every checkpoint so
// that a key rotation leaves the older checkpoints verifiable.
func NewCheckpointSigner(keyID string, priv ed25519.PrivateKey) (*CheckpointSigner, error) {
	if keyID == "" {
		return nil, errors.New("store: checkpoint signer needs a key id")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("store: checkpoint signing key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return &CheckpointSigner{keyID: keyID, priv: priv}, nil
}

// KeyID reports the identifier stamped on checkpoints this signer produces.
func (s *CheckpointSigner) KeyID() string { return s.keyID }

// Public returns the verification key.
func (s *CheckpointSigner) Public() ed25519.PublicKey {
	pub, _ := s.priv.Public().(ed25519.PublicKey)
	return pub
}

func (s *CheckpointSigner) sign(digest [32]byte) []byte {
	return ed25519.Sign(s.priv, digest[:])
}

// CheckpointVerifier holds the public keys checkpoints are verified against.
type CheckpointVerifier struct {
	keys map[string]ed25519.PublicKey
}

// NewCheckpointVerifier builds a verifier over a key-id to public-key map.
func NewCheckpointVerifier(keys map[string]ed25519.PublicKey) *CheckpointVerifier {
	copied := make(map[string]ed25519.PublicKey, len(keys))
	for id, k := range keys {
		copied[id] = k
	}
	return &CheckpointVerifier{keys: copied}
}

// Verify checks a checkpoint's signature against its recomputed digest.
func (v *CheckpointVerifier) Verify(c Checkpoint) error {
	pub, ok := v.keys[c.KeyID]
	if !ok {
		return fmt.Errorf("store: no public key configured for key id %q: %w", c.KeyID, ErrNoSignature)
	}
	want := checkpointDigest(c.Seq, c.CreatedAt, c.PrevHash, c.Heads)
	if !bytes.Equal(want[:], c.HeadsHash[:]) {
		return fmt.Errorf("store: checkpoint %d digest is %x, recomputed %x", c.Seq, c.HeadsHash, want)
	}
	if !ed25519.Verify(pub, c.HeadsHash[:], c.Signature) {
		return fmt.Errorf("store: checkpoint %d signature does not verify: %w", c.Seq, ErrNoSignature)
	}
	return nil
}

// ---------------------------------------------------------------------------
// sinks
// ---------------------------------------------------------------------------

// CheckpointSink receives signed checkpoints outside the database. The default
// implementation is FileSink; a deployment may add a webhook.
type CheckpointSink interface {
	Publish(ctx context.Context, c Checkpoint) error
}

// CheckpointReader reads checkpoints back out of a sink. Verification needs it,
// because the whole point of the sink is that it, and not the database, is the
// authority on what the log used to say. A sink that cannot be read back (a
// webhook, for instance) can receive checkpoints but cannot be verified
// against on its own.
type CheckpointReader interface {
	Checkpoints(ctx context.Context) ([]Checkpoint, error)
}

// FileSink is the default sink: an append-only local file with one JSON
// checkpoint per line.
//
// A file is the default rather than a webhook because the guarantee has to hold
// in the single-container deployment with no second system configured. A
// checkpoint that is only ever delivered somewhere else is a checkpoint that is
// absent whenever delivery is not configured.
type FileSink struct {
	path string
	mu   sync.Mutex
}

// NewFileSink opens (creating if needed) the append-only checkpoint file.
func NewFileSink(path string) (*FileSink, error) {
	if path == "" {
		return nil, errors.New("store: checkpoint file sink needs a path")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("store: create checkpoint directory: %w", err)
		}
	}
	// The path is operator configuration — the sink location is part of the
	// deployment surface — and never reaches here from a request or a policy.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // operator-configured sink path
	if err != nil {
		return nil, fmt.Errorf("store: open checkpoint sink: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("store: open checkpoint sink: %w", err)
	}
	return &FileSink{path: path}, nil
}

// Path reports the file the sink appends to.
func (s *FileSink) Path() string { return s.path }

// Publish appends one checkpoint and flushes it to disk. The fsync is not
// optional: a checkpoint that is in the page cache when the host dies is a
// checkpoint the log can be rewritten behind.
func (s *FileSink) Publish(_ context.Context, c Checkpoint) error {
	line, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("store: encode checkpoint: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("store: open checkpoint sink: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("store: append checkpoint: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("store: sync checkpoint sink: %w", err)
	}
	return nil
}

// Checkpoints reads every checkpoint the sink holds, in file order.
func (s *FileSink) Checkpoints(_ context.Context) ([]Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: read checkpoint sink: %w", err)
	}
	var out []Checkpoint
	for i, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var c Checkpoint
		if err := json.Unmarshal(line, &c); err != nil {
			return nil, fmt.Errorf("store: checkpoint sink line %d: %w", i+1, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// WebhookSink posts checkpoints to an operator-configured endpoint.
//
// The endpoint is a resolved destination, not a policy-supplied URL: nothing a
// policy author writes reaches here. A deployment that uses it is expected to
// hand in an http.Client whose transport enforces the egress allowlist.
type WebhookSink struct {
	endpoint string
	client   *http.Client
}

// NewWebhookSink builds an optional webhook sink.
func NewWebhookSink(endpoint string, client *http.Client) (*WebhookSink, error) {
	if endpoint == "" {
		return nil, errors.New("store: webhook checkpoint sink needs an endpoint")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &WebhookSink{endpoint: endpoint, client: client}, nil
}

// Publish posts one checkpoint as JSON.
func (s *WebhookSink) Publish(ctx context.Context, c Checkpoint) error {
	body, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("store: encode checkpoint: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("store: build checkpoint request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("store: deliver checkpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("store: checkpoint webhook returned %s", resp.Status)
	}
	return nil
}

// MultiSink fans a checkpoint out to several sinks. It stops at the first
// failure so that a delivery problem is reported rather than averaged away.
type MultiSink []CheckpointSink

// Publish delivers to each sink in order.
func (m MultiSink) Publish(ctx context.Context, c Checkpoint) error {
	for _, s := range m {
		if err := s.Publish(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// creating and verifying checkpoints
// ---------------------------------------------------------------------------

// Checkpointer creates and verifies checkpoints.
type Checkpointer struct {
	store  *Store
	signer *CheckpointSigner
	sink   CheckpointSink
}

// Checkpointer builds a checkpointer over this store.
func (s *Store) Checkpointer(signer *CheckpointSigner, sink CheckpointSink) *Checkpointer {
	return &Checkpointer{store: s, signer: signer, sink: sink}
}

// Sink reports the sink checkpoints are published to.
func (c *Checkpointer) Sink() CheckpointSink { return c.sink }

// Checkpoint records the current head of every segment, signs it, stores it and
// publishes it to the sink.
//
// The database row is written first and the sink delivery follows. If delivery
// fails, the caller gets an error and the database is left holding a checkpoint
// the sink does not have — which verification reports as a gap. That is the
// intended failure mode: a missing external copy has to be loud, because the
// external copy is the only thing the database cannot forge.
func (c *Checkpointer) Checkpoint(ctx context.Context) (Checkpoint, error) {
	if c.signer == nil {
		return Checkpoint{}, errors.New("store: checkpointing needs a signer")
	}
	if c.sink == nil {
		return Checkpoint{}, errors.New("store: checkpointing needs a sink")
	}

	var cp Checkpoint
	err := c.store.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// Serialize checkpoint creation. Two concurrent checkpoints would
		// otherwise both claim the same sequence number and one would fail on
		// the primary key after having already been signed.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryKey("stamp:checkpoint")); err != nil {
			return fmt.Errorf("store: lock checkpoint series: %w", err)
		}

		var lastSeq int64
		var lastHash []byte
		err := tx.QueryRow(ctx,
			`SELECT seq, heads_hash FROM audit_checkpoints ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &lastHash)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("store: read last checkpoint: %w", err)
		}
		var prev [32]byte
		if err == nil {
			copy(prev[:], lastHash)
		}

		heads, herr := headsTx(ctx, tx)
		if herr != nil {
			return herr
		}

		cp = Checkpoint{
			Seq:       lastSeq + 1,
			CreatedAt: c.store.Now().Truncate(time.Microsecond),
			Heads:     heads,
			PrevHash:  prev,
			KeyID:     c.signer.KeyID(),
		}
		cp.HeadsHash = checkpointDigest(cp.Seq, cp.CreatedAt, cp.PrevHash, cp.Heads)
		cp.Signature = c.signer.sign(cp.HeadsHash)

		headsJSON, jerr := json.Marshal(cp.Heads)
		if jerr != nil {
			return fmt.Errorf("store: encode checkpoint heads: %w", jerr)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO audit_checkpoints (seq, created_at, heads, heads_hash, prev_hash, key_id, signature)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			cp.Seq, cp.CreatedAt, headsJSON, cp.HeadsHash[:], cp.PrevHash[:], cp.KeyID, cp.Signature)
		if err != nil {
			return fmt.Errorf("store: store checkpoint: %w", err)
		}
		return nil
	})
	if err != nil {
		return Checkpoint{}, err
	}

	if err := c.sink.Publish(ctx, cp); err != nil {
		return cp, fmt.Errorf("store: publish checkpoint %d: %w", cp.Seq, err)
	}
	return cp, nil
}

// Sync republishes any stored checkpoint the sink is missing. It is the repair
// path for a delivery that failed after the row was written.
func (c *Checkpointer) Sync(ctx context.Context) (int, error) {
	reader, ok := c.sink.(CheckpointReader)
	if !ok {
		return 0, errors.New("store: this sink cannot be read back, so it cannot be synced")
	}
	have, err := reader.Checkpoints(ctx)
	if err != nil {
		return 0, err
	}
	present := make(map[int64]struct{}, len(have))
	for _, cp := range have {
		present[cp.Seq] = struct{}{}
	}
	stored, err := c.store.Checkpoints(ctx)
	if err != nil {
		return 0, err
	}
	published := 0
	for _, cp := range stored {
		if _, ok := present[cp.Seq]; ok {
			continue
		}
		if err := c.sink.Publish(ctx, cp); err != nil {
			return published, err
		}
		published++
	}
	return published, nil
}

func headsTx(ctx context.Context, q Querier) ([]WriterHead, error) {
	rows, err := q.Query(ctx, `
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

// Checkpoints reads the database's copy of the checkpoint series.
func (s *Store) Checkpoints(ctx context.Context) ([]Checkpoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT seq, created_at, heads, heads_hash, prev_hash, key_id, signature
		FROM audit_checkpoints ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("store: read checkpoints: %w", err)
	}
	defer rows.Close()

	var out []Checkpoint
	for rows.Next() {
		var (
			cp        Checkpoint
			headsJSON []byte
			headsHash []byte
			prevHash  []byte
		)
		if err := rows.Scan(&cp.Seq, &cp.CreatedAt, &headsJSON, &headsHash, &prevHash, &cp.KeyID, &cp.Signature); err != nil {
			return nil, fmt.Errorf("store: scan checkpoint: %w", err)
		}
		if err := json.Unmarshal(headsJSON, &cp.Heads); err != nil {
			return nil, fmt.Errorf("store: decode checkpoint heads: %w", err)
		}
		copy(cp.HeadsHash[:], headsHash)
		copy(cp.PrevHash[:], prevHash)
		cp.CreatedAt = cp.CreatedAt.UTC()
		out = append(out, cp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read checkpoints: %w", err)
	}
	return out, nil
}

// CheckpointReport is the result of verifying the checkpoint series against the
// log.
type CheckpointReport struct {
	Checkpoints int
	Faults      []Fault
}

// OK reports whether verification found nothing.
func (r *CheckpointReport) OK() bool { return len(r.Faults) == 0 }

// Err returns ErrChainBroken with the fault list attached, or nil.
func (r *CheckpointReport) Err() error {
	if r.OK() {
		return nil
	}
	parts := make([]string, 0, len(r.Faults))
	for _, f := range r.Faults {
		parts = append(parts, f.String())
	}
	return fmt.Errorf("%w: %d checkpoint fault(s): %v", ErrChainBroken, len(r.Faults), parts)
}

// VerifyCheckpoints checks the signed checkpoints held outside the database
// against the audit log.
//
// It is the half of verification that VerifyChain cannot do. Re-chaining the
// whole log leaves every internal link consistent, so only an external record
// of what the heads used to be can tell that the log changed. Concretely this
// reports:
//
//   - a checkpoint whose signature does not verify, or whose digest does not
//     match its own contents;
//   - a break in the checkpoint chain, or a missing sequence number, in the
//     sink or in the database;
//   - a head the log no longer has, or has with a different hash.
func (c *Checkpointer) VerifyCheckpoints(ctx context.Context, verifier *CheckpointVerifier) (*CheckpointReport, error) {
	reader, ok := c.sink.(CheckpointReader)
	if !ok {
		return nil, errors.New("store: this sink cannot be read back, so it cannot be verified against")
	}
	external, err := reader.Checkpoints(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(external, func(i, j int) bool { return external[i].Seq < external[j].Seq })

	stored, err := c.store.Checkpoints(ctx)
	if err != nil {
		return nil, err
	}

	report := &CheckpointReport{Checkpoints: len(external)}

	storedBySeq := make(map[int64]Checkpoint, len(stored))
	for _, cp := range stored {
		storedBySeq[cp.Seq] = cp
	}
	externalBySeq := make(map[int64]Checkpoint, len(external))
	for _, cp := range external {
		externalBySeq[cp.Seq] = cp
	}
	for _, cp := range stored {
		if _, ok := externalBySeq[cp.Seq]; !ok {
			report.Faults = append(report.Faults, Fault{
				Kind: FaultCheckpointGap, Seq: cp.Seq,
				Detail: "checkpoint is in the database but was never delivered to the sink",
			})
		}
	}

	var prev [32]byte
	expected := int64(1)
	for _, cp := range external {
		if cp.Seq != expected {
			report.Faults = append(report.Faults, Fault{
				Kind: FaultCheckpointGap, Seq: cp.Seq,
				Detail: fmt.Sprintf("expected checkpoint %d", expected),
			})
			// The link check below is deliberately left to run: the missing
			// checkpoint also breaks the chain, and reporting both is what
			// tells an operator whether the checkpoint was lost or never
			// written.
		}
		// Adopt the observed sequence so one gap does not report every later
		// checkpoint as misnumbered too.
		expected = cp.Seq + 1

		if !bytes.Equal(cp.PrevHash[:], prev[:]) {
			report.Faults = append(report.Faults, Fault{
				Kind: FaultCheckpointChain, Seq: cp.Seq,
				Detail: fmt.Sprintf("prev_hash %x, chain says %x", cp.PrevHash, prev),
			})
		}
		prev = cp.HeadsHash

		if verifier != nil {
			if err := verifier.Verify(cp); err != nil {
				report.Faults = append(report.Faults, Fault{
					Kind: FaultCheckpointSignature, Seq: cp.Seq, Detail: err.Error(),
				})
			}
		}

		if dbCP, ok := storedBySeq[cp.Seq]; ok && !bytes.Equal(dbCP.HeadsHash[:], cp.HeadsHash[:]) {
			report.Faults = append(report.Faults, Fault{
				Kind: FaultCheckpointChain, Seq: cp.Seq,
				Detail: "the database copy of this checkpoint disagrees with the sink copy",
			})
		}

		for _, head := range cp.Heads {
			var hash []byte
			err := c.store.pool.QueryRow(ctx,
				`SELECT hash FROM audit_log WHERE writer_id = $1 AND seq = $2`,
				head.WriterID, head.Seq).Scan(&hash)
			if errors.Is(err, pgx.ErrNoRows) {
				report.Faults = append(report.Faults, Fault{
					Kind: FaultMissingRow, WriterID: head.WriterID, Seq: head.Seq,
					Detail: fmt.Sprintf("checkpoint %d signed this row but the log no longer has it", cp.Seq),
				})
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("store: read checkpointed row: %w", err)
			}
			if !bytes.Equal(hash, head.Hash[:]) {
				report.Faults = append(report.Faults, Fault{
					Kind: FaultHeadMismatch, WriterID: head.WriterID, Seq: head.Seq,
					Detail: fmt.Sprintf("checkpoint %d signed hash %x, the log now has %x", cp.Seq, head.Hash, hash),
				})
			}
		}
	}
	return report, nil
}
