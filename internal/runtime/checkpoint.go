package runtime

// checkpoint.go is the audit chain's tamper-evidence half at the composition
// root: it loads the signing key from the file it is mounted at, opens the
// sinks, and runs the loop that signs every writer's head on a timer.
//
// Two things here are decisions rather than assembly.
//
// The key never becomes a value in this process's configuration. It is read
// from a path, turned into a signer, and from then on the only thing anything
// else can ask about it is its identifier (R42). There is no field, no
// environment variable and no log line through which the bytes could travel.
//
// The loop repairs before it records. [store.Checkpointer.Checkpoint] writes
// the database row first and publishes second — deliberately, so that a failed
// delivery is loud rather than silent — which leaves the database holding a
// checkpoint the sink does not have. Verification reports that as a gap, and
// without a repair it reports it forever, so an operator learns to read a
// standing gap as normal. Syncing at the head of each tick is what keeps a gap
// meaning what it says.

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/store"
)

// checkpointPlane is this process's checkpoint subsystem: the checkpointer over
// every configured sink, the repair path over the one that can be read back,
// and the interval the loop runs on.
//
// It is nil on a deployment that configured none, which is the state the
// startup warning is about.
type checkpointPlane struct {
	checkpointer *store.Checkpointer
	// repairer is the checkpointer over the readable sink alone. Republishing
	// is only meaningful for a sink whose contents can be compared against the
	// database, and a webhook's cannot: this process has no way to know what
	// the far end kept, so replaying to it would be a delivery decision made on
	// no evidence.
	repairer *store.Checkpointer
	keyID    string
	interval time.Duration
	// destination is where checkpoints go, for the startup log. It names paths
	// and endpoints, never keys.
	destination string
}

// CheckpointVerification is the verification half of the checkpoint
// configuration: the public keys, by identifier.
//
// The identifiers travel with the verifier because "this checkpoint names a key
// I do not have" and "this checkpoint does not verify" are different answers,
// and only a caller holding both can tell them apart. [store.CheckpointVerifier]
// reports the first as a verification error, which is correct for a library and
// wrong for an exit code.
type CheckpointVerification struct {
	Verifier *store.CheckpointVerifier
	// KeyIDs are the identifiers the verifier holds a public key for, sorted.
	KeyIDs []string
}

// Covers reports whether a checkpoint signed under keyID could be verified at
// all.
func (v CheckpointVerification) Covers(keyID string) bool {
	for _, id := range v.KeyIDs {
		if id == keyID {
			return true
		}
	}
	return false
}

// LoadCheckpointSigner reads the signing key from the file it is mounted at.
//
// The failures name the path and never the contents. A key file that is the
// wrong kind of key, or not a key at all, is an operator mistake that has to be
// readable from a container log — and a container log is exactly the place the
// bytes of a signing key must never appear, including inside an error.
func LoadCheckpointSigner(cfg CheckpointConfig) (*store.CheckpointSigner, error) {
	path := strings.TrimSpace(cfg.KeyFile)
	if path == "" {
		return nil, fmt.Errorf("no checkpoint signing key is configured (%s)", EnvCheckpointKeyFile)
	}
	// An operator-configured mount path, and the only way a key gets in.
	raw, err := os.ReadFile(path) //nolint:gosec // an operator-supplied key mount path
	if err != nil {
		return nil, fmt.Errorf("read the checkpoint signing key: %w", err)
	}
	priv, err := parseEd25519PrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%s (%s): %w", path, EnvCheckpointKeyFile, err)
	}
	return store.NewCheckpointSigner(strings.TrimSpace(cfg.KeyID), priv)
}

// LoadCheckpointVerification builds the verifier from the configured public
// keys and, when this host holds the signing key, from that key's own public
// half.
//
// Deriving the active key rather than asking for it twice removes the failure
// where an operator rotates the signing key, forgets to update its public half,
// and gets a deployment that signs checkpoints nothing can verify — including
// itself. What an operator does have to keep is the *retired* halves, and that
// is the one thing rotation genuinely requires of them.
func LoadCheckpointVerification(cfg CheckpointConfig) (CheckpointVerification, error) {
	keys := make(map[string]ed25519.PublicKey, len(cfg.VerifyKeys)+1)
	for id, path := range cfg.VerifyKeys {
		raw, err := os.ReadFile(path) //nolint:gosec // an operator-supplied key path
		if err != nil {
			return CheckpointVerification{}, fmt.Errorf("read the public key for %q: %w", id, err)
		}
		pub, err := parseEd25519PublicKey(raw)
		if err != nil {
			return CheckpointVerification{}, fmt.Errorf("%s (%s), key id %q: %w",
				path, EnvCheckpointVerifyKeys, id, err)
		}
		keys[id] = pub
	}

	if strings.TrimSpace(cfg.KeyFile) != "" {
		signer, err := LoadCheckpointSigner(cfg)
		if err != nil {
			return CheckpointVerification{}, err
		}
		if _, declared := keys[signer.KeyID()]; declared {
			// Two answers for the active identifier, one derived and one
			// declared. Picking either would be picking which of the operator's
			// two statements about their own key is the real one.
			return CheckpointVerification{}, fmt.Errorf(
				"%s declares a public key for %q, which is the active signing key's identifier (%s): "+
					"the active key's public half is derived from the signing key, so list retired "+
					"identifiers there and not this one",
				EnvCheckpointVerifyKeys, signer.KeyID(), EnvCheckpointKeyID)
		}
		keys[signer.KeyID()] = signer.Public()
	}

	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return CheckpointVerification{Verifier: store.NewCheckpointVerifier(keys), KeyIDs: ids}, nil
}

// parseEd25519PrivateKey reads a PEM PKCS#8 Ed25519 key.
//
// One encoding is supported on purpose. A loader that also accepted a raw seed,
// a hex string or a base64 blob would be a loader an operator could feed the
// output of `echo -n` to, and every one of those forms is a form that fits in
// an environment variable — which is the thing R42 is about.
func parseEd25519PrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("is not PEM: write one with " +
			"`openssl genpkey -algorithm ed25519 -out checkpoint.key`")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// The wrapped error is x509's and describes the structure, not the key.
		return nil, fmt.Errorf("is not a PKCS#8 private key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("holds a %T, and checkpoints are signed with an Ed25519 key", parsed)
	}
	return priv, nil
}

// parseEd25519PublicKey reads a PEM PKIX public key — what
// `openssl pkey -in checkpoint.key -pubout` writes.
func parseEd25519PublicKey(raw []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("is not PEM: write one with " +
			"`openssl pkey -in checkpoint.key -pubout -out checkpoint.pub`")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("is not a PKIX public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("holds a %T, and checkpoints are signed with an Ed25519 key", parsed)
	}
	return pub, nil
}

// checkpoints assembles the checkpoint plane, or reports why there is none.
//
// The unconfigured case is a warning and not a boot failure, which is U18's
// scenario and is the right direction for one specific reason: a deployment
// with no checkpoints still records everything it does in a hash chain, and
// refusing to start would trade a missing detection control for a missing
// service. The wording is the part that has to be got right — see the warning
// itself — because a log line that reads like a setting is worse than no log
// line at all.
func (a *App) checkpoints(gate *fact.Gate) (*checkpointPlane, error) {
	cfg := a.cfg.Checkpoint
	if !cfg.Configured() {
		a.logger.Warn(
			"audit checkpoints are not configured: this deployment publishes no signed copy of its audit "+
				"chain outside the database it stores the chain in",
			slog.String("effect", "a wholesale rewrite of the audit log re-chains cleanly and nothing "+
				"disagrees with it, and `stamp audit verify` has nothing to check the log against"),
			slog.String("this_is_not_a_setting", "the control is absent rather than relaxed: no other "+
				"setting compensates, and nothing else in this process detects a rewrite"),
			slog.String("configure", strings.Join([]string{
				EnvCheckpointKeyFile, EnvCheckpointKeyID, EnvCheckpointSinkFile,
			}, ", ")))
		return nil, nil
	}

	signer, err := LoadCheckpointSigner(cfg)
	if err != nil {
		return nil, err
	}

	var (
		sinks       []store.CheckpointSink
		readable    *store.FileSink
		destination []string
	)
	if path := strings.TrimSpace(cfg.SinkFile); path != "" {
		file, ferr := store.NewFileSink(path)
		if ferr != nil {
			return nil, ferr
		}
		sinks = append(sinks, file)
		readable = file
		destination = append(destination, "file "+path)
	}
	if endpoint := strings.TrimSpace(cfg.SinkWebhook); endpoint != "" {
		// Same gate as every other outbound call this process makes. A
		// checkpoint destination is operator configuration and never reaches
		// here from a policy, but it is still egress, and a second set of rules
		// for it would be a second set of rules to keep in agreement.
		if cerr := gate.CheckURL(endpoint); cerr != nil {
			return nil, fmt.Errorf("%s: %w", EnvCheckpointSinkWebhook, cerr)
		}
		hook, herr := store.NewWebhookSink(endpoint, gate.HTTPClient())
		if herr != nil {
			return nil, herr
		}
		sinks = append(sinks, hook)
		destination = append(destination, "webhook "+endpoint)
	}

	sink := sinks[0]
	if len(sinks) > 1 {
		sink = store.MultiSink(sinks)
	}
	plane := &checkpointPlane{
		checkpointer: a.store.Checkpointer(signer, sink),
		keyID:        signer.KeyID(),
		interval:     cfg.Interval,
		destination:  strings.Join(destination, ", "),
	}
	if readable != nil {
		plane.repairer = a.store.Checkpointer(signer, readable)
	} else {
		a.logger.Warn(
			"the only audit checkpoint sink is a webhook, which cannot be read back",
			slog.String("effect", "checkpoints are delivered, and this deployment still cannot verify its "+
				"own audit chain: `stamp audit verify` compares the log against a sink it can read"),
			slog.String("configure", EnvCheckpointSinkFile))
	}
	// The key appears here as an identifier and nowhere as a value. That is the
	// whole of what a log is allowed to know about it, and it is also all an
	// operator needs to read a checkpoint file back.
	a.logger.Info("audit checkpoints are configured",
		slog.String("key_id", plane.keyID),
		slog.String("sink", plane.destination),
		slog.Duration("interval", plane.interval))
	return plane, nil
}

// runCheckpoints signs the audit chain's heads on a timer.
//
// One checkpoint is taken on the way up rather than after the first interval. A
// process that restarts more often than its interval would otherwise never
// produce one, and that is not a hypothetical shape — it is a crash loop, which
// is exactly when an operator most wants the log anchored up to the moment the
// trouble started.
func (a *App) runCheckpoints(ctx context.Context) error {
	a.checkpointOnce(ctx)

	ticker := time.NewTicker(a.checkpoint.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			a.checkpointOnce(ctx)
		}
	}
}

// checkpointOnce repairs the sink and then records a checkpoint.
//
// Failures are logged and the loop continues; they do not end the process. The
// rest of the audit machinery — the hash chain, the same-transaction writes —
// is unaffected by a sink that is full or an endpoint that is down, and taking
// a policy decision point offline because its checkpoint file could not be
// written would convert a detection gap into an outage. The next tick repairs
// what this one could not deliver, and verification reports the gap in the
// meantime, which is the whole reason the gap is a reported fault.
func (a *App) checkpointOnce(ctx context.Context) {
	plane := a.checkpoint
	if plane.repairer != nil {
		// This also carries checkpoints another process recorded into this
		// host's copy of the sink, which is what keeps a role-split deployment
		// from having as many partial sinks as it has processes.
		published, err := plane.repairer.Sync(ctx)
		switch {
		case err != nil && !errors.Is(err, context.Canceled):
			a.logger.Error("republishing missing audit checkpoints failed",
				slog.String("error", err.Error()))
		case published > 0:
			a.logger.Info("republished audit checkpoints the sink was missing",
				slog.Int("checkpoints", published))
		}
	}

	cp, err := plane.checkpointer.Checkpoint(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			a.logger.Error("recording an audit checkpoint failed",
				slog.String("key_id", plane.keyID), slog.String("error", err.Error()))
		}
		return
	}
	a.logger.Info("audit checkpoint recorded",
		slog.Int64("seq", cp.Seq),
		slog.Int("heads", len(cp.Heads)),
		slog.String("key_id", cp.KeyID))
}
