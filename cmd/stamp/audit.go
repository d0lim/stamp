package main

// audit.go is the operator-facing half of R32: the command that checks the
// audit log against itself and against the signed checkpoints held outside the
// database.
//
// It talks to the database directly, like breakglass and unlike policy. That is
// not an inconsistency: the thing being verified is the storage, and a
// verification that went through the running service would be asking the
// process that wrote the log whether the log is correct. An auditor runs this
// with a read-only DSN and a public key, and needs nothing else from the
// deployment.
//
// The exit codes are the contract. Everything in this file exists to keep four
// outcomes distinguishable to a CI step that reads no output at all:
//
//	0  verification ran over at least one checkpoint and everything agrees
//	1  the command was used wrong, or configured wrong, and never looked
//	6  verification ran and the log and the checkpoints do not agree
//	7  verification ran and could not reach a verdict
//
// The one that has to be got right is the last. "There is nothing to verify" is
// not "there is nothing wrong": a deployment that never published a checkpoint,
// a sink someone deleted, a key that was rotated out and never kept — each of
// those produces zero faults, and each of them means the audit trail is
// currently unverifiable. Reporting them as a pass is how a control that
// stopped working goes unnoticed for a year, so none of them is allowed to
// reach exit 0.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/runtime"
	"github.com/d0lim/stamp/internal/store"
)

// auditCommand is the subcommand name.
const auditCommand = "audit"

// The exit codes audit verification resolves to.
//
// They continue the table in policy.go rather than restarting it: one binary
// returns all of them, and a number that means "revision rejected" from one
// subcommand and "chain broken" from another is a number nobody can write a
// pipeline against.
const (
	// exitChainBroken is a verdict: the chain, or the checkpoints over it, do
	// not add up. Something modified, removed or rewrote audit history, or a
	// checkpoint was forged or lost.
	exitChainBroken = 6
	// exitUnverifiable is the absence of a verdict. The command ran, was
	// configured correctly, and could not establish either result — including
	// the case where there was nothing to verify at all.
	exitUnverifiable = 7
)

// auditVerifyTimeout bounds the whole verification. Re-chaining a large log is
// the slow part, and it is a full table scan rather than anything unbounded.
const auditVerifyTimeout = 10 * time.Minute

func runAudit(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return auditUsage()
	}
	switch args[0] {
	case "verify":
		return runAuditVerify(ctx, args[1:], out)
	default:
		return auditUsage()
	}
}

func auditUsage() error {
	return errors.New("audit: expected \"verify\"\n\n" +
		"  stamp audit verify --dsn DSN    re-chain the audit log and check it against the signed checkpoints")
}

// verifyInputs is what verification needs before it can start.
type verifyInputs struct {
	dsn      string
	sinkPath string
	keys     runtime.CheckpointVerification
}

func runAuditVerify(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(out)
	dsn := fs.String("dsn", os.Getenv(runtime.EnvDSN), "PostgreSQL connection string (defaults to $STAMP_DSN)")
	sink := fs.String("sink", "",
		"checkpoint file to verify against (defaults to $"+runtime.EnvCheckpointSinkFile+")")
	timeout := fs.Duration("timeout", auditVerifyTimeout, "how long the whole verification may take")
	if err := fs.Parse(args); err != nil {
		return err
	}

	in, err := auditVerifyInputs(*dsn, *sink)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	// A connection failure is not a usage error and it is not a fault: the
	// command was configured correctly and could not look.
	s, err := store.Open(ctx, store.Config{DSN: in.dsn, MaxConns: 4})
	if err != nil {
		return &exitError{code: exitUnverifiable, err: fmt.Errorf("audit verify: %w", err)}
	}
	defer s.Close()

	// The sink is read, never created. [store.NewFileSink] opens the file for
	// append and would happily bring an empty one into existence, which on a
	// mistyped path turns "that file does not exist" into "there is nothing to
	// verify" — a true statement about the wrong file.
	if _, err := os.Stat(in.sinkPath); err != nil {
		return &exitError{code: exitUnverifiable, err: fmt.Errorf(
			"audit verify: the checkpoint sink cannot be read: %w", err)}
	}
	fileSink, err := store.NewFileSink(in.sinkPath)
	if err != nil {
		return &exitError{code: exitUnverifiable, err: fmt.Errorf("audit verify: %w", err)}
	}

	chain, err := s.VerifyChain(ctx)
	if err != nil {
		return &exitError{code: exitUnverifiable, err: fmt.Errorf("audit verify: %w", err)}
	}
	// The signer is nil because verification never signs. It reads the sink,
	// reads the database and compares the two against the public keys.
	checkpoints, err := s.Checkpointer(nil, fileSink).VerifyCheckpoints(ctx, in.keys.Verifier)
	if err != nil {
		return &exitError{code: exitUnverifiable, err: fmt.Errorf("audit verify: %w", err)}
	}
	held, err := fileSink.Checkpoints(ctx)
	if err != nil {
		return &exitError{code: exitUnverifiable, err: fmt.Errorf("audit verify: %w", err)}
	}

	return reportVerification(out, in, chain, checkpoints, held)
}

// auditVerifyInputs resolves the configuration verification needs, and refuses
// with the code that says which kind of problem it is.
func auditVerifyInputs(dsn, sinkOverride string) (verifyInputs, error) {
	cfg, err := runtime.CheckpointConfigFromEnv()
	if err != nil {
		return verifyInputs{}, fmt.Errorf("audit verify: %w", err)
	}
	if strings.TrimSpace(sinkOverride) != "" {
		// An auditor verifying a copy of the sink that was shipped to them,
		// against a read-only replica. The file is the evidence; where it sits
		// on their disk is not deployment configuration.
		cfg.SinkFile = strings.TrimSpace(sinkOverride)
	}
	if strings.TrimSpace(dsn) == "" {
		return verifyInputs{}, errors.New("audit verify: --dsn is required (or set " + runtime.EnvDSN + ")")
	}

	// A bad key file is a configuration error and exits 1: the command never
	// got as far as the audit trail, and reporting it as "could not verify"
	// would tell a pipeline to go look at the log when the thing to look at is
	// the manifest.
	keys, err := runtime.LoadCheckpointVerification(cfg)
	if err != nil {
		return verifyInputs{}, fmt.Errorf("audit verify: %w", err)
	}

	if strings.TrimSpace(cfg.SinkFile) == "" {
		return verifyInputs{}, &exitError{code: exitUnverifiable, err: fmt.Errorf(
			"audit verify: no readable checkpoint sink is configured, so the log can only be checked "+
				"against itself — and a rewritten log agrees with itself. set %s or pass --sink",
			runtime.EnvCheckpointSinkFile)}
	}
	if len(keys.KeyIDs) == 0 {
		return verifyInputs{}, &exitError{code: exitUnverifiable, err: fmt.Errorf(
			"audit verify: no checkpoint verification key is configured, so no signature can be checked. "+
				"set %s to key-id=/path/to/public-key.pem, or %s where the signing key is held",
			runtime.EnvCheckpointVerifyKeys, runtime.EnvCheckpointKeyFile)}
	}
	return verifyInputs{dsn: dsn, sinkPath: cfg.SinkFile, keys: keys}, nil
}

// reportVerification prints what was found and resolves it to an exit code.
//
// The order of the decisions is the contract. Faults that stand on their own
// are reported as faults even when part of the series could not be verified —
// a head that does not match its signed value is evidence whatever else is
// missing. Everything that leaves the verdict incomplete comes after, and the
// empty sink comes last because it is the case most likely to be mistaken for
// success.
func reportVerification(out io.Writer, in verifyInputs,
	chain *store.ChainReport, checkpoints *store.CheckpointReport, held []store.Checkpoint,
) error {
	_, _ = fmt.Fprintf(out, "audit chain: %d rows across %d segment(s)\n", chain.Rows, len(chain.Segments))
	for _, seg := range chain.Segments {
		_, _ = fmt.Fprintf(out, "  %-24s %d rows, head at seq %d\n", seg.WriterID, seg.Rows, seg.HeadSeq)
	}
	_, _ = fmt.Fprintf(out, "checkpoints: %d in %s, verified under %s\n",
		checkpoints.Checkpoints, in.sinkPath, strings.Join(in.keys.KeyIDs, ", "))

	unknown := unknownKeyIDs(held, in.keys)
	standing := standingFaults(checkpoints.Faults, held, in.keys)

	printFaults(out, "chain", chain.Faults)
	printFaults(out, "checkpoint", checkpoints.Faults)

	switch {
	case len(chain.Faults) > 0 || len(standing) > 0:
		if len(unknown) > 0 {
			_, _ = fmt.Fprintf(out, "\nalso: %d checkpoint(s) are signed under %s, which no configured "+
				"public key covers, so those were not verified either way\n",
				len(unknown), strings.Join(unknown, ", "))
		}
		return &exitError{code: exitChainBroken, err: fmt.Errorf(
			"audit verify: %d chain fault(s) and %d checkpoint fault(s); the audit trail does not "+
				"agree with what was signed", len(chain.Faults), len(checkpoints.Faults))}

	case len(unknown) > 0:
		// Not a failure and emphatically not a pass. Retiring a signing key
		// without keeping its public half is how a series stops being
		// verifiable, quietly, at the moment it is rotated.
		return &exitError{code: exitUnverifiable, err: fmt.Errorf(
			"audit verify: %d checkpoint(s) are signed under %s and no configured public key covers "+
				"them, so the series was not verified. a retired key's public half has to stay in %s "+
				"for the checkpoints it signed to remain verifiable",
			len(unknown), strings.Join(unknown, ", "), runtime.EnvCheckpointVerifyKeys)}

	case checkpoints.Checkpoints == 0:
		// The trap this whole file is arranged around. Nothing was checked, so
		// nothing was wrong; those are not the same sentence.
		return &exitError{code: exitUnverifiable, err: fmt.Errorf(
			"audit verify: %s holds no checkpoints, so nothing was verified. an empty sink is not a "+
				"clean audit trail — it is a deployment that has published no signed head for the log "+
				"to be checked against", in.sinkPath)}
	}

	_, _ = fmt.Fprintf(out, "\nno faults: %d rows re-chain, and %d checkpoint(s) match the log they signed\n",
		chain.Rows, checkpoints.Checkpoints)
	return nil
}

func printFaults(out io.Writer, label string, faults []store.Fault) {
	if len(faults) == 0 {
		return
	}
	_, _ = fmt.Fprintf(out, "\n%d %s fault(s):\n", len(faults), label)
	for _, f := range faults {
		_, _ = fmt.Fprintf(out, "  %s\n", f)
	}
}

// unknownKeyIDs reports the key identifiers the sink's checkpoints name and the
// configured keys do not cover, sorted.
func unknownKeyIDs(held []store.Checkpoint, keys runtime.CheckpointVerification) []string {
	seen := map[string]struct{}{}
	for _, cp := range held {
		if !keys.Covers(cp.KeyID) {
			seen[cp.KeyID] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// standingFaults drops the signature faults that only say "this key is not
// configured here".
//
// [store.CheckpointVerifier] reports an unconfigured key as a verification
// error, which is right for a library: it did not verify. At this layer it is
// the difference between "somebody forged a checkpoint" and "you are missing a
// public key", and reporting the second as the first is how an operator learns
// to ignore the alarm that means tampering.
func standingFaults(faults []store.Fault, held []store.Checkpoint,
	keys runtime.CheckpointVerification,
) []store.Fault {
	uncovered := map[int64]struct{}{}
	for _, cp := range held {
		if !keys.Covers(cp.KeyID) {
			uncovered[cp.Seq] = struct{}{}
		}
	}
	out := make([]store.Fault, 0, len(faults))
	for _, f := range faults {
		if f.Kind == store.FaultCheckpointSignature {
			if _, skip := uncovered[f.Seq]; skip {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}
