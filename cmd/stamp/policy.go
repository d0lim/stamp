package main

// policy.go is the file authoring path's command line: apply a directory,
// export the effective set into one, and lock governance.
//
// It talks to the API rather than to the database. That is the whole shape of
// D10 at the command line — git carries the desired state and the engine holds
// the effective state, so a CLI that wrote policies straight into Postgres
// would be a second authoring path with no governance in front of it. The one
// command here that does touch the database directly is in breakglass.go, and
// it is a subcommand precisely because it is the exception.
//
// Apply returns a proposal identifier and exits (R46). Governance is
// asynchronous — the quorum may be a day away — so "applied" is not something
// this command can report synchronously without lying. --wait is the opt-in,
// and it reports the outcome in the exit code so that a CI step can branch on
// it without parsing anything.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/policy/revision"
)

// policyCommand is the subcommand name.
const policyCommand = "policy"

// The exit codes an apply resolves to.
//
// They are a contract with whatever runs this in CI, so they are declared here
// rather than returned as literals: a pipeline that treats "rejected" and
// "timed out" the same is a pipeline that reports a refused policy change as an
// infrastructure flake.
const (
	// exitFailure is any refusal, usage error or transport failure.
	exitFailure = 1
	// exitRejected is a revision the governance decision refused.
	exitRejected = 3
	// exitReleased is a revision withdrawn or superseded while waiting.
	exitReleased = 4
	// exitTimeout is --wait giving up with the revision still pending. The
	// revision is still open; this says nothing about whether it will pass.
	exitTimeout = 5
)

// exitError carries an exit code out of a subcommand.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// exitCodeOf reports the code a failure should exit with.
func exitCodeOf(err error) int {
	var coded *exitError
	if errors.As(err, &coded) {
		return coded.code
	}
	return exitFailure
}

// defaultWaitTimeout bounds --wait when the caller names none. It is well under
// the default pending lifetime: a CI step that blocks for a day is a CI step
// somebody kills.
const defaultWaitTimeout = 15 * time.Minute

// defaultPollInterval is how often --wait asks. Revisions resolve on human
// timescales, so this is polite rather than fast.
const defaultPollInterval = 2 * time.Second

func runPolicy(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "apply":
		return runPolicyApply(ctx, args[1:], out)
	case "export":
		return runPolicyExport(ctx, args[1:], out)
	case "lock":
		return runPolicyLock(ctx, args[1:], out, os.Stdin)
	default:
		return usage()
	}
}

func usage() error {
	return errors.New("policy: expected one of \"apply\", \"export\" or \"lock\"\n\n" +
		"  stamp policy apply  --dir DIR [--wait]   propose the directory as the desired state\n" +
		"  stamp policy export --dir DIR            write the effective policy set out\n" +
		"  stamp policy lock   --threshold N ...    install quorum governance, once")
}

// client is the API connection every subcommand shares.
type client struct {
	base      string
	token     string
	bootstrap string
	http      *http.Client
	out       io.Writer
}

// bindClient adds the connection flags to a flag set.
func bindClient(fs *flag.FlagSet, out io.Writer) func() (*client, error) {
	base := fs.String("api", os.Getenv("STAMP_API"),
		"base URL of the STAMP console API (defaults to $STAMP_API)")
	token := fs.String("token", os.Getenv("STAMP_TOKEN"),
		"end-user access token (defaults to $STAMP_TOKEN)")
	bootstrap := fs.String("bootstrap-token", os.Getenv("STAMP_BOOTSTRAP_TOKEN"),
		"one-time bootstrap token, required before governance is locked "+
			"(defaults to $STAMP_BOOTSTRAP_TOKEN)")
	timeout := fs.Duration("request-timeout", 30*time.Second, "timeout for one API request")
	return func() (*client, error) {
		if strings.TrimSpace(*base) == "" {
			return nil, errors.New("policy: --api is required (or set STAMP_API)")
		}
		if _, err := url.Parse(*base); err != nil {
			return nil, fmt.Errorf("policy: --api is not a URL: %w", err)
		}
		if strings.TrimSpace(*token) == "" {
			// A policy change is attributed to a person. There is no anonymous
			// authoring path, so a missing token is a usage error rather than a
			// request that will come back 401.
			return nil, errors.New("policy: --token is required (or set STAMP_TOKEN); " +
				"policy authoring is always attributed to a caller")
		}
		return &client{
			base:      strings.TrimSuffix(*base, "/"),
			token:     *token,
			bootstrap: *bootstrap,
			http:      &http.Client{Timeout: *timeout},
			out:       out,
		}, nil
	}
}

// apiError is a refusal the API returned.
type apiError struct {
	status  int
	code    string
	message string
	pending *revision.PendingRevision
}

func (e *apiError) Error() string {
	if e.pending != nil {
		return fmt.Sprintf("revision %s from the %s path is open with %d of %d approvals collected — "+
			"withdraw it, wait for it, or let the pending lifetime expire",
			e.pending.ID, e.pending.Origin, e.pending.Collected, e.pending.Threshold)
	}
	if e.message != "" {
		return fmt.Sprintf("%s (%s)", e.message, e.code)
	}
	return fmt.Sprintf("the API answered %d", e.status)
}

func (c *client) do(ctx context.Context, method, path string, body any, into any) error {
	var reader io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("policy: encode the request: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return fmt.Errorf("policy: build the request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.bootstrap != "" {
		req.Header.Set(api.BootstrapTokenHeader, c.bootstrap)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("policy: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("policy: read the response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return decodeAPIError(resp.StatusCode, raw)
	}
	if into == nil {
		return nil
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("policy: decode the response: %w", err)
	}
	return nil
}

func decodeAPIError(status int, raw []byte) error {
	out := &apiError{status: status}
	var pending api.PendingRevisionResponse
	if err := json.Unmarshal(raw, &pending); err == nil && pending.Pending.ID != "" {
		out.code, out.message, out.pending = pending.Error, pending.Message, &pending.Pending
		return out
	}
	var body api.ErrorResponse
	if err := json.Unmarshal(raw, &body); err == nil {
		out.code, out.message = body.Error, body.Message
	}
	return out
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

func runPolicyApply(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("policy apply", flag.ContinueOnError)
	fs.SetOutput(out)
	connect := bindClient(fs, out)
	dir := fs.String("dir", ".", "directory holding the desired state")
	mode := fs.String("mode", "", "how open decisions are treated: revaluate (default) or grandfather")
	wait := fs.Bool("wait", false,
		"block until the revision resolves and report the outcome in the exit code")
	timeout := fs.Duration("timeout", defaultWaitTimeout, "how long --wait blocks before giving up")
	poll := fs.Duration("poll", defaultPollInterval, "how often --wait asks whether the revision resolved")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := connect()
	if err != nil {
		return err
	}

	payload, err := revision.ReadDir(*dir)
	if err != nil {
		return err
	}
	var result revision.FileApplyResult
	if err := c.do(ctx, http.MethodPost, api.PolicyApplyPath, api.ApplyRequest{
		Documents: payload.Documents,
		Mode:      decision.ApplicationMode(*mode),
	}, &result); err != nil {
		return err
	}

	if result.NoChange {
		_, _ = fmt.Fprintf(c.out, "no change: %s already describes the policy set in force\n", *dir)
		return nil
	}
	for _, id := range result.Adopted {
		_, _ = fmt.Fprintf(c.out, "adopting %s from the console authoring path\n", id)
	}
	_, _ = fmt.Fprintf(c.out, "revision %s proposed (%d change(s), %s)\n",
		result.Proposal.ID, result.Proposal.Delta.Len(), weakeningLabel(result.Proposal.Weakening))
	if result.Proposal.State == revision.StateApplied {
		_, _ = fmt.Fprintf(c.out, "revision %s is in force\n", result.Proposal.ID)
		return nil
	}
	_, _ = fmt.Fprintf(c.out, "  approvals required: %d\n", result.Proposal.Threshold)
	if !*wait {
		// The default. R46: a proposal identifier and an exit, because
		// governance is asynchronous and "applied" is not a synchronous answer.
		return nil
	}
	return c.waitFor(ctx, result.Proposal.ID, *timeout, *poll)
}

// waitFor blocks until the revision leaves the pending state.
func (c *client) waitFor(ctx context.Context, id string, timeout, poll time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var proposal revision.Proposal
		path := strings.Replace(api.RevisionReadPattern, "GET ", "", 1)
		path = strings.Replace(path, "{id}", url.PathEscape(id), 1)
		if err := c.do(ctx, http.MethodGet, path, nil, &proposal); err != nil {
			return err
		}
		switch proposal.State {
		case revision.StateApplied:
			_, _ = fmt.Fprintf(c.out, "revision %s is in force\n", id)
			return nil
		case revision.StateRejected:
			return &exitError{code: exitRejected,
				err: fmt.Errorf("revision %s was rejected", id)}
		case revision.StateWithdrawn, revision.StateSuperseded:
			return &exitError{code: exitReleased,
				err: fmt.Errorf("revision %s was %s before it resolved", id, proposal.State)}
		}
		if !time.Now().Before(deadline) {
			return &exitError{code: exitTimeout,
				err: fmt.Errorf("revision %s is still open after %s; it has not been rejected", id, timeout)}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

func weakeningLabel(weakening bool) string {
	if weakening {
		return "weakening"
	}
	return "not weakening"
}

// ---------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------

func runPolicyExport(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("policy export", flag.ContinueOnError)
	fs.SetOutput(out)
	connect := bindClient(fs, out)
	dir := fs.String("dir", "", "directory to write the policy set into (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*dir) == "" {
		return errors.New("policy export: --dir is required")
	}
	c, err := connect()
	if err != nil {
		return err
	}

	var export revision.Export
	if err := c.do(ctx, http.MethodGet, api.PolicyExportPath, nil, &export); err != nil {
		return err
	}
	for _, f := range export.Files {
		target := filepath.Join(*dir, filepath.FromSlash(f.Name))
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(*dir)) {
			// The names come from the server. A path that climbed out of the
			// target directory would be a write the operator did not ask for,
			// so it is refused rather than sanitized.
			return fmt.Errorf("policy export: the server named a file outside %s: %s", *dir, f.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return fmt.Errorf("policy export: create %s: %w", filepath.Dir(target), err)
		}
		if err := os.WriteFile(target, []byte(f.Content), 0o600); err != nil {
			return fmt.Errorf("policy export: write %s: %w", target, err)
		}
	}
	_, _ = fmt.Fprintf(c.out, "wrote %d policies and the schema to %s\n", export.PolicyCount, *dir)
	_, _ = fmt.Fprintf(c.out, "applying this directory unchanged proposes no revision\n")
	return nil
}

// ---------------------------------------------------------------------------
// lock
// ---------------------------------------------------------------------------

func runPolicyLock(ctx context.Context, args []string, out io.Writer, in io.Reader) error {
	fs := flag.NewFlagSet("policy lock", flag.ContinueOnError)
	fs.SetOutput(out)
	connect := bindClient(fs, out)
	threshold := fs.Int("threshold", 0, "how many approvals a governance revision needs")
	approvers := fs.String("approvers", "", "comma-separated approver identities")
	claim := fs.String("claim", "", "token claim naming the approvers, instead of a list")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *threshold <= 0 {
		return errors.New("policy lock: --threshold must be at least 1")
	}
	members := splitAddresses(*approvers)
	if len(members) == 0 && *claim == "" {
		return errors.New("policy lock: name the approvers with --approvers or --claim")
	}
	c, err := connect()
	if err != nil {
		return err
	}

	// The resolved set is printed before anything is sent. The lock cannot be
	// undone from inside the running system, so the operator confirms what they
	// are installing rather than what they typed.
	_, _ = fmt.Fprintf(c.out, "locking governance on %s\n", c.base)
	_, _ = fmt.Fprintf(c.out, "  approvals required: %d\n", *threshold)
	if len(members) > 0 {
		_, _ = fmt.Fprintf(c.out, "  approvers:          %s\n", strings.Join(members, ", "))
		if *threshold > len(members) {
			return fmt.Errorf("policy lock: %d approvals cannot be collected from %d approvers",
				*threshold, len(members))
		}
	}
	if *claim != "" {
		_, _ = fmt.Fprintf(c.out, "  approver claim:     %s\n", *claim)
	}
	_, _ = fmt.Fprintf(c.out, "\nthis cannot be undone from inside the running system; "+
		"recovery afterwards is the offline break-glass procedure.\n")
	if !*yes {
		_, _ = fmt.Fprintf(c.out, "type \"lock\" to continue: ")
		reader := bufio.NewReader(in)
		answer, _ := reader.ReadString('\n')
		if strings.TrimSpace(answer) != "lock" {
			return errors.New("policy lock: not confirmed")
		}
	}

	var result map[string]string
	if err := c.do(ctx, http.MethodPost, "/governance/lock", api.LockRequest{
		Threshold: *threshold,
		Approvers: members,
		Claim:     *claim,
	}, &result); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(c.out, "governance is %s; the bootstrap token is spent\n", result["mode"])
	return nil
}
