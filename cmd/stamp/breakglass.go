package main

// breakglass.go is the operator-facing half of the offline recovery procedure.
//
// It is a subcommand rather than a flag on the server because it is not a way
// of starting the service: it connects to the database, resets governance to
// solo-admin mode, prints a fresh bootstrap token and exits. The mechanism —
// including the refusal to run while the service is up, and the highest-severity
// audit row that lands in the same transaction as the reset — lives in the
// governance package, where it can be exercised against a real database.
//
// The command is deliberately noisy and deliberately awkward. It requires the
// operator's name and a written reason, both of which go into the audit chain
// verbatim, and it will not run without an explicit confirmation flag. None of
// that is a security control; the liveness check and the audit row are. It is
// there so that nobody runs this by reflex.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// breakglassCommand is the subcommand name.
const breakglassCommand = "breakglass"

// breakglassTimeout bounds the whole procedure. It is short: everything it does
// is one transaction against a database that, by the time it runs, nothing else
// is talking to.
const breakglassTimeout = 30 * time.Second

func runBreakglass(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet(breakglassCommand, flag.ContinueOnError)
	fs.SetOutput(out)
	dsn := fs.String("dsn", os.Getenv("STAMP_DSN"), "PostgreSQL connection string (defaults to $STAMP_DSN)")
	addrs := fs.String("addr", "",
		"comma-separated listen addresses to probe; the run is refused if any is already bound")
	actor := fs.String("actor", "", "who is running this — recorded in the audit chain")
	reason := fs.String("reason", "", "why this is being run — recorded in the audit chain")
	instance := fs.String("instance", defaultInstance(), "host identifier for the audit writer claim")
	confirm := fs.Bool("confirm", false,
		"required: acknowledge that this resets governance to solo-admin mode")
	if err := fs.Parse(args); err != nil {
		return err
	}

	switch {
	case *dsn == "":
		return errors.New("breakglass: --dsn is required (or set STAMP_DSN)")
	case *actor == "":
		return errors.New("breakglass: --actor is required; a governance reset with no name on it is a reset nobody answers for")
	case *reason == "":
		return errors.New("breakglass: --reason is required and is recorded in the audit chain verbatim")
	case !*confirm:
		return errors.New("breakglass: refusing to run without --confirm; this resets governance to solo-admin mode " +
			"and issues a new bootstrap token")
	}

	ctx, cancel := context.WithTimeout(ctx, breakglassTimeout)
	defer cancel()

	s, err := store.Open(ctx, store.Config{DSN: *dsn, MaxConns: 4})
	if err != nil {
		return err
	}
	defer s.Close()

	result, err := revision.BreakGlass(ctx, revision.BreakGlassConfig{
		Store:     s,
		Instance:  *instance,
		Actor:     *actor,
		Reason:    *reason,
		Addresses: splitAddresses(*addrs),
	})
	if err != nil {
		if errors.Is(err, revision.ErrListenersRunning) {
			return fmt.Errorf("%w\n\nstop every stamp process against this database and run it again", err)
		}
		return err
	}

	// The token is printed and never stored in readable form. This is the only
	// time it is shown.
	_, _ = fmt.Fprintf(out, "governance has been reset to solo-admin mode.\n")
	_, _ = fmt.Fprintf(out, "  reserved policy version: %d\n", result.PolicyVersion)
	_, _ = fmt.Fprintf(out, "  audit record:            %s/%d (severity %s)\n",
		revision.DefaultBreakGlassWriter, result.AuditSeq, revision.SeverityCritical)
	_, _ = fmt.Fprintf(out, "\nbootstrap token (shown once):\n\n    %s\n\n", result.Token)
	_, _ = fmt.Fprintf(out, "lock governance again as soon as the incident is over; an unused token "+
		"raises a %s audit warning on a timer.\n", revision.SeverityCritical)
	return nil
}

func splitAddresses(spec string) []string {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	parts := strings.Split(spec, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func defaultInstance() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "unknown"
	}
	return host
}
