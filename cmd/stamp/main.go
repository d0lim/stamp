// Command stamp is the single entrypoint for every STAMP deployment
// topology. Which subsystems run is decided by --roles, not by which binary
// was built.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/runtime"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "stamp: %v\n", err)
		// The exit code is part of the contract for `policy apply --wait`:
		// governance refusing a revision and a network failing are different
		// events, and a CI step has to be able to branch on which one happened.
		os.Exit(exitCodeOf(err))
	}
}

func run(args []string, logOut *os.File) error {
	// Subcommands come before flag parsing. breakglass is not a way of starting
	// the service — it refuses to run while the service is up — so it must not
	// share the server's flag set or its startup path. `policy` is a client of
	// the API rather than a server at all, for the same reason.
	if len(args) > 0 && args[0] == breakglassCommand {
		return runBreakglass(context.Background(), args[1:], logOut)
	}
	if len(args) > 0 && args[0] == policyCommand {
		return runPolicy(context.Background(), args[1:], logOut)
	}

	fs := flag.NewFlagSet("stamp", flag.ContinueOnError)
	rolesSpec := fs.String("roles", runtime.RoleAll,
		"comma-separated subsystems to run, or \"all\" (check,decide,consumer,api,console)")
	// The three surfaces are three listeners rather than three path prefixes on
	// one, so each gets its own address. An empty address means the surface is
	// not listened on at all, which is how a PEP tier runs with no console
	// reachable anywhere.
	pepAddr := fs.String("pep-addr", "", "address the PEP listener binds to (overrides $"+runtime.EnvPEPAddr+")")
	consoleAddr := fs.String("console-addr", "", "address the console listener binds to (overrides $"+runtime.EnvConsoleAddr+")")
	callbackAddr := fs.String("callback-addr", "", "address the callback listener binds to (overrides $"+runtime.EnvCallbackAddr+")")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		_, _ = fmt.Fprintln(logOut, version)
		return nil
	}

	// Role parsing happens before anything is started so a bad --roles value
	// fails startup instead of silently running a subset.
	roles, err := runtime.ParseRoles(*rolesSpec)
	if err != nil {
		return err
	}

	cfg, err := runtime.ConfigFromEnv()
	if err != nil {
		return err
	}
	overrideAddr(cfg.Addresses, api.SurfacePEP, *pepAddr)
	overrideAddr(cfg.Addresses, api.SurfaceConsole, *consoleAddr)
	overrideAddr(cfg.Addresses, api.SurfaceCallback, *callbackAddr)

	logger := slog.New(slog.NewJSONHandler(logOut, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app, err := runtime.Assemble(ctx, cfg, roles, logger)
	if err != nil {
		return err
	}
	defer app.Close()

	if err := app.Listen(); err != nil {
		return err
	}

	logger.Info("starting",
		slog.String("version", version),
		slog.String("roles", roles.String()),
		slog.Any("components", app.Components()),
		slog.String("pep", app.Addr(api.SurfacePEP)),
		slog.String("console", app.Addr(api.SurfaceConsole)),
		slog.String("callback", app.Addr(api.SurfaceCallback)),
	)

	// The bootstrap token is printed here and stored nowhere in readable form.
	// This is its only appearance; a later start returns the empty string.
	if token := app.BootstrapToken(); token != "" {
		_, _ = fmt.Fprintf(logOut, "\ngovernance bootstrap token (shown once):\n\n    %s\n\n"+
			"lock governance with it as soon as the approver set is known; "+
			"an unused token raises a critical audit warning on a timer.\n\n", token)
	}

	err = app.Serve(ctx)
	logger.Info("stopped")
	return err
}

// overrideAddr applies a flag over the environment. An explicit empty flag is
// not an override — the flag is absent, not set to nothing — so unbinding a
// surface is done by setting its environment variable to the empty string.
func overrideAddr(addresses map[api.Surface]string, surface api.Surface, addr string) {
	if addr == "" || addresses == nil {
		return
	}
	addresses[surface] = addr
}
