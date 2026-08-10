// Command stamp is the single entrypoint for every STAMP deployment
// topology. Which subsystems run is decided by --roles, not by which binary
// was built.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/d0lim/stamp/internal/runtime"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const shutdownGrace = 15 * time.Second

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "stamp: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, logOut *os.File) error {
	fs := flag.NewFlagSet("stamp", flag.ContinueOnError)
	rolesSpec := fs.String("roles", runtime.RoleAll,
		"comma-separated subsystems to run, or \"all\" (check,decide,consumer,api,console)")
	addr := fs.String("addr", ":8080", "address the HTTP listener binds to")
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
	set, err := runtime.ParseRoles(*rolesSpec)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(logOut, nil))
	registry := runtime.Default()
	logger.Info("starting",
		slog.String("version", version),
		slog.String("roles", set.String()),
		slog.Any("components", registry.ActiveNames(set)),
		slog.String("addr", *addr),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           registry.Handler(set),
		ReadHeaderTimeout: 10 * time.Second,
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 1+len(registry.Runners(set)))

	for _, c := range registry.Runners(set) {
		wg.Add(1)
		go func(c runtime.Component) {
			defer wg.Done()
			logger.Info("runner started", slog.String("component", c.Name))
			if err := c.Run(ctx); err != nil {
				errCh <- fmt.Errorf("component %s: %w", c.Name, err)
			}
		}(c)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http listener: %w", err)
		}
	}()

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case runErr = <-errCh:
		logger.Error("subsystem failed", slog.String("error", runErr.Error()))
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("listener shutdown", slog.String("error", err.Error()))
		if runErr == nil {
			runErr = err
		}
	}
	wg.Wait()
	logger.Info("stopped")
	return runErr
}
