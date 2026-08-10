package bench_test

// The benchmark harness assembles the real process: a real Postgres from a
// container, a real OIDC issuer on a socket, a real fact source upstream on
// another one, and the composition root serving its real listeners. The load
// generator speaks HTTP to the address the process bound.
//
// Nothing here is a double, because the thing R26 asks to be measured is the
// end-to-end check path. A benchmark that called the evaluator directly would
// be measuring the evaluator, and the evaluator is the part of that path this
// unit is least worried about.
//
// What the harness is not: an isolated load generator. It shares the machine
// with the process it is measuring, and the artifact says so. On a two-vCPU
// shared runner an out-of-process generator would contend for the same cores
// anyway; what a separate generator would buy is an open arrival model, and
// that is a change to make when the numbers are stable enough to be worth it.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/d0lim/stamp/bench"
	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/policy"
	stamp "github.com/d0lim/stamp/internal/runtime"
	"github.com/d0lim/stamp/internal/store"
)

const (
	postgresImage = "postgres:17-alpine"
	testAudience  = "stamp"
	testWorkload  = "pep-1"
	testKeyID     = "bench-key"
	// destAccount is the destination every request in every check scenario
	// asks about. Holding it fixed is what makes the warm and the miss
	// scenario differ in exactly one thing: whether the fact answer was
	// already cached.
	destAccount = "2002"
)

// ---------------------------------------------------------------------------
// settings
// ---------------------------------------------------------------------------

// config is the bench's own configuration, read from the environment so that
// the workflow can shrink the load for a small runner without a code change.
type config struct {
	profile     string
	outDir      string
	baseline    string
	commit      string
	concurrency int
	duration    time.Duration
	warmup      time.Duration
}

var benchCfg = func() config {
	c := config{
		profile:     envString("BENCH_PROFILE", "local"),
		outDir:      envString("BENCH_OUT", "out"),
		baseline:    envString("BENCH_BASELINE", ""),
		commit:      envString("BENCH_COMMIT", os.Getenv("GITHUB_SHA")),
		concurrency: envInt("BENCH_CONCURRENCY", 8),
		duration:    envDuration("BENCH_DURATION", 3*time.Second),
		warmup:      envDuration("BENCH_WARMUP", time.Second),
	}
	return c
}()

func envString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v, err := time.ParseDuration(os.Getenv(key))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

// ---------------------------------------------------------------------------
// the collected report
// ---------------------------------------------------------------------------

var (
	collectedMu sync.Mutex
	collected   = &bench.Report{}
)

func record(run bench.Run) {
	collectedMu.Lock()
	defer collectedMu.Unlock()
	collected.Add(run)
}

// note records something the process said about itself during a scenario.
//
// The one that matters so far is the shutdown error: under a sustained check
// load the audit writer has been seen to end a run needing a head reload after
// a chain sequence conflict, which is a fact about the audit chain rather than
// about this benchmark. It goes into the artifact and into a workflow warning
// rather than into a failed job. This unit measures; it does not own the chain,
// it cannot fix it from here, and a bench job going red on another unit's
// intermittent condition is a job people learn to ignore.
func note(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	collectedMu.Lock()
	defer collectedMu.Unlock()
	collected.Notes = append(collected.Notes, line)
	fmt.Fprintln(os.Stderr, "bench note: "+line)
}

// ---------------------------------------------------------------------------
// postgres
// ---------------------------------------------------------------------------

// postgresDSN starts the container on first use. The report's unit tests run in
// this same package's directory and must not need a Docker daemon, so nothing
// starts until a benchmark actually asks for a database.
var postgresDSN = sync.OnceValues(func() (string, error) {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase("stamp"),
		tcpostgres.WithUsername("stamp"),
		tcpostgres.WithPassword("stamp"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return "", fmt.Errorf("the benchmarks need a working Docker daemon: %w", err)
	}
	containerMu.Lock()
	container = c
	containerMu.Unlock()
	return c.ConnectionString(ctx, "sslmode=disable")
})

var (
	containerMu sync.Mutex
	container   testcontainers.Container
	dbSerial    atomic.Int64
)

func freshDB(tb testing.TB) string {
	tb.Helper()
	adminDSN, err := postgresDSN()
	if err != nil {
		tb.Fatalf("start postgres: %v", err)
	}
	name := fmt.Sprintf("b%d_%d", time.Now().UnixNano()%1e9, dbSerial.Add(1))

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		tb.Fatalf("connect to admin database: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); err != nil {
		tb.Fatalf("create database %s: %v", name, err)
	}
	cfg, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		tb.Fatalf("parse dsn: %v", err)
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.ConnConfig.User, cfg.ConnConfig.Password, cfg.ConnConfig.Host, cfg.ConnConfig.Port, name)
}

// ---------------------------------------------------------------------------
// the identity provider
// ---------------------------------------------------------------------------

var benchKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

type mockIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newMockIdP(tb testing.TB) *mockIdP {
	tb.Helper()
	m := &mockIdP{key: benchKey()}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": testKeyID,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(m.key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.key.E)).Bytes()),
		}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	m.server = httptest.NewServer(mux)
	tb.Cleanup(m.server.Close)
	return m
}

func (m *mockIdP) workload(tb testing.TB, subject string) string {
	tb.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": m.server.URL,
		"sub": subject,
		"aud": testAudience,
		"azp": testWorkload,
		"iat": now.Add(-time.Minute).Unix(),
		// The measurement window is minutes at most, and a token that expired
		// mid-run would turn a latency benchmark into a 401 benchmark.
		"exp": now.Add(2 * time.Hour).Unix(),
	}
	header := map[string]string{"alg": "RS256", "kid": testKeyID, "typ": "JWT"}
	encode := func(v any) string {
		data, err := json.Marshal(v)
		if err != nil {
			tb.Fatalf("marshal token part: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signing := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, digest[:])
	if err != nil {
		tb.Fatalf("sign token: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// ---------------------------------------------------------------------------
// the fact source upstream
// ---------------------------------------------------------------------------

// upstream is the remote a synchronous fact source calls. It answers the same
// whitelist for every account, so that a cache miss and a cache hit return the
// same decision and the two scenarios differ only in the work done to get it.
//
// It counts its calls, which is how the miss rate in the artifact is a measured
// number rather than an assumption about how the scenario was built.
type upstream struct {
	server *httptest.Server
	calls  atomic.Int64
	block  atomic.Bool
}

func newUpstream(tb testing.TB) *upstream {
	tb.Helper()
	u := &upstream{}
	mux := http.NewServeMux()
	mux.HandleFunc("/whitelist", func(w http.ResponseWriter, r *http.Request) {
		u.calls.Add(1)
		if u.block.Load() {
			// Never answer. The caller's declared timeout is what ends this
			// request, which is the whole point of the ceiling scenario.
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []string{destAccount}})
	})
	u.server = httptest.NewServer(mux)
	tb.Cleanup(u.server.Close)
	return u
}

func (u *upstream) declaration(timeout time.Duration) fact.Declaration {
	return fact.Declaration{
		Name:    "account_whitelist",
		Kind:    policy.SourceHTTP,
		Params:  []policy.Param{{Name: "account", Type: policy.TypeString}},
		Returns: policy.ListOf(policy.TypeString),
		OnError: policy.OnErrorDeny,
		TTL:     5 * time.Minute,
		Timeout: timeout,
		URL:     u.server.URL + "/whitelist",
	}
}

// ---------------------------------------------------------------------------
// the assembled process
// ---------------------------------------------------------------------------

type harness struct {
	tb       testing.TB
	app      *stamp.App
	idp      *mockIdP
	upstream *upstream
	token    string
	checkURL string
	client   *http.Client
}

type options struct {
	// factTimeout is the declared per-call timeout on the whitelist source.
	// It is the ceiling on the miss path, and the ceiling scenarios vary it to
	// show that the ceiling follows the declaration.
	factTimeout time.Duration
	// velocity configures the ingestion plane instead of the synchronous fact
	// source, for the scenario U12 made possible.
	velocity bool
	// concurrency sizes the client connection pool. The load driver uses the
	// same number of workers.
	concurrency int
}

func newHarness(tb testing.TB, opts options) *harness {
	tb.Helper()
	if opts.factTimeout == 0 {
		opts.factTimeout = 2 * time.Second
	}
	if opts.concurrency == 0 {
		opts.concurrency = benchCfg.concurrency
	}

	idp := newMockIdP(tb)
	up := newUpstream(tb)

	cfg := stamp.Config{
		DSN:         freshDB(tb),
		MaxConns:    int32(opts.concurrency) + 8, //nolint:gosec // a concurrency knob, not a conversion of untrusted input
		Migrate:     true,
		ApplyGrants: true,
		InstanceID:  "bench",
		WriterID:    "bench-writer",
		Addresses: map[api.Surface]string{
			api.SurfacePEP:      "127.0.0.1:0",
			api.SurfaceConsole:  "127.0.0.1:0",
			api.SurfaceCallback: "127.0.0.1:0",
		},
		OIDC: stamp.OIDCConfig{
			Issuers: []stamp.IssuerConfig{{
				Issuer:          idp.server.URL,
				JWKSURL:         idp.server.URL + "/jwks",
				WorkloadClients: []string{testWorkload},
			}},
			Audience:               testAudience,
			Algorithms:             []string{"RS256"},
			AllowInsecureTransport: true,
		},
		Egress: fact.EgressConfig{
			Allow:         []string{up.server.URL},
			AllowLoopback: true,
		},
		// Fail-open on audit saturation, deliberately. The default buffer
		// flushes on a timer, so a sustained rate above its capacity drops
		// events and — with fail-closed set — would turn every later request
		// into a deny. That would measure the buffer's saturation instead of
		// the check path. The saturation is not hidden: the artifact carries
		// the chained and dropped counts read back out of the audit chain.
		AuditFailClosed: false,
		// Audit batching is left at the api package's defaults on purpose. The
		// audit conversion in the artifact multiplies by the same constant the
		// deployment under measurement is actually using.
	}
	if opts.velocity {
		withVelocity(&cfg)
	} else {
		cfg.FactSources = []fact.Declaration{up.declaration(opts.factTimeout)}
	}

	roles, err := stamp.ParseRoles(stamp.RoleAll)
	if err != nil {
		tb.Fatalf("parse roles: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	app, err := stamp.Assemble(ctx, cfg, roles, benchLogger())
	if err != nil {
		cancel()
		tb.Fatalf("assemble: %v", err)
	}
	if err := app.Listen(); err != nil {
		cancel()
		app.Close()
		tb.Fatalf("listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx) }()
	tb.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				note("%s: the process reported %q on shutdown", tb.Name(), err)
			}
		case <-time.After(30 * time.Second):
			note("%s: the process did not stop within 30s of cancellation", tb.Name())
		}
		app.Close()
	})

	h := &harness{
		tb: tb, app: app, idp: idp, upstream: up,
		token:    idp.workload(tb, "svc-bench"),
		checkURL: "http://" + app.Addr(api.SurfacePEP) + api.EvaluationPath,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				// One idle connection per worker. Without this the pool
				// evicts connections between requests and the benchmark
				// measures TCP setup as if it were policy evaluation.
				MaxIdleConns:        opts.concurrency * 2,
				MaxIdleConnsPerHost: opts.concurrency * 2,
				MaxConnsPerHost:     opts.concurrency * 2,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
	return h
}

// benchLogger discards the process's logs unless BENCH_LOG is set. A run that
// is producing numbers wants a quiet process; a run that is being diagnosed
// wants everything, and the audit buffer's saturation alert is only visible
// there.
func benchLogger() *slog.Logger {
	if os.Getenv("BENCH_LOG") == "" {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// seed writes the schema and policies straight into the store, the way an
// operator bootstraps a fresh install, then makes the process pick them up.
func (h *harness) seed(schema *policy.Schema, policies ...*policy.Policy) {
	h.tb.Helper()
	ctx := context.Background()
	pool := h.app.Store().Pool()
	rec, err := store.PutSchema(ctx, pool, schema, store.OriginForm, "bench")
	if err != nil {
		h.tb.Fatalf("seed schema: %v", err)
	}
	for _, p := range policies {
		if _, err := store.PutPolicy(ctx, pool, store.PolicyInput{
			Policy: p, SchemaVersion: rec.Version, Origin: store.OriginForm, Author: "bench",
		}); err != nil {
			h.tb.Fatalf("seed policy %s: %v", p.ID, err)
		}
	}
	if err := h.app.Refresh(ctx); err != nil {
		h.tb.Fatalf("refresh after seeding: %v", err)
	}
}

// evaluate issues one check request and reports the decision.
func (h *harness) evaluate(body string) (allowed bool, err error) {
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, h.checkURL, strings.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	var decoded api.EvaluationResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return false, fmt.Errorf("decode response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("POST %s = %d", api.EvaluationPath, resp.StatusCode)
	}
	return decoded.Decision, nil
}

// post sends a body to one of the process's other surfaces.
func (h *harness) post(surface api.Surface, path, body string) (int, []byte) {
	h.tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, "http://"+h.app.Addr(surface)+path, strings.NewReader(body))
	if err != nil {
		h.tb.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		h.tb.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.tb.Fatalf("read %s: %v", path, err)
	}
	return resp.StatusCode, raw
}

// auditPressure reads back what the check path's audit buffer managed to chain
// during the run, and what it lost.
//
// It reads the chain rather than the buffer's counters because the chain is
// what an auditor would read, and because a count that only exists in memory
// cannot corroborate the conversion the artifact publishes.
func (h *harness) auditPressure() *bench.AuditPressure {
	h.tb.Helper()
	ctx := context.Background()
	pool := h.app.Store().Pool()
	var p bench.AuditPressure
	err := pool.QueryRow(ctx, `
		SELECT
			coalesce(sum((payload->>'count')::bigint) FILTER (WHERE kind = $1), 0),
			count(*) FILTER (WHERE kind = $1),
			coalesce(sum((payload->>'dropped')::bigint) FILTER (WHERE kind = $2), 0),
			count(*) FILTER (WHERE kind = $2)
		FROM audit_log`, store.AuditKindCheckBatch, store.AuditKindCheckGap).
		Scan(&p.ChainedEvents, &p.BatchRows, &p.DroppedEvents, &p.GapRows)
	if err != nil {
		h.tb.Fatalf("read audit pressure: %v", err)
	}
	return &p
}

// ---------------------------------------------------------------------------
// the load driver
// ---------------------------------------------------------------------------

// sample is one scenario's raw measurement.
type sample struct {
	requests int
	errors   int
	denies   int
	// firstError is what the first failing request said. An error count with
	// no error text in the artifact is a number nobody can act on.
	firstError string
	latencies  []time.Duration
	window     time.Duration
	offeredRPS int
}

// loadSpec is how one scenario is driven.
type loadSpec struct {
	concurrency int
	warmup      time.Duration
	window      time.Duration
	// offeredRPS paces the whole scenario at a fixed request rate instead of
	// letting the clients go as fast as they can. Zero means unpaced, which is
	// what a "maximum QPS" number requires.
	//
	// The miss scenarios need it, and the reason is a finding rather than a
	// convenience: the fact plane's egress client leaves MaxIdleConnsPerHost
	// at Go's default of two, so a scenario where every request is a miss
	// opens and closes a TCP connection for nearly every request. Loopback
	// TIME_WAIT then bounds the sustainable rate at roughly
	// ephemeral ports / TIME_WAIT — about 550/s on this macOS host
	// (16384 ports, 30s) and about 470/s on a stock Linux runner
	// (28231 ports, 60s). Driven above that, the scenario stops measuring the
	// check path and starts measuring port exhaustion.
	offeredRPS int
	// atWindowOpen runs once, when warmup ends and measurement begins. It is
	// how a scenario snapshots a counter it wants a delta of — the fact
	// source's call count, which is where the measured miss rate comes from.
	// Counting from before warmup would fold the warmup's fetches into a rate
	// whose denominator is the window, and report a miss rate above 100%.
	//
	// A request already in flight when the window opens can be counted on
	// either side of it, so the rate carries an error of at most one request
	// per client out of the window's several hundred.
	atWindowOpen func()
}

// drive runs a load for the configured warmup and window.
//
// Warmup requests are issued and discarded rather than skipped: the caches,
// the connection pool and the compile cache all reach steady state by being
// used, and a scenario whose first measured request pays for a connection
// setup and a CEL compile is measuring the wrong thing.
func drive(spec loadSpec, call func(worker, iteration int) (allowed bool, err error)) sample {
	start := time.Now()
	measureFrom := start.Add(spec.warmup)
	end := measureFrom.Add(spec.window)

	// A paced scenario gives each worker its own slice of the offered rate, so
	// the arrival pattern stays even instead of arriving in bursts of N.
	var interval time.Duration
	if spec.offeredRPS > 0 {
		interval = time.Duration(float64(time.Second) *
			float64(spec.concurrency) / float64(spec.offeredRPS))
	}

	per := make([]sample, spec.concurrency)
	var wg sync.WaitGroup
	if spec.atWindowOpen != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Until(measureFrom))
			spec.atWindowOpen()
		}()
	}
	for w := range spec.concurrency {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			local := sample{}
			next := start
			for i := 0; time.Now().Before(end); i++ {
				if interval > 0 {
					next = next.Add(interval)
					if wait := time.Until(next); wait > 0 {
						time.Sleep(wait)
					}
				}
				issued := time.Now()
				allowed, err := call(worker, i)
				elapsed := time.Since(issued)
				if issued.Before(measureFrom) {
					continue
				}
				local.requests++
				switch {
				case err != nil:
					local.errors++
					if local.firstError == "" {
						local.firstError = err.Error()
					}
				case !allowed:
					local.denies++
				}
				local.latencies = append(local.latencies, elapsed)
			}
			per[worker] = local
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(measureFrom)

	merged := sample{window: elapsed, offeredRPS: spec.offeredRPS}
	for _, p := range per {
		merged.requests += p.requests
		merged.errors += p.errors
		merged.denies += p.denies
		merged.latencies = append(merged.latencies, p.latencies...)
		if merged.firstError == "" {
			merged.firstError = p.firstError
		}
	}
	return merged
}

// run converts a raw sample into the report's shape.
func (s sample) run(scenario, title string, concurrency int) bench.Run {
	qps := 0.0
	if s.window > 0 {
		qps = float64(s.requests) / s.window.Seconds()
	}
	run := bench.Run{
		Scenario:       scenario,
		Title:          title,
		Concurrency:    concurrency,
		OfferedRPS:     s.offeredRPS,
		Requests:       s.requests,
		Errors:         s.errors,
		FirstError:     s.firstError,
		Denies:         s.denies,
		DurationMillis: float64(s.window) / float64(time.Millisecond),
		QPS:            qps,
		Latency:        bench.Summarize(s.latencies),
	}
	if s.errors > 0 {
		note("%s: %d of %d requests failed; the first said %q",
			scenario, s.errors, s.requests, s.firstError)
	}
	return run
}

// evaluationBody is one AuthZEN request.
func evaluationBody(sourceAccount, destinationAccount, action string) string {
	return fmt.Sprintf(`{"subject":{"type":"account","id":"acct-src","properties":{"number":%q}},`+
		`"resource":{"type":"account","id":"acct-dst","properties":{"number":%q}},`+
		`"action":{"name":%q}}`, sourceAccount, destinationAccount, action)
}

// ---------------------------------------------------------------------------
// artifacts
// ---------------------------------------------------------------------------

func TestMain(m *testing.M) {
	code := m.Run()
	if err := writeArtifacts(); err != nil {
		fmt.Fprintf(os.Stderr, "bench: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	containerMu.Lock()
	running := container
	containerMu.Unlock()
	if running != nil {
		if err := testcontainers.TerminateContainer(running); err != nil {
			fmt.Fprintf(os.Stderr, "terminate container: %v\n", err)
		}
	}
	os.Exit(code)
}

// writeArtifacts renders the results document and the report.
//
// A run that measured nothing writes nothing. `go test ./...` compiles this
// package and runs its unit tests without ever asking for a benchmark, and a
// report claiming zero scenarios would be worse than no report at all.
func writeArtifacts() error {
	collectedMu.Lock()
	report := collected
	collectedMu.Unlock()
	if len(report.Runs) == 0 {
		return nil
	}

	report.Schema = bench.Schema
	report.GeneratedAt = time.Now().UTC()
	report.Commit = benchCfg.commit
	report.Profile = benchCfg.profile
	report.Environment = bench.Environment{
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		NumCPU:        runtime.NumCPU(),
		GoVersion:     runtime.Version(),
		PostgresImage: postgresImage,
		LoadModel: fmt.Sprintf("closed loop, %d in-process clients, %s warmup, %s window",
			benchCfg.concurrency, benchCfg.warmup, benchCfg.duration),
		Host: os.Getenv("RUNNER_NAME"),
	}

	thresholds, err := bench.LoadThresholds("thresholds.json")
	if err != nil {
		return err
	}
	profile, ok := thresholds.Profile(benchCfg.profile)
	if !ok {
		return fmt.Errorf("no threshold profile named %q", benchCfg.profile)
	}

	var baseline *bench.Report
	if benchCfg.baseline != "" {
		loaded, err := bench.LoadReport(benchCfg.baseline)
		switch {
		case err == nil:
			baseline = loaded
		// errors.Is rather than os.IsNotExist: the read error is wrapped, and
		// the legacy helper does not unwrap, so a first run with no baseline
		// would report its own artifact as corrupt.
		case errors.Is(err, fs.ErrNotExist):
			fmt.Fprintf(os.Stderr, "bench: no baseline at %s; regressions are unreported\n",
				benchCfg.baseline)
		default:
			// A corrupt baseline is worth saying out loud, but it is not worth
			// throwing away a completed measurement over.
			fmt.Fprintf(os.Stderr, "bench: baseline unusable (%v); regressions are unreported\n", err)
		}
	}

	evaluation := report.Evaluate(benchCfg.profile, profile, baseline)
	resultsPath := benchCfg.outDir + "/results.json"
	reportPath := benchCfg.outDir + "/report.md"
	if err := report.WriteJSON(resultsPath); err != nil {
		return err
	}
	if err := evaluation.WriteMarkdown(reportPath); err != nil {
		return err
	}
	for _, line := range evaluation.Annotations() {
		fmt.Println(line)
	}
	fmt.Printf("bench: wrote %s and %s\n", resultsPath, reportPath)
	return nil
}
