package runtime

// failure_test.go asks the question an authorization engine is actually judged
// on: when the database is gone, what does each surface answer?
//
// Everything else in this package tests the process while its dependencies
// work. That is the easy half. A check tier that loses Postgres and keeps
// answering "allow" from the policy set it happened to be holding is not
// degrading gracefully — it is a security defect wearing an availability
// costume, and no test in this repository could tell the difference.
//
// The rules this file follows, and why:
//
//  1. The database is killed for real. The container testcontainers already
//     runs is stopped. A failure-injecting mock reproduces the failure we
//     imagined; a stopped container reproduces the one that happens — the pool
//     with live connections that get reset mid-statement, the retry that has
//     its own deadline, the context that expires somewhere else.
//
//  2. Every assertion is on the answer the caller received, never on "an error
//     occurred". In an authorization engine an exception and an allow are
//     different things right up until something upstream turns one into the
//     other, and the only place that is visible is the response.
//
//  3. The table below was written after the run, not before it. Each line is
//     what this process actually did, and two of them were not what we
//     expected. They are called out where they are asserted.
//
// What was observed, with the database stopped under a running process:
//
//	surface                                  answer
//	---------------------------------------  --------------------------------
//	POST /access/v1/evaluation               200 {"decision":false,
//	                                         "stamp.reason":"audit_unavailable"}
//	  ... for one audit flush interval       200 {"decision":true, ...}  (!)
//	      after the kill                     2–56 allows over 6–48ms measured
//	CheckService.Evaluate, in process        allow, policy_matched, until the
//	                                         staleness deadline; then deny
//	                                         with policy_set_stale
//	POST /decisions                          500 internal_error, and no
//	                                         decision row is created
//	POST /decisions/{id}/.../approvals       500 internal_error
//	GET  /decisions/{id}                     500 internal_error
//	GET  /audit/decisions                    500 internal_error
//	GET  /healthz                            200 ok
//	GET  /readyz                             200 ready                     (!)
//
// The two marked lines are the findings. Both are asserted below, at
// [TestTheSurfacesAnswerWhenTheDatabaseIsGone]'s "the check surface refuses"
// and "readiness" subtests, with the reasoning at each.
//
// Nothing in this file changes behaviour. It is a description, and the point of
// writing a description down as assertions is that the next change to any of
// these paths has to say out loud that it moved one.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/store"
)

// ---------------------------------------------------------------------------
// a database that can be taken away
// ---------------------------------------------------------------------------

// killableDatabase is a Postgres this test may stop and start again, reached
// through an address that survives the stop.
//
// It is its own container rather than the package's shared one for the obvious
// reason: every other test in this package is talking to that one.
//
// The relay is the part that needs explaining. Docker publishes a container
// port on an ephemeral host port, and `docker start` after `docker stop`
// allocates a *new* one — measured here, 34033 before and 34034 after. The
// process under test parses its DSN once at assembly and never looks at it
// again, exactly as a deployed process does, so a moved port would mean the
// recovery half of this file could not be written at all. The relay is a fixed
// address in front of the moving one: it forwards bytes while the container is
// up, and while it is down it accepts and immediately closes, which is what a
// load balancer with no healthy backend does.
//
// The relay carries no protocol knowledge and never fabricates a failure. The
// failure is a real Postgres that is really not running.
type killableDatabase struct {
	t         *testing.T
	container testcontainers.Container
	relay     *dbRelay
	dsn       string
}

func newKillableDatabase(t *testing.T) *killableDatabase {
	t.Helper()
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase("stamp"),
		tcpostgres.WithUsername("stamp"),
		tcpostgres.WithPassword("stamp"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("the dependency-failure tests need a working Docker daemon: %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(c); err != nil {
			t.Logf("terminate the killable database: %v", err)
		}
	})

	db := &killableDatabase{t: t, container: c}
	db.relay = newDBRelay(t, db.upstream())
	db.dsn = "postgres://stamp:stamp@" + db.relay.addr() + "/stamp?sslmode=disable"
	return db
}

// upstream is where the container's Postgres is listening right now.
func (d *killableDatabase) upstream() string {
	d.t.Helper()
	ctx := context.Background()
	host, err := d.container.Host(ctx)
	if err != nil {
		d.t.Fatalf("read the container host: %v", err)
	}
	port, err := d.container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		d.t.Fatalf("read the container port: %v", err)
	}
	return net.JoinHostPort(host, port.Port())
}

// stop takes the database away.
func (d *killableDatabase) stop() {
	d.t.Helper()
	timeout := 10 * time.Second
	if err := d.container.Stop(context.Background(), &timeout); err != nil {
		d.t.Fatalf("stop the database container: %v", err)
	}
	d.relay.point("")
}

// start gives it back, at whatever port Docker chose this time.
func (d *killableDatabase) start() {
	d.t.Helper()
	if err := d.container.Start(context.Background()); err != nil {
		d.t.Fatalf("start the database container: %v", err)
	}
	d.relay.point(d.upstream())
}

// dbRelay is a fixed TCP address in front of a moving one. See
// [killableDatabase].
type dbRelay struct {
	listener net.Listener

	mu sync.Mutex
	// upstream is where to forward. Empty means the database is gone, and a
	// connection to it is accepted and closed.
	upstream string
}

func newDBRelay(t *testing.T, upstream string) *dbRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the database relay: %v", err)
	}
	r := &dbRelay{listener: listener, upstream: upstream}
	go r.accept()
	t.Cleanup(func() { _ = listener.Close() })
	return r
}

func (r *dbRelay) addr() string { return r.listener.Addr().String() }

func (r *dbRelay) point(upstream string) {
	r.mu.Lock()
	r.upstream = upstream
	r.mu.Unlock()
}

func (r *dbRelay) accept() {
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			return // the listener is closed: the test is over
		}
		go r.forward(conn)
	}
}

func (r *dbRelay) forward(client net.Conn) {
	defer func() { _ = client.Close() }()
	r.mu.Lock()
	upstream := r.upstream
	r.mu.Unlock()
	if upstream == "" {
		return
	}
	server, err := net.DialTimeout("tcp", upstream, 2*time.Second)
	if err != nil {
		return
	}
	defer func() { _ = server.Close() }()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(server, client); _ = server.Close() }()
	go func() { defer wg.Done(); _, _ = io.Copy(client, server); _ = client.Close() }()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// reading the surfaces
// ---------------------------------------------------------------------------

// checkVerdict is what a caller of the check surface got: the status, whether
// the AuthZEN body says allow, and the ground it gave.
type checkVerdict struct {
	status int
	allow  bool
	reason string
	body   string
}

func (v checkVerdict) String() string {
	return fmt.Sprintf("%d allow=%v reason=%q", v.status, v.allow, v.reason)
}

// checkSurface issues one real request to POST /access/v1/evaluation and reads
// the answer out of the response, which is the only place the caller's answer
// exists. An error status is not folded into "deny" here: the two are recorded
// separately so an assertion can tell them apart.
func (h *harness) checkSurface(token string) checkVerdict {
	h.t.Helper()
	status, raw := h.do(http.MethodPost, api.SurfacePEP, api.EvaluationPath, token,
		evaluation("1001", "2002", "transfer"), nil)
	var decoded struct {
		Decision bool           `json:"decision"`
		Context  map[string]any `json:"context"`
	}
	_ = json.Unmarshal(raw, &decoded)
	reason, _ := decoded.Context["stamp.reason"].(string)
	return checkVerdict{status: status, allow: decoded.Decision, reason: reason, body: strings.TrimSpace(string(raw))}
}

// auditor mints a console credential carrying auditor standing, which is what
// the history read requires.
func (m *mockIdP) auditor(t *testing.T, subject string) string {
	t.Helper()
	now := time.Now()
	return m.sign(t, map[string]any{
		"iss":                   m.server.URL,
		"sub":                   subject,
		"aud":                   testAudience,
		"azp":                   testConsole,
		"iat":                   now.Add(-time.Minute).Unix(),
		"exp":                   now.Add(time.Hour).Unix(),
		api.DefaultAuditorClaim: []any{"auditor"},
	})
}

// probe reads one liveness or readiness endpoint.
func (h *harness) probe(surface api.Surface, path string) (int, string) {
	h.t.Helper()
	status, raw := h.do(http.MethodGet, surface, path, "", "", nil)
	return status, strings.TrimSpace(string(raw))
}

// awaitAuditQuiet waits until every event the test has produced so far is in
// the chain and nothing is queued behind it.
//
// It is the setup for an honest measurement rather than a convenience: the
// check surface refuses because a flush failed, so killing the database while a
// batch is already in flight measures the flush's latency instead of the
// window. A quiet buffer is the state an outage that begins between two batches
// finds, which is the one worth describing.
func (h *harness) awaitAuditQuiet(within time.Duration) {
	h.t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		stats := h.app.buffer.Stats()
		if stats.Queued == 0 && !stats.Alerting && stats.Flushed > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("the audit buffer did not settle within %s: %+v", within, h.app.buffer.Stats())
}

// awaitCheckSurfaceRefusal polls the check surface until it stops allowing, and
// returns how long that took and how many allows it served on the way.
//
// It exists because the transition is not instantaneous and the size of the
// window is itself one of this file's findings. See the "the check surface
// refuses" subtest.
func (h *harness) awaitCheckSurfaceRefusal(token string, within time.Duration) (allows int, took time.Duration) {
	h.t.Helper()
	start := time.Now()
	for time.Since(start) < within {
		got := h.checkSurface(token)
		if !got.allow {
			return allows, time.Since(start)
		}
		allows++
		time.Sleep(time.Millisecond)
	}
	h.t.Fatalf("the check surface was still allowing %s after the database was stopped, "+
		"having served %d allows: an instance that cannot record what it decided must stop deciding",
		within, allows)
	return allows, 0
}

// ---------------------------------------------------------------------------
// the test
// ---------------------------------------------------------------------------

// TestTheSurfacesAnswerWhenTheDatabaseIsGone stops the database under a running
// process and pins what every surface answers, then starts it again and pins
// that every surface comes back.
//
// Recovery is half the test on purpose. A surface that refuses correctly and
// never recovers has turned a database blip into an outage that outlives it,
// which is its own defect and one that only a test in both directions catches.
func TestTheSurfacesAnswerWhenTheDatabaseIsGone(t *testing.T) {
	db := newKillableDatabase(t)

	// The staleness deadline is shortened from its 60s default so the in-process
	// check tier's own refusal is reachable inside a test. Nothing else about
	// the deployment is changed: the audit buffer, its flush interval and
	// STAMP_AUDIT_FAIL_CLOSED are the harness's ordinary settings, because the
	// question is what the ordinary deployment does.
	const stalenessDeadline = 2 * time.Second
	h := newHarness(t, harnessOptions{dsn: db.dsn, writerID: "failure-writer", mutate: func(cfg *Config) {
		cfg.PolicyStalenessDeadline = stalenessDeadline
	}})
	h.seed(tenantSchema(), whitelistPolicy("whitelist-transfer"), closurePolicy("closure", 1, "alice"))

	pep := h.idp.workload(t, "svc-payments")
	alice := h.idp.user(t, "alice")
	auditor := h.idp.auditor(t, "auditor-1")

	// One pending decision, created through the surface by the caller who will
	// later try to read it, so the refusals below are refusals to serve a real
	// caller a real row rather than a not-found.
	var pending struct {
		ID string `json:"id"`
	}
	status, body := h.do(http.MethodPost, api.SurfacePEP, api.DecisionsPath, pep,
		decideRequest("acct-src", "close", 5000, "45m"), nil)
	if status != http.StatusCreated {
		t.Fatalf("POST %s = %d: %s", api.DecisionsPath, status, body)
	}
	h.decode(body, &pending)
	approvalPath := "/decisions/" + pending.ID + "/challenges/0/approvals"

	// The baseline. Without it, "every surface refuses" is also what a broken
	// harness produces.
	t.Run("every surface works while the database is there", func(t *testing.T) {
		if got := h.checkSurface(pep); !got.allow {
			t.Fatalf("the check surface answered %s with the database up, want an allow", got)
		}
		if status, _ := h.do(http.MethodGet, api.SurfacePEP, api.DecisionsPath+"/"+pending.ID,
			pep, "", nil); status != http.StatusOK {
			t.Fatalf("GET %s/{id} = %d, want 200", api.DecisionsPath, status)
		}
		if status, _ := h.do(http.MethodGet, api.SurfaceConsole, "/audit/decisions",
			auditor, "", nil); status != http.StatusOK {
			t.Fatalf("GET /audit/decisions as an auditor = %d, want 200", status)
		}
		// The probes are read here for a reason that is not symmetry: a
		// successful /readyz latches the schema gate open, and a deployed
		// process is probed every few seconds from the moment it binds. Reading
		// it once while the database is up is what makes the outage assertion
		// below the one a Kubernetes deployment actually gets. See the
		// "readiness" subtest.
		for _, surface := range []api.Surface{api.SurfacePEP, api.SurfaceConsole} {
			if status, body := h.probe(surface, "/healthz"); status != http.StatusOK {
				t.Fatalf("GET /healthz on %v = %d %s, want 200", surface, status, body)
			}
			if status, body := h.probe(surface, "/readyz"); status != http.StatusOK {
				t.Fatalf("GET /readyz on %v = %d %s, want 200", surface, status, body)
			}
		}
	})

	decisionsBefore := h.countDecisions()

	// The audit buffer is drained before the kill, and the reason is the whole
	// subject of the "the check surface refuses" subtest: the surface finds out
	// the chain is gone when a flush fails, so a buffer with a flush already in
	// flight when the database dies hides the window that a quiet one exposes.
	// The quiet one is the honest case to measure — it is what an outage that
	// starts between two batches looks like.
	h.awaitAuditQuiet(5 * time.Second)

	// The rest of the test runs with no database.
	db.stop()

	var allowsInTheWindow int
	t.Run("the check surface refuses", func(t *testing.T) {
		// FINDING. The refusal is not immediate, and it cannot be: the audit
		// buffer is asynchronous by design (R32 chose one chain row per batch
		// over one per judgment), so the surface learns the chain is
		// unreachable when a flush fails, and until then it answers from the
		// snapshot it holds. Measured here, with the harness's 50ms flush
		// interval, that window served between 2 and 56 allows across runs,
		// spanning 6ms to 48ms — the flush interval, as the mechanism predicts.
		// [api.DefaultAuditFlushInterval] is one second, so a deployment that
		// did not shorten it serves a second of allows.
		//
		// Every one of those allows is unaudited: its event is dropped when the
		// flush that would have chained it fails. That is not silent — it is
		// counted, and the gap marker asserted at the bottom of this test is
		// where it becomes visible — but an operator reading "fail closed" as
		// "no allow is served that is not in the chain" is reading something
		// this process does not promise.
		//
		// The assertion is therefore on the bound rather than on the window:
		// the surface must stop allowing quickly, and everything it serves
		// after that must be a refusal. Asserting that the window exists would
		// make closing it a test failure.
		var took time.Duration
		allowsInTheWindow, took = h.awaitCheckSurfaceRefusal(pep, 5*time.Second)
		t.Logf("the check surface served %d allow(s) over %s before it began refusing",
			allowsInTheWindow, took.Round(time.Millisecond))

		// The refusal is a verdict, not an error. A PEP has to do something
		// with the answer, and a 500 with no verdict is an answer it cannot
		// act on: R40's whole point is that the deny reaches the caller.
		got := h.checkSurface(pep)
		if got.status != http.StatusOK || got.allow || got.reason != string(engine.ReasonAuditUnavailable) {
			t.Fatalf("the check surface answered %s with no database, want 200 with a deny "+
				"grounded in %q", got, engine.ReasonAuditUnavailable)
		}

		// And it does not flap back. A surface that alternates between allow and
		// deny during an outage is worse than either.
		for range 20 {
			if got := h.checkSurface(pep); got.allow {
				t.Fatalf("the check surface allowed again after it began refusing: %s", got)
			}
		}
	})

	t.Run("the decide surface refuses and creates nothing", func(t *testing.T) {
		status, body := h.do(http.MethodPost, api.SurfacePEP, api.DecisionsPath, pep,
			decideRequest("acct-src", "close", 5000, "45m"), nil)
		if status == http.StatusCreated {
			t.Fatalf("POST %s created a decision with no database: %s", api.DecisionsPath, body)
		}
		if status != http.StatusInternalServerError || !strings.Contains(string(body), `"internal_error"`) {
			t.Fatalf("POST %s = %d %s, want 500 internal_error", api.DecisionsPath, status, body)
		}
	})

	t.Run("a challenge takes no evidence", func(t *testing.T) {
		// The dangerous shape here is not the error, it is an approval that is
		// accepted and lost: the caller is told the quorum advanced and no row
		// says so. The status has to be a refusal.
		status, body := h.do(http.MethodPost, api.SurfaceConsole, approvalPath, alice, "", nil)
		if status == http.StatusOK {
			t.Fatalf("an approval was accepted with no database: %s", body)
		}
		if status != http.StatusInternalServerError || !strings.Contains(string(body), `"internal_error"`) {
			t.Fatalf("POST %s = %d %s, want 500 internal_error", approvalPath, status, body)
		}
	})

	t.Run("the reads refuse rather than answer from nothing", func(t *testing.T) {
		// An empty history is a worse answer than an error: it reads as "this
		// deployment made no decisions", which is a statement an auditor would
		// act on.
		status, body := h.do(http.MethodGet, api.SurfaceConsole, "/audit/decisions", auditor, "", nil)
		if status != http.StatusInternalServerError {
			t.Fatalf("GET /audit/decisions = %d %s, want 500", status, body)
		}
		status, body = h.do(http.MethodGet, api.SurfacePEP, api.DecisionsPath+"/"+pending.ID, pep, "", nil)
		if status != http.StatusInternalServerError {
			t.Fatalf("GET %s/{id} = %d %s, want 500", api.DecisionsPath, status, body)
		}
	})

	t.Run("the in-process check tier holds its snapshot until the deadline", func(t *testing.T) {
		// This is the check path with no HTTP and no audit gate in front of it:
		// the evaluator and the freshness of the policy set it holds, which is
		// what a check tier is.
		//
		// R24's staged failure is deliberate and it is the reason the served
		// surface above is the one carrying fail-closed: a failover of a few
		// seconds must not drop the whole fleet into deny, so the instance keeps
		// judging on the set it has and only stops once it has been unable to
		// confirm that set for StalenessDeadline. Both halves are pinned here.
		// If the first ever becomes a refusal, this assertion is where that
		// decision gets recorded.
		in := engine.Input{
			Action:   "transfer",
			Subject:  engine.Entity{Type: "account", ID: "acct-src", Attributes: map[string]any{"number": "1001"}},
			Resource: engine.Entity{Type: "account", ID: "acct-dst", Attributes: map[string]any{"number": "2002"}},
		}
		res, err := h.app.Check().Evaluate(context.Background(), in)
		if err != nil {
			t.Fatalf("evaluate inside the deadline: %v", err)
		}
		if !res.Allowed() || res.Reason() != engine.ReasonPolicyMatched {
			t.Fatalf("the check service answered allow=%v/%q inside its staleness deadline, want the "+
				"held policy set's verdict: R24 trades a stale answer for surviving a failover",
				res.Allowed(), res.Reason())
		}

		deadline := time.Now().Add(stalenessDeadline + 3*time.Second)
		for {
			res, err := h.app.Check().Evaluate(context.Background(), in)
			if err != nil {
				t.Fatalf("evaluate past the deadline: %v", err)
			}
			if !res.Allowed() {
				if res.Reason() != engine.ReasonPolicySetStale {
					t.Fatalf("the check service refused with %q, want %q",
						res.Reason(), engine.ReasonPolicySetStale)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the check service was still allowing %s after the database was stopped, "+
					"with a %s staleness deadline: an instance that cannot confirm the effective "+
					"policy set is guessing", stalenessDeadline+3*time.Second, stalenessDeadline)
			}
			time.Sleep(50 * time.Millisecond)
		}
		if stats := h.app.Check().Stats(); !stats.FailClosed || stats.RefreshFailures == 0 {
			t.Errorf("check stats = failClosed:%v refreshFailures:%d, want a tier that reports both",
				stats.FailClosed, stats.RefreshFailures)
		}
	})

	t.Run("liveness stays up and readiness does not reopen", func(t *testing.T) {
		// FINDING, and the one the plan expected to go the other way.
		//
		// /healthz answering 200 is right: liveness asks whether the process is
		// alive, and killing a pod because its database went away turns one
		// outage into two.
		//
		// /readyz answering 200 is what a deployed process does, and it is not
		// what readiness.go's closing paragraph says. That comment reads "A
		// database that cannot be reached is reported unready rather than
		// ready", and it is true exactly once — before the gate has opened.
		// [schemaVersionGate.ready] latches on its first success and every later
		// probe is answered without touching the database, so an unreachable
		// database is reported unready only by a process that has never yet been
		// found ready. A pod is probed every few seconds from the moment it
		// binds, so in a real deployment the gate is open seconds after boot and
		// the sentence stops holding for the rest of the process's life.
		//
		// The order of this test is what makes that visible: the baseline
		// subtest reads /readyz while the database is up, exactly as a kubelet
		// would, and that read is why the assertion here is 200. Written
		// without it — which is how it was written first — the same assertion
		// fails with 503 "database schema version is unreadable", because the
		// gate had never opened. Both answers are this build's; which one an
		// operator gets is decided by whether their probe ran before the outage.
		//
		// The latch itself is deliberate and reasoned in readiness.go: a schema
		// rolled backwards under a running pod must not pull the fleet out of
		// service. Nothing is changed here — this round proves rather than
		// changes — and the operational consequence is smaller than it first
		// looks, because every replica loses the same database at the same
		// instant, so unreadiness would empty the Service rather than shed load
		// onto a healthy peer. It is pinned so that the divergence between the
		// comment and the behaviour is something a reader trips over instead of
		// something they trust.
		for _, surface := range []api.Surface{api.SurfacePEP, api.SurfaceConsole} {
			if status, body := h.probe(surface, "/healthz"); status != http.StatusOK {
				t.Errorf("GET /healthz on %v = %d %s with no database, want 200: liveness is not "+
					"a database probe", surface, status, body)
			}
			if status, body := h.probe(surface, "/readyz"); status != http.StatusOK {
				t.Errorf("GET /readyz on %v = %d %s with no database, want 200. unready is arguably "+
					"the better answer, but it is not the one a gate that has already opened gives. "+
					"if this changed on purpose, update the table at the top of this file, "+
					"readiness.go's closing paragraph, and docs/operations/failure-modes.md with it",
					surface, status, body)
			}
		}
	})

	// ---- and back again ---------------------------------------------------

	db.start()

	t.Run("every surface recovers", func(t *testing.T) {
		// No process restart, no reconfiguration: the same pool, the same
		// buffer, the same latched gate. A refusal that outlives its cause is
		// the defect this half exists to catch.
		const within = 30 * time.Second

		waitFor := func(name string, ok func() bool) {
			t.Helper()
			deadline := time.Now().Add(within)
			for time.Now().Before(deadline) {
				if ok() {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Fatalf("%s did not recover within %s of the database coming back", name, within)
		}

		waitFor("the check surface", func() bool { return h.checkSurface(pep).allow })
		waitFor("the decide surface", func() bool {
			status, _ := h.do(http.MethodPost, api.SurfacePEP, api.DecisionsPath, pep,
				decideRequest("acct-src", "close", 5000, "45m"), nil)
			return status == http.StatusCreated
		})
		waitFor("the audit history", func() bool {
			status, _ := h.do(http.MethodGet, api.SurfaceConsole, "/audit/decisions", auditor, "", nil)
			return status == http.StatusOK
		})
		waitFor("the approval route", func() bool {
			status, _ := h.do(http.MethodPost, api.SurfaceConsole, approvalPath, alice, "", nil)
			return status == http.StatusOK
		})

		// The check surface's recovered answer has to be the policy's verdict
		// and not a residual refusal wearing a 200.
		if got := h.checkSurface(pep); !got.allow || got.reason != string(engine.ReasonPolicyMatched) {
			t.Fatalf("the recovered check surface answered %s, want the policy's allow", got)
		}
	})

	t.Run("nothing was created while the database was gone", func(t *testing.T) {
		// The refusals above were read from responses. This is the other side
		// of the same claim, read from the rows: the decide surface's 500 was a
		// refusal and not a write that failed to be reported. Two decisions
		// were created after the database came back — the recovery probe's and
		// the one below is not counted — so the arithmetic is stated rather
		// than assumed.
		created := h.countDecisions() - decisionsBefore
		if created > 1 {
			t.Errorf("%d decisions exist beyond the ones this test created deliberately: a request "+
				"refused with 500 left a row behind", created-1)
		}
	})

	t.Run("the audit loss is marked in the chain", func(t *testing.T) {
		// R32: the allows served in the window at the top of this test are not
		// in the chain, and the chain has to say so. A clean chain that quietly
		// skipped a window of traffic is the failure mode the gap marker exists
		// to prevent.
		if allowsInTheWindow == 0 {
			t.Skip("no allow was served in the window, so there is no loss to mark")
		}
		deadline := time.Now().Add(30 * time.Second)
		var gaps []map[string]any
		for time.Now().Before(deadline) {
			gaps = h.auditPayloads(store.AuditKindCheckGap)
			if len(gaps) > 0 {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if len(gaps) == 0 {
			t.Fatalf("%d allow(s) were served and dropped from the audit and the chain carries no %q "+
				"marker: the hole is invisible", allowsInTheWindow, store.AuditKindCheckGap)
		}
		var dropped float64
		for _, gap := range gaps {
			n, ok := gap["dropped"].(float64)
			if !ok {
				t.Fatalf("gap marker %v carries no dropped count", gap)
			}
			dropped += n
		}
		if int(dropped) < allowsInTheWindow {
			t.Errorf("the chain marks %d lost records but %d allows were served unaudited: the "+
				"marker must cover at least what was lost", int(dropped), allowsInTheWindow)
		}

		// And the chain still verifies. A gap is data in the chain, not damage
		// to it: an operator who cannot verify the chain after an outage cannot
		// tell a marked hole from tampering.
		h.verifyChain()
	})

}
