package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/store"
)

// TestAProcessAheadOfTheSchemaAnswersReadyzWith503 is the upgrade this repository
// was one `helm upgrade` away from breaking.
//
// The chart gives `database.migrate` to the tier holding the `api` role and to
// no other, and it sequences nothing: no `helm.sh/hook`, no migration Job, no
// initContainer. So `helm upgrade` rolls every Deployment at once and a serving
// pod on the new image can be looking at the old schema. 000008 is the first
// migration in this repository to add a column to a table a *non-migrating* tier
// reads — internal/store's decisionColumns names idempotency_key, and it backs
// every decision read and the create insert — so this is the first upgrade where
// that window is an outage rather than a curiosity.
//
// The database here is that window, built the only honest way: migrate all the
// way up, then roll back to 7. What the test asserts is that the process notices.
// The pod answers 503 on /readyz, so Kubernetes keeps it out of its Service and
// the old pods keep serving; it answers 200 on /healthz at the same moment, so
// nothing restarts it while it waits.
func TestAProcessAheadOfTheSchemaAnswersReadyzWith503(t *testing.T) {
	ctx := context.Background()
	dsn := freshDB(t)

	s, err := store.Open(ctx, store.Config{DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Down two: 000009's index and 000008's column. Version 7 is the schema an
	// old-image api tier leaves behind while the new decide pods come up.
	if err := s.MigrateDown(ctx, 2); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	want, err := store.LatestSchemaVersion()
	if err != nil {
		t.Fatalf("latest schema version: %v", err)
	}
	s.Close()

	// The check role, because its boot and its loops do not read `decisions`:
	// this test is about the gate in front of the surface, and a process that
	// failed to assemble against schema 7 would prove something else. The gate
	// is not conditional on the role — see build() — so any non-migrating tier
	// would answer the same.
	h := newHarness(t, harnessOptions{
		roles: "check", dsn: dsn, writerID: "stamp-schema-behind",
		mutate: func(cfg *Config) { cfg.Migrate = false },
	})

	code, body := h.do(http.MethodGet, api.SurfacePEP, "/readyz", "", "", nil)
	if code != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz against schema 7 = %d, want 503: this pod would be in its Service "+
			"answering 42703 on every decision read", code)
	}
	// The reason is in the body so that `kubectl describe` on the stuck pod says
	// which version it is waiting for. A 503 that says nothing is an upgrade
	// that looks hung for no stated reason.
	for _, fragment := range []string{"version 7", fmt.Sprintf("needs %d", want)} {
		if !strings.Contains(string(body), fragment) {
			t.Errorf("GET /readyz body does not mention %q: %q", fragment, string(body))
		}
	}

	// Liveness is unaffected, and that is deliberate: the chart's livenessProbe
	// still asks /healthz, and a /healthz that followed the schema would restart
	// every waiting pod on a timer instead of letting the migration land.
	if code, _ := h.do(http.MethodGet, api.SurfacePEP, "/healthz", "", "", nil); code != http.StatusOK {
		t.Errorf("GET /healthz against schema 7 = %d, want 200: a schema that has not landed is "+
			"not a wedged process, and restarting this pod would not help", code)
	}
}

// The gate latches on the schema, and the latch is what keeps a probe every few
// seconds off the database for the rest of the process's life. Asserted through
// the store rather than through HTTP because the claim is about the second call,
// not about the status code.
//
// This is the constraint the reachability signal exists to respect: a readiness
// probe that queried the database every few seconds would add load to a
// database at exactly the moment it is least able to take it. The gate closing
// again (below) must not cost this property, so this test stays as it was.
func TestTheSchemaGateStopsAskingOnceTheSchemaHasArrived(t *testing.T) {
	ctx := context.Background()
	dsn := freshDB(t)
	s, err := store.Open(ctx, store.Config{DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	gate, err := newSchemaVersionGate(s, nil, nil)
	if err != nil {
		t.Fatalf("new gate: %v", err)
	}
	if err := gate.ready(ctx); err != nil {
		t.Fatalf("ready against the latest schema: %v", err)
	}
	if !gate.open.Load() {
		t.Fatal("the gate did not latch after the schema arrived")
	}

	// Roll the schema out from under it. A latched gate does not look again —
	// stated as a test because it is a deliberate trade and not an oversight: a
	// down migration is a manual act, and a gate that reopened on one would pull
	// the whole fleet out of service during the incident.
	if err := s.MigrateDown(ctx, 2); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	if err := gate.ready(ctx); err != nil {
		t.Fatalf("a latched gate re-read the schema and closed: %v", err)
	}
}

// TestTheGateClosesOnObservedFailuresAndOpensOnTheNextGoodRead is the whole of
// U1's mechanism at unit scale: what closes an open gate, what does not, and
// what opens it again.
//
// The trick that makes it a real test of "did the gate ask the database?" is
// the same one the latch test uses: the schema is rolled backwards, so a gate
// that re-reads answers an error naming the version and a gate that did not
// re-read answers nil. Nothing has to be mocked to tell the two apart, and the
// difference is the one that matters — a probe that queries a struggling
// database is the failure mode this design was chosen to avoid.
func TestTheGateClosesOnObservedFailuresAndOpensOnTheNextGoodRead(t *testing.T) {
	ctx := context.Background()
	dsn := freshDB(t)
	s, err := store.Open(ctx, store.Config{DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// The observer is driven directly rather than through the pool's tracer.
	// What the tracer classifies is store's to test — see
	// TestReachabilityDistinguishesAnUnreachableServerFromAnAngryOne — and what
	// the gate does with the classification is this one's.
	reach := &databaseReachability{}
	gate, err := newSchemaVersionGate(s, reach, nil)
	if err != nil {
		t.Fatalf("new gate: %v", err)
	}
	if err := gate.ready(ctx); err != nil {
		t.Fatalf("ready against the latest schema: %v", err)
	}

	// Roll the schema back, so that from here on "the gate asked" and "the gate
	// did not ask" have different answers.
	if err := s.MigrateDown(ctx, 2); err != nil {
		t.Fatalf("migrate down: %v", err)
	}

	// Under the threshold: still ready, and still not asking. A single reset
	// connection is weather, not an outage, and a fleet that left its Service
	// over one would flap in unison.
	for range unreachableStreak - 1 {
		reach.observe(store.Reachability{Err: errors.New("connection reset by peer")})
	}
	if err := gate.ready(ctx); err != nil {
		t.Fatalf("the gate closed after %d transport failures, below the threshold of %d: %v",
			unreachableStreak-1, unreachableStreak, err)
	}

	// One statement that reached the server clears the streak, so the failures
	// have to be consecutive. This is what keeps a partially-degraded database
	// — some statements answered, some connections dropped — from emptying the
	// Service.
	reach.observe(store.Reachability{Reached: true})
	for range unreachableStreak - 1 {
		reach.observe(store.Reachability{Err: errors.New("connection reset by peer")})
	}
	if err := gate.ready(ctx); err != nil {
		t.Fatalf("a success between the failures did not clear the streak: %v", err)
	}

	// At the threshold: the gate closes, and closing means it reads the schema
	// again. The rolled-back schema is how we know it read.
	for range unreachableStreak {
		reach.observe(store.Reachability{Err: errors.New("connection reset by peer")})
	}
	err = gate.ready(ctx)
	if err == nil {
		t.Fatal("the gate stayed open after the database stopped answering: a pod that cannot " +
			"reach its database must leave its Service")
	}
	if !strings.Contains(err.Error(), "version 7") {
		t.Errorf("the gate closed with %q, want the re-read schema version: closing has to mean "+
			"asking again, or the gate can never find out the database came back", err)
	}
	if gate.open.Load() {
		t.Error("the gate reported not-ready but left its latch open")
	}

	// And it opens again on the next good read, with no restart and nothing
	// reset by hand. A gate that goes unready and stays there is an outage of
	// its own — the pod is out of the Service, so nothing else it does will
	// ever tell it otherwise.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate back up: %v", err)
	}
	if err := gate.ready(ctx); err != nil {
		t.Fatalf("the gate did not reopen once the database answered again: %v", err)
	}
	if !gate.open.Load() {
		t.Error("the gate answered ready without latching, so it will query on every probe")
	}
}
