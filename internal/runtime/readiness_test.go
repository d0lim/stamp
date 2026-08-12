package runtime

import (
	"context"
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

// The gate latches, and the latch is what keeps a probe every few seconds off
// the database for the rest of the process's life. Asserted through the store
// rather than through HTTP because the claim is about the second call, not about
// the status code.
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

	gate, err := newSchemaVersionGate(s, nil)
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
