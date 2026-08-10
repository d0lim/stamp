package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/policy"
)

// The official AuthZEN interop harness is a Node program that talks to a PDP
// over HTTP; the conformance workflow runs it against a real listener. This
// test replays the very same vendored fixtures against the same handler, in
// process and offline, so that the fixtures are a gate on every `go test` run
// rather than only on the job that has Node and network.
//
// The fixture file is vendored at a pinned upstream commit — see
// testdata/conformance/README.md — because the upstream set moves.

const conformanceDir = "../../testdata/conformance"

type conformanceCase struct {
	Request  api.EvaluationRequest `json:"request"`
	Expected bool                  `json:"expected"`
}

type conformanceFixtures struct {
	Evaluation []conformanceCase `json:"evaluation"`
}

// directoryEntry is one user of the interop scenario's directory.
type directoryEntry struct {
	ID    string   `json:"id"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

type conformanceDirectory struct {
	Users []directoryEntry `json:"users"`

	// calls counts lookups that actually reached the directory, so a test can
	// tell the fact plane's TTL cache is in front of it.
	calls atomic.Int64
}

// serve starts the directory as an HTTP fact source.
//
// The interop scenario's PDP is expected to know who the opaque subject
// identifiers are. In STAMP that knowledge is not policy data, so it is served
// here the way any deployment would serve it: behind the declared fact sources,
// through the fact plane's own egress gate, cache and timeouts.
func (d *conformanceDirectory) serve(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /directory/role_members", func(w http.ResponseWriter, r *http.Request) {
		d.calls.Add(1)
		role := r.URL.Query().Get("role")
		members := []string{}
		for _, u := range d.Users {
			for _, held := range u.Roles {
				if held == role {
					members = append(members, u.ID)
					break
				}
			}
		}
		sort.Strings(members)
		writeFact(w, members)
	})
	mux.HandleFunc("GET /directory/user_email", func(w http.ResponseWriter, r *http.Request) {
		d.calls.Add(1)
		id := r.URL.Query().Get("user_id")
		for _, u := range d.Users {
			if u.ID == id {
				writeFact(w, u.Email)
				return
			}
		}
		http.Error(w, "unknown user", http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func writeFact(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"value": value})
}

func readJSONFile(t *testing.T, name string, into any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(conformanceDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

func readFixtures(t *testing.T) conformanceFixtures {
	t.Helper()
	var fixtures conformanceFixtures
	readJSONFile(t, "decisions-authorization-api-1_0-01.json", &fixtures)
	return fixtures
}

// newConformanceFixture wires the interop deployment: the ported policy set,
// the directory behind the declared fact sources, and the AuthZEN surface in
// front.
func newConformanceFixture(t *testing.T) (*fixture, *conformanceDirectory) {
	t.Helper()
	set, err := policy.LoadFS(os.DirFS(filepath.Join(conformanceDir, "policies")))
	if err != nil {
		t.Fatalf("load conformance policies: %v", err)
	}

	dir := &conformanceDirectory{}
	readJSONFile(t, "directory.json", dir)
	server := dir.serve(t)

	registry, err := fact.NewRegistry([]fact.Declaration{
		{
			Name:    "role_members",
			Kind:    policy.SourceHTTP,
			Params:  []policy.Param{{Name: "role", Type: policy.TypeString}},
			Returns: policy.ListOf(policy.TypeString),
			TTL:     time.Minute,
			Timeout: 5 * time.Second,
			URL:     server.URL + "/directory/role_members",
		},
		{
			Name:    "user_email",
			Kind:    policy.SourceHTTP,
			Params:  []policy.Param{{Name: "user_id", Type: policy.TypeString}},
			Returns: policy.TypeString,
			TTL:     time.Minute,
			Timeout: 5 * time.Second,
			URL:     server.URL + "/directory/user_email",
		},
	}, fact.Config{Egress: fact.EgressConfig{
		Allow:         []string{server.URL},
		AllowLoopback: true,
	}})
	if err != nil {
		t.Fatalf("build fact registry: %v", err)
	}
	t.Cleanup(registry.Close)

	// The load gate: a policy set naming a source this deployment cannot serve
	// is refused before it is ever evaluated against.
	if err := registry.VerifySchema(&set.Schema); err != nil {
		t.Fatalf("verify schema against the deployment: %v", err)
	}
	resolver, err := api.NewFactResolver(registry)
	if err != nil {
		t.Fatalf("build fact resolver: %v", err)
	}

	return newFixture(t, fixtureOptions{
		loader:   staticLoader(snapshotOf(t, set, "interop-1"), "interop-1"),
		resolver: resolver,
		// The harness sends `ownerID`; a STAMP attribute name is a CEL
		// identifier, so the deployment maps the two explicitly.
		aliases:  map[string]string{"ownerID": "owner_id"},
		revision: "interop-1",
	}), dir
}

func TestAuthZENAccessEvaluationConformance(t *testing.T) {
	t.Parallel()
	f, _ := newConformanceFixture(t)
	fixtures := readFixtures(t)

	// The upstream Access Evaluation profile is exactly forty cases at the
	// pinned commit. Asserting the count is what stops a silently empty run
	// from passing, which is the same failure the workflow's wrapper guards
	// against on the other side.
	const wantCases = 40
	if len(fixtures.Evaluation) != wantCases {
		t.Fatalf("fixtures: want %d evaluation cases, got %d", wantCases, len(fixtures.Evaluation))
	}

	passed := 0
	for i, tc := range fixtures.Evaluation {
		body, err := json.Marshal(tc.Request)
		if err != nil {
			t.Fatalf("case %d: marshal: %v", i, err)
		}
		status, resp := f.evaluate(t, string(body))
		if status != http.StatusOK {
			t.Fatalf("case %d: status %d for %s", i, status, body)
		}
		if resp.Decision != tc.Expected {
			t.Errorf("case %d: decision %v, want %v\n  request: %s\n  reason: %s",
				i, resp.Decision, tc.Expected, body, f.reasonOf(t, resp))
			continue
		}
		passed++
	}
	if passed != wantCases {
		t.Fatalf("conformance: %d/%d cases passed", passed, wantCases)
	}
}

// The batch endpoint and the Search APIs are deferred, and the conformance
// target is pinned to the single Access Evaluation profile. An unimplemented
// endpoint must therefore be absent rather than half-answered, so that a client
// discovers it is not offered instead of receiving a verdict from it.
func TestBatchEvaluationEndpointIsNotOffered(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	req := httptest.NewRequest(http.MethodPost, "/access/v1/evaluations", strings.NewReader(`{"evaluations":[]}`))
	req.Header.Set("Authorization", "Bearer "+f.idp.token(t, "svc-a", testClientID))
	rec := httptest.NewRecorder()
	f.server.Handler(api.SurfacePEP).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("the batch endpoint answered %d", rec.Code)
	}
}

// R14: a check-path source lookup is served from cache within the declared
// TTL. Forty requests over a five-user directory must not become forty
// directory calls, and the compiled programs must be reused across them.
func TestConformanceRunSharesTheCompileAndFactCaches(t *testing.T) {
	t.Parallel()
	f, dir := newConformanceFixture(t)
	fixtures := readFixtures(t)

	for i, tc := range fixtures.Evaluation {
		body, err := json.Marshal(tc.Request)
		if err != nil {
			t.Fatalf("case %d: marshal: %v", i, err)
		}
		f.evaluate(t, string(body))
	}

	// Three roles plus five user identifiers is the whole distinct call set the
	// fixtures can reach; the declared TTL covers the rest.
	if calls := dir.calls.Load(); calls > 8 {
		t.Fatalf("directory calls: want at most 8 within the declared TTL, got %d", calls)
	}
	stats := f.service.Stats()
	// Five policies, one compilation each, however many requests arrive.
	if stats.Cache.Compilations != 5 {
		t.Fatalf("compilations: want 5, got %d", stats.Cache.Compilations)
	}
	if stats.Cache.Hits == 0 {
		t.Fatalf("the compile cache was never hit: %+v", stats.Cache)
	}
	if stats.Revision != engine.Revision("interop-1") {
		t.Fatalf("revision: %q", stats.Revision)
	}
}
