package release_test

// routes_test.go is the structural half of R11, and the half a version string
// cannot be.
//
// The version gate next door reads three numbers and compares them to three
// constants. It passes whatever the decision API's endpoint table says, because
// the document's major comes from a path constant that does not move when a
// route is added, removed or moved to another listener (#44). A document that
// denies an endpoint the binary serves is worse than no document: it is
// believed, and the endpoint it denies is reachable.
//
// So the two are compared as sets. The document's endpoint table is the
// declaration; testdata/mounted-routes.json is what the composition root really
// mounts, rendered by internal/runtime where the assembled registry exists. A
// route with no row, a row with no route, and a row that names the wrong
// listener or the wrong credential are each a failure here.
//
// GET /healthz is deliberately outside the comparison. Every surface answers it
// whatever the roles are, because [api.Server] mounts it rather than a
// component, so it appears in no registry and belongs in the document's prose
// rather than in a table whose fourth column is a role.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	decisionAPIDoc = "../../docs/contracts/decision-api.md"
	mountTableFile = "testdata/mounted-routes.json"
	// The heading the endpoint table lives under. The heading is matched rather
	// than the table's position, so a section added above it does not silently
	// move the parser onto another table.
	endpointHeading = "## Endpoints"
)

// endpoint is one endpoint as both sides state it: the listener it is on, the
// credential it asks for, and the roles that serve it.
type endpoint struct {
	surface string
	auth    string
	roles   string
}

func (e endpoint) String() string {
	return e.surface + " / " + e.auth + " / " + e.roles
}

// --- the mounted side -----------------------------------------------------

type mountedRoute struct {
	Name    string   `json:"name"`
	Roles   []string `json:"roles"`
	Surface string   `json:"surface"`
	Pattern string   `json:"pattern"`
	Auth    string   `json:"auth"`
}

type mountTable struct {
	Routes []mountedRoute `json:"routes"`
}

func loadMountTable(t *testing.T, path string) mountTable {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v (run `go test ./internal/runtime/ -run TestTheMountTableFileIsUpToDate`, "+
			"which needs a Docker daemon)", path, err)
	}
	var table mountTable
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(table.Routes) == 0 {
		t.Fatalf("%s lists no routes", path)
	}
	return table
}

// endpoints keys the table by pattern. Two routes on one pattern would be two
// listeners answering the same method and path, which the document's one row
// per pattern cannot say — so it is reported here rather than silently
// collapsed.
func (m mountTable) endpoints(t *testing.T) map[string]endpoint {
	t.Helper()
	out := make(map[string]endpoint, len(m.Routes))
	for _, r := range m.Routes {
		if _, dup := out[r.Pattern]; dup {
			t.Fatalf("%q is mounted on more than one surface; the contract document has one row "+
				"per pattern and cannot state that", r.Pattern)
		}
		roles := append([]string(nil), r.Roles...)
		sort.Strings(roles)
		out[r.Pattern] = endpoint{surface: r.Surface, auth: r.Auth, roles: strings.Join(roles, ",")}
	}
	return out
}

// surfacesOf returns the listeners one role's routes are mounted on.
func (m mountTable) surfacesOf(role string) []string {
	seen := map[string]struct{}{}
	for _, r := range m.Routes {
		for _, have := range r.Roles {
			if have == role {
				seen[r.Surface] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// surfacesOfEveryRole returns the listeners any role's routes are mounted on.
//
// It is the all-in-one tier's answer to surfacesOf: that tier is started with
// --roles=all, so every route in this table is mounted in its process and every
// surface in it is one it has to bind.
func (m mountTable) surfacesOfEveryRole() []string {
	seen := map[string]struct{}{}
	for _, r := range m.Routes {
		seen[r.Surface] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// pathsOn returns the request paths mounted on one surface, with the method
// dropped and duplicates collapsed: one path served by two methods is one thing
// a deployment either reaches or does not.
func (m mountTable) pathsOn(surface string) []string {
	seen := map[string]struct{}{}
	for _, r := range m.Routes {
		if r.Surface != surface {
			continue
		}
		fields := strings.Fields(r.Pattern)
		seen[fields[len(fields)-1]] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// patternsOn returns the patterns one role mounts on one surface, for a message
// that names what became unreachable rather than only which listener did.
func (m mountTable) patternsOn(role, surface string) []string {
	var out []string
	for _, r := range m.Routes {
		if r.Surface != surface {
			continue
		}
		for _, have := range r.Roles {
			if have == role {
				out = append(out, r.Pattern)
			}
		}
	}
	sort.Strings(out)
	return out
}

// --- the documented side ---------------------------------------------------

// parseEndpointTable reads the endpoint table out of a contract document.
//
// A cell's first backticked run is its value: the document annotates rows in
// prose ("(subtree)") and the annotation is not part of what is compared.
func parseEndpointTable(t *testing.T, path string) map[string]endpoint {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	lines := strings.Split(string(raw), "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == endpointHeading {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s has no %q section: the contract document has to state its endpoints "+
			"somewhere a machine can read them", path, endpointHeading)
	}

	out := map[string]endpoint{}
	inTable := false
	for _, line := range lines[start:] {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			if inTable {
				break
			}
			continue
		}
		inTable = true
		cells := tableCells(trimmed)
		if len(cells) != 4 {
			t.Fatalf("%s: endpoint row %q has %d cells, want 4 (pattern, surface, auth, roles)",
				path, trimmed, len(cells))
		}
		pattern := backticked(cells[0])
		if pattern == "" {
			// The header and the |---| separator, and nothing else: every real
			// row states its pattern in backticks.
			continue
		}
		if _, dup := out[pattern]; dup {
			t.Fatalf("%s lists %q twice", path, pattern)
		}
		roles := allBackticked(cells[3])
		sort.Strings(roles)
		out[pattern] = endpoint{
			surface: strings.ToLower(strings.TrimSpace(cells[1])),
			auth:    strings.ToLower(strings.TrimSpace(cells[2])),
			roles:   strings.Join(roles, ","),
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s has an %q section with no endpoint rows in it", path, endpointHeading)
	}
	return out
}

func tableCells(row string) []string {
	parts := strings.Split(strings.Trim(row, "|"), "|")
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.TrimSpace(p)
	}
	return out
}

func backticked(cell string) string {
	all := allBackticked(cell)
	if len(all) == 0 {
		return ""
	}
	return all[0]
}

func allBackticked(cell string) []string {
	var out []string
	rest := cell
	for {
		open := strings.Index(rest, "`")
		if open < 0 {
			return out
		}
		rest = rest[open+1:]
		closing := strings.Index(rest, "`")
		if closing < 0 {
			return out
		}
		if value := strings.TrimSpace(rest[:closing]); value != "" {
			out = append(out, value)
		}
		rest = rest[closing+1:]
	}
}

// --- the comparison --------------------------------------------------------

// routeDrift reports every way the declaration and the route table disagree.
// It is a function over two maps so that the self-check below can hand it
// planted drift and watch the same code report it.
func routeDrift(documented, mounted map[string]endpoint) []string {
	var problems []string
	for pattern, got := range mounted {
		want, ok := documented[pattern]
		if !ok {
			problems = append(problems, "mounted and undocumented: "+pattern+" ("+got.String()+
				") is served and the contract document does not list it")
			continue
		}
		if want != got {
			problems = append(problems, "drifted: "+pattern+" is documented as "+want.String()+
				" and mounted as "+got.String())
		}
	}
	for pattern, want := range documented {
		if _, ok := mounted[pattern]; !ok {
			problems = append(problems, "documented and unmounted: "+pattern+" ("+want.String()+
				") is in the contract document and no component mounts it")
		}
	}
	sort.Strings(problems)
	return problems
}

// TestTheContractDocumentAndTheMountedRoutesAreTheSameSet is #44 closed: the
// endpoint table and the router describe one API.
func TestTheContractDocumentAndTheMountedRoutesAreTheSameSet(t *testing.T) {
	documented := parseEndpointTable(t, decisionAPIDoc)
	mounted := loadMountTable(t, mountTableFile).endpoints(t)

	if problems := routeDrift(documented, mounted); len(problems) > 0 {
		t.Errorf("the decision API contract and the mounted routes disagree:\n  %s\n\n"+
			"the document is %s and the routes are %s, regenerated by "+
			"TestTheMountTableFileIsUpToDate in internal/runtime.",
			strings.Join(problems, "\n  "), decisionAPIDoc, mountTableFile)
	}
}

// TestTheRouteDriftCheckFails is the self-check. A comparison that has only
// ever agreed is not known to compare anything, and every fixture below is one
// way the declaration and the code are supposed to be caught apart.
func TestTheRouteDriftCheckFails(t *testing.T) {
	const fixtures = "testdata/routes-drift"

	// The control. It shares the parsers and the comparison with the three
	// cases below, so a fixture set that failed for a structural reason —
	// an unreadable table, a loader that returns nothing — would show up here
	// rather than as three passing drift assertions.
	t.Run("an aligned fixture reports nothing", func(t *testing.T) {
		dir := filepath.Join(fixtures, "aligned")
		problems := routeDrift(
			parseEndpointTable(t, filepath.Join(dir, "decision-api.md")),
			loadMountTable(t, filepath.Join(dir, "mounted-routes.json")).endpoints(t),
		)
		if len(problems) > 0 {
			t.Fatalf("the aligned fixture reported drift:\n  %s", strings.Join(problems, "\n  "))
		}
	})

	cases := map[string]struct {
		dir  string
		want string
	}{
		"a route is mounted that the document does not list": {
			dir:  "mounted-undocumented",
			want: "mounted and undocumented: POST /decisions/{id}/challenges/{ordinal}/mfa",
		},
		"the document lists a route nothing mounts": {
			dir:  "documented-unmounted",
			want: "documented and unmounted: GET /decisions/inbox",
		},
		"a documented route is mounted on another listener": {
			dir:  "surface-drifted",
			want: "drifted: POST /decisions is documented as console",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(fixtures, tc.dir)
			problems := routeDrift(
				parseEndpointTable(t, filepath.Join(dir, "decision-api.md")),
				loadMountTable(t, filepath.Join(dir, "mounted-routes.json")).endpoints(t),
			)
			if len(problems) == 0 {
				t.Fatalf("%s reported no drift, and it is planted drift", dir)
			}
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Errorf("%s was caught but not named: want %q in\n  %s",
					dir, tc.want, strings.Join(problems, "\n  "))
			}
		})
	}
}
