package release_test

// errorcodes_test.go is the consumer side of the error code artifact, and it
// stands to console/contract/error-codes.json the way routes_test.go stands to
// testdata/mounted-routes.json.
//
// The renderer lives in internal/api, where the syntax tree is. This file reads
// only the committed bytes, and that separation is the point: a renderer's own
// test cannot tell the difference between "the package emits nothing" and "the
// scan found nothing", because both produce the same empty document. Reading
// the file as a stranger does — knowing only that a binary serving three
// listeners must be able to refuse something on each of them — is what turns an
// empty or truncated artifact into a failure rather than into a set difference
// the console side then reports against the wrong side.
//
// It is here rather than in internal/api for the reason the package doc gives:
// these are the gates a release has to pass, and the error vocabulary is one of
// the three public contracts R11 covers.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	errorCodeFile      = "../../console/contract/error-codes.json"
	errorExemptionFile = "../../console/contract/error-code-exemptions.json"
	// The heading the unimplemented-surface table lives under, matched rather
	// than located by position for the reason routes_test.go matches its own:
	// a section added above it must not silently move the parser onto another
	// table.
	unimplementedHeading = "## 콘솔이 부르지 않는 표면"
)

// errorCodeDocumentVersion is the shape the console's check knows how to read.
// It is restated here rather than imported because internal/release imports
// nothing from the product on purpose, and because a version that changed on
// one side only is exactly what this constant is for.
const errorCodeDocumentVersion = 1

// The listeners the binary binds. A code artifact that has lost one of them has
// lost every code on it, and the console would read the loss as "the server no
// longer emits this" — which is the shape of the incident this whole round
// closes, arriving from the other direction.
var errorCodeSurfaces = []string{"callback", "console", "pep"}

type emittedCode struct {
	Code     string   `json:"code"`
	Statuses []int    `json:"statuses"`
	Surfaces []string `json:"surfaces"`
}

type errorCodeDocument struct {
	Version  int           `json:"version"`
	Note     string        `json:"note"`
	Surfaces []string      `json:"surfaces"`
	Codes    []emittedCode `json:"codes"`
}

// wireToken is the spelling every code in this API uses: lower case, digits and
// underscores. It is not a style rule — the console branches on these as
// literals and a code with a space or a capital in it is a code somebody
// mistyped into a table where nothing would catch it.
var wireToken = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func loadErrorCodes(t *testing.T, path string) errorCodeDocument {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v (run `go test ./internal/api/ -run TestErrorCodeFileIsUpToDate`)", path, err)
	}
	var doc errorCodeDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return doc
}

// errorCodeProblems reports every way the artifact is not usable as the
// server's half of a set comparison.
//
// It is a function over a decoded document so that the self-check below can
// hand it planted damage and watch the same code report it.
func errorCodeProblems(doc errorCodeDocument) []string {
	var problems []string

	if doc.Version != errorCodeDocumentVersion {
		problems = append(problems, fmt.Sprintf(
			"the document states version %d and the console's check reads version %d",
			doc.Version, errorCodeDocumentVersion))
	}
	if !strings.Contains(doc.Note, "internal/api") {
		problems = append(problems, "the document's note does not say what generates it; "+
			"a contributor who finds it stale has to be told where to look")
	}
	if len(doc.Codes) == 0 {
		problems = append(problems, "the document lists no error codes at all, which no build of "+
			"this binary can be true of: the generator ran and found nothing")
	}

	seen := map[string]bool{}
	perSurface := map[string]int{}
	for _, c := range doc.Codes {
		switch {
		case c.Code == "":
			problems = append(problems, "a row states no code")
		case !wireToken.MatchString(c.Code):
			problems = append(problems, fmt.Sprintf("%q is not a wire token", c.Code))
		case seen[c.Code]:
			problems = append(problems, fmt.Sprintf(
				"%q is listed twice; the console reads this into a set and would never notice",
				c.Code))
		}
		seen[c.Code] = true

		if len(c.Statuses) == 0 {
			problems = append(problems, fmt.Sprintf("%q is written under no status", c.Code))
		}
		for _, status := range c.Statuses {
			if status < 400 || status > 599 {
				problems = append(problems, fmt.Sprintf(
					"%q is written under status %d, and an error code outside 4xx/5xx means the "+
						"renderer read a success path as a refusal", c.Code, status))
			}
		}
		if len(c.Surfaces) == 0 {
			problems = append(problems, fmt.Sprintf(
				"%q reaches no listener; the console cannot tell whether it needs to handle it", c.Code))
		}
		for _, surface := range c.Surfaces {
			known := false
			for _, bound := range errorCodeSurfaces {
				if surface == bound {
					known = true
				}
			}
			if !known {
				problems = append(problems, fmt.Sprintf("%q names unknown listener %q", c.Code, surface))
				continue
			}
			perSurface[surface]++
		}
	}

	for _, surface := range errorCodeSurfaces {
		if perSurface[surface] == 0 {
			problems = append(problems, fmt.Sprintf(
				"no code reaches the %s listener; every listener this binary binds can refuse "+
					"something, so this is the renderer losing a surface rather than a surface "+
					"that refuses nothing", surface))
		}
	}

	sort.Strings(problems)
	return problems
}

// TestTheErrorCodeArtifactIsUsable is the release gate: the committed document
// is one a machine on the other side of the wire can compare against.
func TestTheErrorCodeArtifactIsUsable(t *testing.T) {
	doc := loadErrorCodes(t, errorCodeFile)
	if problems := errorCodeProblems(doc); len(problems) > 0 {
		t.Errorf("%s is not usable as the server's half of the error vocabulary:\n  %s\n\n"+
			"it is regenerated by TestErrorCodeFileIsUpToDate in internal/api.",
			errorCodeFile, strings.Join(problems, "\n  "))
	}
}

// TestTheUnimplementedSurfacesAgree keeps the contract document's account of
// what the console does not implement and the console's own list from drifting.
//
// Two documents saying the same thing is two documents that will one day say
// different things. The console's list is the one a machine already enforces —
// scripts/check-contract.mjs fails on a declared endpoint no screen calls and
// no entry names, and on an entry naming an endpoint some screen does call — so
// the document is compared against it rather than the other way round.
//
// It matters because the exemption the code vocabulary rests on is the same
// idea. The console does not handle the callback listener's refusals because it
// never calls that listener; if "what the console does not reach" is a belief
// rather than a checked list, then so is every exemption resting on it.
func TestTheUnimplementedSurfacesAgree(t *testing.T) {
	documented := parseUnimplementedTable(t, decisionAPIDoc)
	listed := loadUnimplementedEndpoints(t, errorExemptionFile)

	var problems []string
	for name := range documented {
		if _, ok := listed[name]; !ok {
			problems = append(problems, name+" is in the contract document's unimplemented table "+
				"and not in "+errorExemptionFile)
		}
	}
	for name, reason := range listed {
		if _, ok := documented[name]; !ok {
			problems = append(problems, name+" is listed as unimplemented in "+errorExemptionFile+
				" and the contract document does not say so")
		}
		if strings.TrimSpace(reason) == "" {
			problems = append(problems, name+" is listed as unimplemented with no reason")
		}
	}
	if len(documented) == 0 {
		problems = append(problems, decisionAPIDoc+" has an "+unimplementedHeading+
			" section with no rows in it")
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Errorf("the contract document and the console's unimplemented list disagree:\n  %s",
			strings.Join(problems, "\n  "))
	}
}

// parseUnimplementedTable reads the endpoint names out of the document's
// unimplemented table. A row may name more than one — two halves of one file
// authoring path share a reason — so every backticked run in the first cell
// counts.
func parseUnimplementedTable(t *testing.T, path string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(string(raw), "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == unimplementedHeading {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s has no %q section: the console's unimplemented surfaces have to be stated "+
			"somewhere a machine can read them, or the exemptions resting on them are a belief",
			path, unimplementedHeading)
	}

	out := map[string]bool{}
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
		if len(cells) != 2 {
			t.Fatalf("%s: unimplemented row %q has %d cells, want 2 (endpoint, reason)",
				path, trimmed, len(cells))
		}
		for _, name := range allBackticked(cells[0]) {
			out[name] = true
		}
	}
	return out
}

func loadUnimplementedEndpoints(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Endpoints []struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	out := make(map[string]string, len(doc.Endpoints))
	for _, e := range doc.Endpoints {
		out[e.Name] = e.Reason
	}
	return out
}

// TestTheErrorCodeArtifactTripwiresFire is the self-check.
//
// Every case is one way a generator fails quietly — it renders nothing, it
// loses a listener, it writes a code twice, it renders a success path. The
// aligned control shares the whole comparison with them, so a check that had
// stopped reporting anything would show up there rather than as four passing
// assertions.
func TestTheErrorCodeArtifactTripwiresFire(t *testing.T) {
	aligned := errorCodeDocument{
		Version: errorCodeDocumentVersion,
		Note:    "Generated by TestErrorCodeFileIsUpToDate in internal/api.",
		Codes: []emittedCode{
			{Code: "not_found", Statuses: []int{404}, Surfaces: []string{"console", "pep"}},
			{Code: "rejected", Statuses: []int{403}, Surfaces: []string{"callback"}},
		},
	}

	t.Run("an aligned document reports nothing", func(t *testing.T) {
		if problems := errorCodeProblems(aligned); len(problems) > 0 {
			t.Fatalf("the aligned document reported problems:\n  %s", strings.Join(problems, "\n  "))
		}
	})

	cases := map[string]struct {
		damage func(errorCodeDocument) errorCodeDocument
		want   string
	}{
		"the generator rendered nothing": {
			damage: func(d errorCodeDocument) errorCodeDocument { d.Codes = nil; return d },
			want:   "lists no error codes at all",
		},
		"a listener lost every code it had": {
			damage: func(d errorCodeDocument) errorCodeDocument {
				d.Codes = d.Codes[:1]
				return d
			},
			want: "no code reaches the callback listener",
		},
		"a code is listed twice": {
			damage: func(d errorCodeDocument) errorCodeDocument {
				d.Codes = append(append([]emittedCode(nil), d.Codes...), d.Codes[0])
				return d
			},
			want: "is listed twice",
		},
		"a success path was read as a refusal": {
			damage: func(d errorCodeDocument) errorCodeDocument {
				codes := append([]emittedCode(nil), d.Codes...)
				codes[0].Statuses = []int{200}
				d.Codes = codes
				return d
			},
			want: "read a success path as a refusal",
		},
		"the document shape moved out from under the console": {
			damage: func(d errorCodeDocument) errorCodeDocument { d.Version = 99; return d },
			want:   "the console's check reads version",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			problems := errorCodeProblems(tc.damage(aligned))
			if len(problems) == 0 {
				t.Fatalf("%s reported nothing, and it is planted damage", name)
			}
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Errorf("%s was caught but not named: want %q in\n  %s",
					name, tc.want, strings.Join(problems, "\n  "))
			}
		})
	}
}
