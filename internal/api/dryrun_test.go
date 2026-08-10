package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/policy"
)

// draftPolicy is unsaved: it names a policy identifier the effective set does
// not contain, and it is written against the effective schema.
const draftPolicy = `
apiVersion: stamp/v1
kind: Policy
id: draft-publish
subject: user
resource: doc
actions: [publish]
condition:
  all:
    - left: {field: subject.id}
      in: [alice, bob]
    - left: {field: resource.owner_id}
      op: eq
      right: alice
challenges:
  - type: quorum
    threshold: 2
    approvers: {members: [carol, dave]}
`

func (f *fixture) dryRun(t *testing.T, body string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, api.DryRunPath, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+f.idp.token(t, "operator", "console-app"))
	rec := httptest.NewRecorder()
	f.server.Handler(api.SurfaceConsole).ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func dryRunBody(t *testing.T, document string, input map[string]any) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"document": document, "input": input})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return string(body)
}

func TestDryRunReportsMatchPerConditionResultsAndChallengesWithoutStoring(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	before := f.buffer.Stats()
	beforeRevision := f.service.Revision()

	status, body := f.dryRun(t, dryRunBody(t, draftPolicy, map[string]any{
		"action":   "publish",
		"subject":  map[string]any{"type": "user", "id": "alice"},
		"resource": map[string]any{"type": "doc", "id": "doc-1", "attributes": map[string]any{"owner_id": "alice"}},
	}))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp api.DryRunResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.PolicyID != "draft-publish" {
		t.Fatalf("policy id: %q", resp.PolicyID)
	}
	if !resp.Matched || !resp.Holds {
		t.Fatalf("matched=%v holds=%v", resp.Matched, resp.Holds)
	}
	if resp.Reason != string(engine.ReasonRequiresDecision) {
		t.Fatalf("reason: %q", resp.Reason)
	}
	if len(resp.Challenges) != 1 || resp.Challenges[0].Type != string(policy.ChallengeQuorum) {
		t.Fatalf("challenges: %+v", resp.Challenges)
	}
	if got := resp.Challenges[0].Detail["threshold"]; got != float64(2) {
		t.Fatalf("challenge detail: %+v", resp.Challenges[0].Detail)
	}
	if len(resp.Conditions) != 3 {
		t.Fatalf("per-condition results: %+v", resp.Conditions)
	}
	for _, node := range resp.Conditions {
		if node.Result == nil || !*node.Result {
			t.Fatalf("condition %q: %v (%s)", node.Pointer, node.Result, node.Error)
		}
	}
	if resp.Stored {
		t.Fatal("the response claims something was stored")
	}

	// Nothing was written anywhere: no policy version, no audit event beyond
	// the authentication of the operator who asked.
	if f.service.Revision() != beforeRevision {
		t.Fatal("a dry run moved the effective policy revision")
	}
	after := f.buffer.Stats()
	if after.Enqueued-before.Enqueued != 1 {
		t.Fatalf("a dry run enqueued %d audit events beyond the operator's authentication",
			after.Enqueued-before.Enqueued-1)
	}
	if err := f.buffer.Flush(t.Context()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	batches, gaps := f.writer.snapshot()
	if len(gaps) != 0 {
		t.Fatalf("gap markers: %+v", gaps)
	}
	if len(batches) != 1 || batches[0].Count != 1 {
		t.Fatalf("a dry run put more than the operator's authentication into the chain: %+v", batches)
	}
}

func TestDryRunSeparatesTheFailingCondition(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	status, body := f.dryRun(t, dryRunBody(t, draftPolicy, map[string]any{
		"action":   "publish",
		"subject":  map[string]any{"type": "user", "id": "alice"},
		"resource": map[string]any{"type": "doc", "id": "doc-1", "attributes": map[string]any{"owner_id": "mallory"}},
	}))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp api.DryRunResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Matched || resp.Holds {
		t.Fatalf("matched=%v holds=%v", resp.Matched, resp.Holds)
	}
	if len(resp.Challenges) != 0 {
		t.Fatalf("challenges fired for a condition that did not hold: %+v", resp.Challenges)
	}
	results := map[string]bool{}
	for _, node := range resp.Conditions {
		if node.Result == nil {
			t.Fatalf("node %q: %s", node.Pointer, node.Error)
		}
		results[node.Pointer] = *node.Result
	}
	if !results["/condition/all/0"] || results["/condition/all/1"] {
		t.Fatalf("the failing row is not identified: %+v", results)
	}
}

// R44 and U2's contract meet here: a draft that fails validation comes back as
// the validator's own diagnostics, pointer and code included, so the console
// can put each one on the field that caused it.
func TestDryRunOfAnInvalidPolicyReturnsTheValidatorsDiagnostics(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	const invalid = `
apiVersion: stamp/v1
kind: Policy
id: broken
subject: user
resource: doc
actions: [read]
condition:
  left: {field: subject.rank}
  op: eq
  right: 3
`
	status, body := f.dryRun(t, dryRunBody(t, invalid, map[string]any{
		"action":   "read",
		"subject":  map[string]any{"type": "user", "id": "alice"},
		"resource": map[string]any{"type": "doc", "id": "doc-1"},
	}))
	if status != http.StatusBadRequest {
		t.Fatalf("status %d: %s", status, body)
	}
	var resp api.DiagnosticsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Diagnostics) == 0 {
		t.Fatalf("no diagnostics returned: %s", body)
	}

	// The same document through the library's own door produces the same
	// diagnostics; the surface passes them through rather than restating them.
	set := loadSet(t, allowlistSet)
	draft, decodeErr := policy.Decode(strings.NewReader(invalid))
	if decodeErr != nil {
		t.Fatalf("decode draft: %v", decodeErr)
	}
	direct := policy.Validate(&policy.Set{Schema: set.Schema, Policies: draft.Policies})
	if len(direct) != len(resp.Diagnostics) {
		t.Fatalf("diagnostics count: surface %d, validator %d", len(resp.Diagnostics), len(direct))
	}
	for i := range direct {
		if direct[i] != resp.Diagnostics[i] {
			t.Fatalf("diagnostic %d was rewritten:\nsurface   %+v\nvalidator %+v", i, resp.Diagnostics[i], direct[i])
		}
	}
	if !resp.Diagnostics.Has(policy.CodeUnknownAttribute) {
		t.Fatalf("expected an unknown-attribute code: %+v", resp.Diagnostics)
	}
}

// The sample input is a rendered form, not free-form JSON: an attribute the
// entity declaration does not carry is a mistake worth reporting rather than a
// key to ignore.
func TestDryRunRefusesUndeclaredSampleAttributes(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	status, body := f.dryRun(t, dryRunBody(t, draftPolicy, map[string]any{
		"action":   "publish",
		"subject":  map[string]any{"type": "user", "id": "alice", "attributes": map[string]any{"rank": "senior"}},
		"resource": map[string]any{"type": "doc", "id": "doc-1"},
	}))
	if status != http.StatusBadRequest {
		t.Fatalf("status %d: %s", status, body)
	}
}

func TestDryRunRequiresAUserCredential(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	body := dryRunBody(t, draftPolicy, map[string]any{
		"action":   "publish",
		"subject":  map[string]any{"type": "user", "id": "alice"},
		"resource": map[string]any{"type": "doc", "id": "doc-1"},
	})
	for _, tc := range []struct {
		name  string
		token string
		want  int
	}{
		{"no credential", "", http.StatusUnauthorized},
		{"workload credential", f.idp.token(t, "svc-a", testClientID), http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodPost, api.DryRunPath, strings.NewReader(body))
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		f.server.Handler(api.SurfaceConsole).ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s: status %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}

func TestDryRunNamesThePolicyWhenTheDocumentHasSeveral(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	twoPolicies := draftPolicy + `---
apiVersion: stamp/v1
kind: Policy
id: draft-read
subject: user
resource: doc
actions: [read]
condition:
  left: {field: subject.id}
  in: [alice]
`
	input := map[string]any{
		"action":   "read",
		"subject":  map[string]any{"type": "user", "id": "alice"},
		"resource": map[string]any{"type": "doc", "id": "doc-1"},
	}
	if status, _ := f.dryRun(t, dryRunBody(t, twoPolicies, input)); status != http.StatusBadRequest {
		t.Fatalf("an ambiguous document was accepted: status %d", status)
	}

	body, err := json.Marshal(map[string]any{"document": twoPolicies, "policy_id": "draft-read", "input": input})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	status, raw := f.dryRun(t, string(body))
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, raw)
	}
	var resp api.DryRunResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.PolicyID != "draft-read" || resp.Decision != engine.Allow.String() {
		t.Fatalf("unexpected result: %+v", resp)
	}
}
