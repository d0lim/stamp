package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/store"
)

// allowlistSet is the smallest policy set that exercises all three check-path
// verdicts: an allowlist hit, an allowlist miss, and a policy that carries a
// challenge and therefore cannot be satisfied here at all.
const allowlistSet = `
apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes: {id: string}
  - name: doc
    attributes: {id: string, owner_id: string}
actions: [read, publish]
---
apiVersion: stamp/v1
kind: Policy
id: allowlist-read
subject: user
resource: doc
actions: [read]
condition:
  left: {field: subject.id}
  in: [alice, bob]
---
apiVersion: stamp/v1
kind: Policy
id: gated-publish
subject: user
resource: doc
actions: [publish]
condition:
  left: {field: subject.id}
  in: [alice]
challenges:
  - type: quorum
    threshold: 2
    approvers: {members: [carol, dave]}
`

func evaluationBody(subjectID, action, resourceType string) string {
	return fmt.Sprintf(`{
		"subject": {"type": "user", "id": %q},
		"action": {"name": %q},
		"resource": {"type": %q, "id": "doc-1"}
	}`, subjectID, action, resourceType)
}

func TestAllowlistHitAndMiss(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	status, hit := f.evaluate(t, evaluationBody("alice", "read", "doc"))
	if status != http.StatusOK || !hit.Decision {
		t.Fatalf("allowlist hit: status %d, decision %v", status, hit.Decision)
	}
	if reason := f.reasonOf(t, hit); reason != string(engine.ReasonPolicyMatched) {
		t.Fatalf("allowlist hit reason: %q", reason)
	}
	if id := hit.Context[api.ContextKeyPolicyID]; id != "allowlist-read" {
		t.Fatalf("allowlist hit policy id: %v", id)
	}

	status, miss := f.evaluate(t, evaluationBody("mallory", "read", "doc"))
	if status != http.StatusOK || miss.Decision {
		t.Fatalf("allowlist miss: status %d, decision %v", status, miss.Decision)
	}
	if reason := f.reasonOf(t, miss); reason != string(engine.ReasonConditionNotMet) {
		t.Fatalf("allowlist miss reason: %q", reason)
	}
}

func TestChallengeBearingPolicyDeniesWithRequiresDecision(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	// alice satisfies the gated policy's condition. The check path still
	// refuses, because the policy carries a challenge and this path cannot
	// issue one.
	_, resp := f.evaluate(t, evaluationBody("alice", "publish", "doc"))
	if resp.Decision {
		t.Fatal("a policy carrying a challenge was allowed on the check path")
	}
	if reason := f.reasonOf(t, resp); reason != string(engine.ReasonRequiresDecision) {
		t.Fatalf("reason: want %q, got %q", engine.ReasonRequiresDecision, reason)
	}
}

func TestNoMatchingPolicyDenies(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	for _, tc := range []struct {
		name string
		body string
	}{
		{"unknown action", evaluationBody("alice", "archive", "doc")},
		{"unknown resource type", evaluationBody("alice", "read", "ledger")},
	} {
		_, resp := f.evaluate(t, tc.body)
		if resp.Decision {
			t.Fatalf("%s: allowed", tc.name)
		}
		if reason := f.reasonOf(t, resp); reason != string(engine.ReasonNoMatchingPolicy) {
			t.Fatalf("%s: reason %q", tc.name, reason)
		}
	}
}

// A standard AuthZEN consumer reads `decision` and drops everything else. Every
// verdict this surface produces has to survive that, which means the boolean
// alone must never disagree with the reason we would have told a STAMP-aware
// client.
func TestStandardConsumerIgnoringContextReadsTheSameVerdict(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	cases := []struct {
		name  string
		body  string
		allow bool
	}{
		{"allowlist hit", evaluationBody("alice", "read", "doc"), true},
		{"allowlist miss", evaluationBody("mallory", "read", "doc"), false},
		{"challenge bearing", evaluationBody("alice", "publish", "doc"), false},
		{"no matching policy", evaluationBody("alice", "archive", "doc"), false},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, api.EvaluationPath, strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+f.idp.token(t, "svc-a", testClientID))
		rec := httptest.NewRecorder()
		f.server.Handler(api.SurfacePEP).ServeHTTP(rec, req)

		// Decode into a type that has no context field at all: this is the
		// consumer that does not know STAMP exists.
		var standard struct {
			Decision bool `json:"decision"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &standard); err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		if standard.Decision != tc.allow {
			t.Fatalf("%s: standard consumer read %v, want %v", tc.name, standard.Decision, tc.allow)
		}

		var full api.EvaluationResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &full); err != nil {
			t.Fatalf("%s: decode full: %v", tc.name, err)
		}
		if full.Decision != standard.Decision {
			t.Fatalf("%s: the context-aware and context-blind readings disagree", tc.name)
		}
		// Everything STAMP-specific is namespaced, so a consumer that keeps the
		// context cannot collide with a field the specification may add.
		for key := range full.Context {
			if !strings.HasPrefix(key, "stamp.") {
				t.Fatalf("%s: response context carries un-namespaced key %q", tc.name, key)
			}
		}
	}
}

func TestUnauthenticatedRequestIsRejectedBeforeEvaluation(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	before := f.buffer.Stats().Enqueued
	req := httptest.NewRequest(http.MethodPost, api.EvaluationPath, strings.NewReader(evaluationBody("alice", "read", "doc")))
	rec := httptest.NewRecorder()
	f.server.Handler(api.SurfacePEP).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: want 401, got %d", rec.Code)
	}
	if rec.Body.String() == "" || strings.Contains(rec.Body.String(), "decision") {
		t.Fatalf("an unauthenticated request must not receive a verdict: %q", rec.Body.String())
	}

	records := f.auth.all()
	if len(records) != 1 {
		t.Fatalf("audit records: want 1, got %d", len(records))
	}
	rejection := records[0]
	if rejection.Allowed {
		t.Fatal("the rejection was audited as allowed")
	}
	if rejection.CallerID != "anonymous" {
		t.Fatalf("caller id: want anonymous, got %q", rejection.CallerID)
	}
	if rejection.Reason != identity.ReasonMissingCredential {
		t.Fatalf("reason: want %q, got %q", identity.ReasonMissingCredential, rejection.Reason)
	}
	if rejection.Path != api.EvaluationPath {
		t.Fatalf("path: %q", rejection.Path)
	}

	// One event reached the buffer — the rejection — and no judgment did.
	if got := f.buffer.Stats().Enqueued - before; got != 1 {
		t.Fatalf("events enqueued: want 1 (the rejection), got %d", got)
	}
}

func TestEndUserTokenIsRefusedAtThePEPSurface(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	// A valid token, but minted for a client the operator did not list as a
	// workload: it is an end user, and the PEP surface is not theirs.
	status, _ := f.evaluateAs(t, evaluationBody("alice", "read", "doc"), f.idp.token(t, "alice", "console-app"))
	if status != http.StatusForbidden {
		t.Fatalf("status: want 403, got %d", status)
	}
}

func TestJudgmentIsAuditedWithCallerAndPolicy(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	if _, resp := f.evaluate(t, evaluationBody("alice", "read", "doc")); !resp.Decision {
		t.Fatal("expected an allow")
	}
	if err := f.buffer.Flush(t.Context()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	batches, gaps := f.writer.snapshot()
	if len(gaps) != 0 {
		t.Fatalf("unexpected gap markers: %+v", gaps)
	}
	if len(batches) != 1 {
		t.Fatalf("batches: want 1, got %d", len(batches))
	}
	// Two events: the successful authentication and the judgment. Recomputing
	// the root from the events we expect is what makes this an assertion about
	// what reached the chain rather than about how many things did.
	want := store.MerkleRoot([][]byte{
		api.Event{
			Kind:     api.EventAuth,
			Time:     f.now,
			CallerID: "workload:" + f.idp.server.URL + "#svc-a",
			Reason:   identity.ReasonAuthenticated,
			Method:   http.MethodPost,
			Path:     api.EvaluationPath,
			Allowed:  true,
		}.Leaf(),
		api.Event{
			Kind:     api.EventCheck,
			Time:     f.now,
			CallerID: "workload:" + f.idp.server.URL + "#svc-a",
			Action:   "read",
			Subject:  "user:alice",
			Resource: "doc:doc-1",
			Decision: "allow",
			Reason:   string(engine.ReasonPolicyMatched),
			PolicyID: "allowlist-read",
			Revision: "rev-1",
			Method:   http.MethodPost,
			Path:     api.EvaluationPath,
			Allowed:  true,
		}.Leaf(),
	})
	if batches[0].Root != want {
		t.Fatalf("batch root does not match the events we expect in it:\n got %x\nwant %x", batches[0].Root, want)
	}
	if batches[0].Count != 2 {
		t.Fatalf("batch count: want 2, got %d", batches[0].Count)
	}
	if batches[0].Digest != api.AuditDigestScheme {
		t.Fatalf("digest scheme: %q", batches[0].Digest)
	}
}

// R32: when the buffer saturates the loss must be counted, must raise the
// alert, must appear in the chain as a gap, and — for an operator who chose
// fail-closed — must stop the surface judging.
func TestAuditSaturationCountsLosesAlertsAndFailsClosed(t *testing.T) {
	t.Parallel()
	var alerts int
	writer := &recordingWriter{}
	buffer, err := api.NewAuditBuffer(api.AuditConfig{
		Writer:         writer,
		Capacity:       2,
		AlertThreshold: 2,
		FailClosed:     true,
		OnAlert:        func(api.AuditStats) { alerts++ },
		Now:            func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("build buffer: %v", err)
	}

	for i := range 5 {
		buffer.Record(context.Background(), api.Event{Kind: api.EventCheck, CallerID: fmt.Sprintf("caller-%d", i)})
	}
	stats := buffer.Stats()
	if stats.Dropped != 3 {
		t.Fatalf("dropped: want 3, got %d", stats.Dropped)
	}
	if !stats.Alerting || alerts != 1 {
		t.Fatalf("alert: alerting=%v raised=%d", stats.Alerting, alerts)
	}
	if !buffer.FailClosed() {
		t.Fatal("the operator asked for fail-closed and the buffer is alerting, but FailClosed is false")
	}

	if err := buffer.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	_, gaps := writer.snapshot()
	if len(gaps) != 1 {
		t.Fatalf("gap markers: want 1, got %d", len(gaps))
	}
	if gaps[0].Dropped != 3 {
		t.Fatalf("gap dropped count: want 3, got %d", gaps[0].Dropped)
	}
	if gaps[0].Reason == "" {
		t.Fatal("the gap marker carries no reason")
	}
	// The hole is now recorded and the queue has drained, so the alert clears.
	if buffer.Alerting() {
		t.Fatal("the alert did not clear after the gap was chained and the queue drained")
	}
}

func TestCheckDeniesWhileTheAuditBufferIsFailClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{
		documents:  allowlistSet,
		failClosed: true,
		capacity:   1,
	})

	// Saturate: the first request's own audit events fill the one-event queue,
	// and the overflow raises the alert.
	for range 3 {
		f.evaluate(t, evaluationBody("alice", "read", "doc"))
	}
	if !f.buffer.FailClosed() {
		t.Fatalf("buffer did not go fail-closed: %+v", f.buffer.Stats())
	}

	_, resp := f.evaluate(t, evaluationBody("alice", "read", "doc"))
	if resp.Decision {
		t.Fatal("a fail-closed instance allowed a request it could not audit")
	}
	if reason := f.reasonOf(t, resp); reason != string(engine.ReasonAuditUnavailable) {
		t.Fatalf("reason: want %q, got %q", engine.ReasonAuditUnavailable, reason)
	}
}

func TestBufferKeepsJudgingWhenTheOperatorDidNotAskToFailClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet, capacity: 1})

	for range 3 {
		f.evaluate(t, evaluationBody("alice", "read", "doc"))
	}
	if f.buffer.Stats().Dropped == 0 {
		t.Fatal("expected the one-event queue to drop something")
	}
	if f.buffer.FailClosed() {
		t.Fatal("a deployment that did not ask for fail-closed was failed closed")
	}
	_, resp := f.evaluate(t, evaluationBody("alice", "read", "doc"))
	if !resp.Decision {
		t.Fatalf("judging stopped without the operator asking: %s", f.reasonOf(t, resp))
	}
}

func TestMalformedRequestIsRefusedRatherThanJudged(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	for _, body := range []string{
		`{"subject": {"type": "user"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "d"}}`,
		`{"subject": {"type": "user", "id": "alice"}, "resource": {"type": "doc", "id": "d"}}`,
		`not json`,
	} {
		req := httptest.NewRequest(http.MethodPost, api.EvaluationPath, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+f.idp.token(t, "svc-a", testClientID))
		rec := httptest.NewRecorder()
		f.server.Handler(api.SurfacePEP).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q: status %d", body, rec.Code)
		}
	}
}

// The specification lets a PEP attach properties we do not model. Refusing them
// would break interoperability; reading a declared one wrongly would change a
// decision. So an undeclared property is dropped and a declared one is
// converted or refused.
func TestUndeclaredPropertiesAreIgnoredAndDeclaredOnesAreTyped(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOptions{documents: allowlistSet})

	_, resp := f.evaluate(t, `{
		"subject": {"type": "user", "id": "alice", "properties": {"tenant": "acme", "seat_count": 3}},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "doc-1", "properties": {"owner_id": "alice"}}
	}`)
	if !resp.Decision {
		t.Fatalf("undeclared properties changed the verdict: %s", f.reasonOf(t, resp))
	}

	req := httptest.NewRequest(http.MethodPost, api.EvaluationPath, strings.NewReader(`{
		"subject": {"type": "user", "id": "alice"},
		"action": {"name": "read"},
		"resource": {"type": "doc", "id": "doc-1", "properties": {"owner_id": 42}}
	}`))
	req.Header.Set("Authorization", "Bearer "+f.idp.token(t, "svc-a", testClientID))
	rec := httptest.NewRecorder()
	f.server.Handler(api.SurfacePEP).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a declared attribute with the wrong type must be refused, got %d", rec.Code)
	}
}
