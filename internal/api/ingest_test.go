package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/stream"
)

// The ingest surface is a write surface, and these tests are about the three
// things that follow from that: an unauthenticated caller does not reach the
// handler and is audited anyway, the caller identity the aggregation layer
// dedups by is the verified one rather than anything on the wire, and a
// refusal tells a stranger nothing they could enumerate a deployment with.
//
// What a credential may write, and how fast, is decided in the stream package
// and tested there. What is asserted here is the mapping between those
// outcomes and HTTP.

// recordingAdapter stands in for the ingest adapter.
type recordingAdapter struct {
	callers []string
	batches []stream.IngestBatch
	err     error
	result  stream.Result
}

func (a *recordingAdapter) Submit(_ context.Context, callerID string, batch stream.IngestBatch) (stream.Result, error) {
	a.callers = append(a.callers, callerID)
	a.batches = append(a.batches, batch)
	if a.err != nil {
		return stream.Result{}, a.err
	}
	return a.result, nil
}

type ingestFixture struct {
	server  *api.Server
	adapter *recordingAdapter
	idp     *mockIdP
	auth    *spySink
}

func newIngestFixture(t *testing.T) *ingestFixture {
	t.Helper()
	idp := newMockIdP(t)
	auth := &spySink{inner: identity.AuditSinkFunc(func(context.Context, identity.AuthRecord) {})}
	server, err := api.New(api.Config{
		Identity: idp.middleware(t, auth, func() time.Time { return fixedNow }),
		Addresses: map[api.Surface]string{
			api.SurfacePEP:      "127.0.0.1:0",
			api.SurfaceCallback: "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	adapter := &recordingAdapter{result: stream.Result{Applied: 2}}
	ingest, err := api.NewIngestAPI(api.IngestConfig{Adapter: adapter})
	if err != nil {
		t.Fatalf("build ingest api: %v", err)
	}
	if err := server.Mount(ingest); err != nil {
		t.Fatalf("mount: %v", err)
	}
	return &ingestFixture{server: server, adapter: adapter, idp: idp, auth: auth}
}

const ingestPath = "/ingest/v1/events"

func (f *ingestFixture) post(t *testing.T, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, ingestPath, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.server.Handler(api.SurfaceCallback).ServeHTTP(rec, req)
	return rec
}

const goodBatch = `{"source":"daily_withdrawal_total","events":[
	{"event_id":"e1","subject":"user-1","value":400,"produced_at":"2026-08-10T11:00:00Z"},
	{"event_id":"e2","subject":"user-1","value":350,"produced_at":"2026-08-10T11:30:00Z"}
]}`

// An authenticated batch reaches the adapter, and the caller it is attributed
// to is the verified credential's identifier — the same string the dedup key
// is namespaced by. Nothing in the request body can influence it.
func TestIngestAttributesTheBatchToTheVerifiedCaller(t *testing.T) {
	f := newIngestFixture(t)
	rec := f.post(t, f.idp.token(t, "producer-1", testClientID), goodBatch)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body)
	}
	var res api.IngestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if res.Accepted != 2 {
		t.Errorf("accepted = %d, want 2", res.Accepted)
	}
	if len(f.adapter.callers) != 1 {
		t.Fatalf("the adapter saw %d batches, want 1", len(f.adapter.callers))
	}
	if !strings.HasSuffix(f.adapter.callers[0], "#producer-1") {
		t.Errorf("caller = %q, want the verified subject identifier", f.adapter.callers[0])
	}
	if !strings.HasPrefix(f.adapter.callers[0], "workload:") {
		t.Errorf("caller = %q, want it qualified as a workload", f.adapter.callers[0])
	}
	batch := f.adapter.batches[0]
	if batch.Source != "daily_withdrawal_total" || len(batch.Events) != 2 {
		t.Fatalf("batch = %+v, want the two events for the named source", batch)
	}
	if want := time.Date(2026, 8, 10, 11, 0, 0, 0, time.UTC); !batch.Events[0].ProducedAt.Equal(want) {
		t.Errorf("produced_at = %s, want %s", batch.Events[0].ProducedAt, want)
	}
}

// An unauthenticated batch is refused before the handler runs, and the
// rejection is audited with a caller identifier even though there was no
// caller.
func TestIngestRefusesAndAuditsAnUnauthenticatedBatch(t *testing.T) {
	f := newIngestFixture(t)
	rec := f.post(t, "", goodBatch)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if len(f.adapter.batches) != 0 {
		t.Fatal("an unauthenticated batch reached the ingest adapter")
	}
	records := f.auth.all()
	if len(records) != 1 {
		t.Fatalf("the audit sink saw %d attempts, want 1", len(records))
	}
	if records[0].Allowed {
		t.Error("the refused attempt was audited as allowed")
	}
	if records[0].CallerID == "" {
		t.Error("the refused attempt was audited with no caller identifier")
	}
	if records[0].Path != ingestPath {
		t.Errorf("audited path = %q, want %q", records[0].Path, ingestPath)
	}
}

// An end-user token does not open the ingest endpoint. The surface's
// credential table admits a workload here, and the route asked for one.
func TestIngestRefusesAnEndUserToken(t *testing.T) {
	f := newIngestFixture(t)
	rec := f.post(t, f.idp.token(t, "alice", "console"), goodBatch)

	if rec.Code == http.StatusAccepted {
		t.Fatal("an end-user token was accepted for ingestion")
	}
	if len(f.adapter.batches) != 0 {
		t.Fatal("an end-user batch reached the ingest adapter")
	}
}

// The ingest endpoint is not reachable on the PEP surface. The separation is
// three routers rather than a path rule, so this is the assertion that the
// route went on the surface it was meant to.
func TestIngestIsNotOnThePEPSurface(t *testing.T) {
	f := newIngestFixture(t)
	req := httptest.NewRequest(http.MethodPost, ingestPath, strings.NewReader(goodBatch))
	req.Header.Set("Authorization", "Bearer "+f.idp.token(t, "producer-1", testClientID))
	rec := httptest.NewRecorder()
	f.server.Handler(api.SurfacePEP).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status on the PEP surface = %d, want 404", rec.Code)
	}
	if len(f.adapter.batches) != 0 {
		t.Fatal("a batch sent to the PEP surface reached the ingest adapter")
	}
}

// Every authorization refusal is one answer. Telling a caller apart "you have
// no grant" from "that source is not yours" from "no such source" would let a
// credential with one narrow grant enumerate the deployment's source names by
// reading status codes.
func TestIngestAuthorizationRefusalsAreIndistinguishable(t *testing.T) {
	bodies := make(map[string]string)
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"no grant", stream.ErrNoIngestGrant},
		{"out of scope", stream.ErrOutOfScope},
		{"unknown source", stream.ErrUnknownSource},
		{"deduction not permitted", stream.ErrDeductionNotPermitted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIngestFixture(t)
			f.adapter.err = tc.err
			rec := f.post(t, f.idp.token(t, "producer-1", testClientID), goodBatch)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body)
			}
			bodies[tc.name] = rec.Body.String()
		})
	}
	var first string
	for name, body := range bodies {
		if first == "" {
			first = body
			continue
		}
		if body != first {
			t.Errorf("the refusal for %q differs from the others: %s vs %s", name, body, first)
		}
	}
}

// The remaining outcomes each get their own status: a rate limit is a 429 with
// a retry hint, a malformed event is a 400 the caller can act on, and anything
// else is a 500 that narrates nothing.
func TestIngestStatusMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"rate limited", stream.ErrRateLimited, http.StatusTooManyRequests},
		{"batch too large", stream.ErrBatchTooLarge, http.StatusRequestEntityTooLarge},
		{"no event id", stream.ErrNoEventID, http.StatusBadRequest},
		{"no producer timestamp", stream.ErrNoProducedAt, http.StatusBadRequest},
		{"stale event", stream.ErrTooOld, http.StatusBadRequest},
		{"database down", errors.New("connection refused"), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newIngestFixture(t)
			f.adapter.err = tc.err
			rec := f.post(t, f.idp.token(t, "producer-1", testClientID), goodBatch)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.want, rec.Body)
			}
			if tc.want == http.StatusTooManyRequests && rec.Header().Get("Retry-After") == "" {
				t.Error("a 429 carried no Retry-After")
			}
			if tc.want == http.StatusInternalServerError && strings.Contains(rec.Body.String(), "connection refused") {
				t.Errorf("the 500 narrated the underlying failure: %s", rec.Body)
			}
		})
	}
}

// A body that is not an ingest document, or that carries fields this contract
// does not define, is refused rather than partially interpreted.
func TestIngestRefusesMalformedBodies(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"not json", "{", http.StatusBadRequest},
		{"unknown field", `{"source":"s","metric":"withdrawal_amount","events":[]}`, http.StatusBadRequest},
		{"oversized", `{"source":"` + strings.Repeat("a", 2<<20) + `","events":[]}`, http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIngestFixture(t)
			rec := f.post(t, f.idp.token(t, "producer-1", testClientID), tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.want, rec.Body)
			}
			if len(f.adapter.batches) != 0 {
				t.Error("a malformed body reached the ingest adapter")
			}
		})
	}
}
