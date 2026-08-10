package api

// ingest.go is the HTTP surface of the event ingestion port.
//
// It sits on the callback surface, with a workload credential required.
// That placement is a choice worth stating, because it is the one place this
// endpoint could have gone wrong.
//
// It is not on the PEP surface. That surface carries check and decide — the
// questions — and a deployment binds it to the network its enforcement points
// live on. An event producer is a different population with a different
// credential and a different blast radius: a producer credential reaching
// check would let a compromised producer enumerate decisions, and a PEP
// credential reaching ingest would let any enforcement point rewrite the
// aggregates it is judged against.
//
// It is not on the console surface either, whose callers are people.
//
// It is on the callback surface because that is already defined as the one a
// deployment may have to expose beyond its own perimeter, which is exactly
// what an event producer sits outside of, and because that surface's
// credential table already admits a workload credential. What it does not
// share with the external-challenge callback next to it is anonymity: that
// endpoint proves itself with a signature and this one is authenticated,
// rate-limited and scope-checked, so it is mounted with AuthWorkload and an
// unauthenticated request never reaches the handler.
//
// The handler itself is thin on purpose. Which (source, metric) pairs a
// credential may write, whether it may send a deduction, and what its rate is
// are decided in the stream package next to the aggregation they protect —
// this file's job is to turn a request into a call and an outcome into a
// status code, and to make sure the status code tells a stranger nothing they
// could enumerate with.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/stream"
)

// IngestPattern is the endpoint an event producer sends batches to.
const IngestPattern = "POST /ingest/v1/events"

// DefaultMaxIngestBytes bounds an ingest body. A batch is capped in events by
// the adapter; this caps it in bytes, which is the limit that matters before
// the body has been parsed.
const DefaultMaxIngestBytes = 1 << 20

// IngestSubmitter accepts one authenticated batch. It is the stream package's
// ingest adapter, stated as an interface so this surface does not depend on
// how the adapter is built.
type IngestSubmitter interface {
	Submit(ctx context.Context, callerID string, batch stream.IngestBatch) (stream.Result, error)
}

// IngestConfig configures an [IngestAPI].
type IngestConfig struct {
	// Adapter accepts batches. Required.
	Adapter IngestSubmitter
	// MaxRequestBytes bounds a batch body. Zero selects DefaultMaxIngestBytes.
	MaxRequestBytes int64
}

// IngestAPI serves the HTTP ingest endpoint.
type IngestAPI struct {
	adapter  IngestSubmitter
	maxBytes int64
}

var _ Provider = (*IngestAPI)(nil)

// NewIngestAPI builds the ingest surface.
func NewIngestAPI(cfg IngestConfig) (*IngestAPI, error) {
	if cfg.Adapter == nil {
		return nil, errors.New("api: the ingest surface requires an ingest adapter")
	}
	a := &IngestAPI{adapter: cfg.Adapter, maxBytes: cfg.MaxRequestBytes}
	if a.maxBytes <= 0 {
		a.maxBytes = DefaultMaxIngestBytes
	}
	return a, nil
}

// Routes implements [Provider].
func (a *IngestAPI) Routes() []Route {
	return []Route{{
		Name:    "event-ingest",
		Surface: SurfaceCallback,
		Pattern: IngestPattern,
		Auth:    AuthWorkload,
		Handler: http.HandlerFunc(a.ingest),
	}}
}

// IngestRequest is the wire form of one batch.
type IngestRequest struct {
	// Source names the velocity source being written. The metric is not on the
	// wire: it comes from that source's declaration, so a request cannot pick
	// which aggregate it lands in after the scope check was written.
	Source string `json:"source"`
	// Events are the events in the batch.
	Events []IngestEventRequest `json:"events"`
}

// IngestEventRequest is one event on the wire.
type IngestEventRequest struct {
	// EventID is the producer-assigned identifier. It is required: it is the
	// dedup key, and the producer assigns it because the alternative is a
	// broker-assigned one that would not survive a replay through this path.
	EventID string `json:"event_id"`
	// Subject is whose aggregate the event contributes to.
	Subject string `json:"subject"`
	// Value is the delta.
	Value float64 `json:"value"`
	// ProducedAt is the producer's timestamp, and what ingestion lag is
	// measured from. It is required.
	ProducedAt time.Time `json:"produced_at"`
}

// IngestResponse reports what the batch did.
type IngestResponse struct {
	// Accepted is how many events were new.
	Accepted int `json:"accepted"`
	// Duplicates is how many had already been recorded. A producer that
	// retried a delivery reads a non-zero count here and stops retrying,
	// rather than being told the batch failed.
	Duplicates int `json:"duplicates"`
}

func (a *IngestAPI) ingest(w http.ResponseWriter, r *http.Request) {
	caller, ok := identity.SubjectFromContext(r.Context())
	if !ok {
		// Unreachable through the mounted route: this endpoint requires a
		// workload credential and the middleware rejects and audits before the
		// handler runs. Restated here so the handler is correct standalone.
		writeError(w, http.StatusUnauthorized, "unauthenticated", "an ingest batch requires a workload credential")
		return
	}

	var req IngestRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, a.maxBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large",
				fmt.Sprintf("the batch exceeds the %d byte limit", a.maxBytes))
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "the batch could not be read as an ingest document")
		return
	}

	batch := stream.IngestBatch{Source: req.Source, Events: make([]stream.IngestEvent, len(req.Events))}
	for i, e := range req.Events {
		batch.Events[i] = stream.IngestEvent{
			EventID:    e.EventID,
			Subject:    e.Subject,
			Value:      e.Value,
			ProducedAt: e.ProducedAt,
		}
	}

	res, err := a.adapter.Submit(r.Context(), caller.CallerID(), batch)
	if err != nil {
		a.refuse(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, IngestResponse{Accepted: res.Applied, Duplicates: res.Duplicates})
}

// refuse maps an ingestion failure to a status.
//
// Three groups, and the grouping is the security-relevant part. An
// authorization refusal is one answer whatever the cause — no grant, wrong
// scope, a source that does not exist — because distinguishing them would let
// a credential with one narrow grant enumerate every source name on the
// deployment by reading status codes. A malformed batch is narrated, because
// the caller wrote it and telling them what is wrong with their own document
// reveals nothing. Everything else is an outage, and an outage is not
// explained to a stranger.
func (a *IngestAPI) refuse(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, stream.ErrRateLimited):
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "the ingest rate limit for this caller was exceeded")
	case errors.Is(err, stream.ErrNoIngestGrant),
		errors.Is(err, stream.ErrOutOfScope),
		errors.Is(err, stream.ErrUnknownSource),
		errors.Is(err, stream.ErrDeductionNotPermitted):
		writeError(w, http.StatusForbidden, "not_permitted",
			"this credential may not write that source and metric")
	case errors.Is(err, stream.ErrBatchTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", err.Error())
	case errors.Is(err, stream.ErrRejected):
		writeError(w, http.StatusBadRequest, "invalid_event", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "the batch could not be processed")
	}
}
