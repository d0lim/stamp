package runtime

// ingest_test.go is M3's exit condition: the event ingestion plane and the
// group directory plane meeting the rest of the process.
//
// The first flow is the one D17's port exists to serve, and it is only a flow
// once the composition root is there. Events go in over the HTTP ingest route
// with a workload credential, land in fixed-width buckets, and a check request
// reaches back through the resolver stack to read the trailing sum and denies
// on it. Nothing in it is a double: a real listener, a real credential, real
// buckets in a real Postgres, and the same evaluator every other flow uses.
//
// The second is the gap that flow would otherwise hide. A velocity source is
// served by a plane the synchronous registry deliberately skips, so a
// deployment that runs no such plane has to refuse a schema declaring one — and
// until something asserts that, the difference between "checked and admitted"
// and "checked by nobody" is invisible.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
	"github.com/d0lim/stamp/internal/stream"
)

const (
	// velocitySource is the declared event source both halves of this file use.
	velocitySource = "daily_transfer_total"
	// velocityMetric is the aggregate it reads. It is deployment configuration
	// and never appears in the schema: a policy author names the source, and
	// which metric that source reads is not theirs to choose.
	velocityMetric = "transfer_amount"
	// velocityLimit is the trailing-window total a transfer may not push past.
	velocityLimit = 1000
)

// velocitySchemaDecl is the schema half of the velocity source: a name, one
// string parameter, a return type and a failure behaviour. Everything else
// about it lives in the deployment configuration below.
func velocitySchemaDecl() policy.SourceDecl {
	return policy.SourceDecl{
		Name:    velocitySource,
		Kind:    policy.SourceEvent,
		Params:  []policy.Param{{Name: "account", Type: policy.TypeString}},
		Returns: policy.TypeDouble,
		OnError: policy.OnErrorDeny,
	}
}

// velocityDeclaration is the operator half: which metric, how wide the buckets
// are, how far back the window reaches, which adapter feeds it.
func velocityDeclaration() stream.Declaration {
	return stream.Declaration{
		Name:        velocitySource,
		Metric:      velocityMetric,
		Adapter:     DefaultIngestAdapterName,
		Window:      10 * time.Minute,
		BucketWidth: time.Minute,
		Params:      []policy.Param{{Name: "account", Type: policy.TypeString}},
		Returns:     policy.TypeDouble,
		OnError:     policy.OnErrorDeny,
	}
}

// velocitySchemaFor builds the tenant schema with the velocity source declared.
func velocitySchemaFor(sources ...policy.SourceDecl) *policy.Schema {
	return &policy.Schema{
		Entities: []policy.EntityType{{
			Name:       "account",
			Attributes: []policy.Attribute{{Name: "number", Type: policy.TypeString}},
		}},
		Actions: []policy.Action{{Name: "transfer"}},
		Sources: sources,
	}
}

// velocityPolicy is the limit itself: a transfer is allowed while the source
// account's trailing total is under the limit.
func velocityPolicy(id string) *policy.Policy {
	return &policy.Policy{
		ID:          id,
		Description: "a transfer is refused once the account's trailing total is spent",
		Subject:     "account",
		Resource:    "account",
		Actions:     []string{"transfer"},
		Condition: policy.Compare{
			Op:    policy.OpLt,
			Left:  policy.Source(velocitySource, policy.Field(policy.RoleSubject, "number")),
			Right: policy.Double(velocityLimit),
		},
	}
}

// withVelocity configures the ingestion plane: one velocity source, and one
// ingest grant scoped to it.
//
// The grant's caller identifier is the one the identity layer derives from a
// verified token rather than the bare `sub`. A subject identifier is unique
// only inside its issuer, so a grant written against a bare one would be a
// grant to whoever holds that name at any pinned IdP — the same argument D7
// makes about approvers, arriving here as a configuration shape.
func withVelocity(callerID string) func(*Config) {
	return func(cfg *Config) {
		cfg.StreamSources = []stream.Declaration{velocityDeclaration()}
		cfg.IngestCredentials = []stream.IngestCredential{{
			CallerID: callerID,
			Scope:    []stream.ScopeEntry{{Source: velocitySource, Metric: velocityMetric}},
		}}
	}
}

// ingestBody renders one ingest batch.
func ingestBody(events ...stream.IngestEvent) string {
	lines := make([]string, len(events))
	for i, e := range events {
		lines[i] = fmt.Sprintf(`{"event_id": %q, "subject": %q, "value": %v, "produced_at": %q}`,
			e.EventID, e.Subject, e.Value, e.ProducedAt.UTC().Format(time.RFC3339Nano))
	}
	return fmt.Sprintf(`{"source": %q, "events": [%s]}`, velocitySource, strings.Join(lines, ","))
}

// ---------------------------------------------------------------------------
// a velocity limit judged end to end
// ---------------------------------------------------------------------------

// TestVelocityLimitIsJudgedEndToEnd is the flow the ingestion port exists for.
//
// It exercises three things that only exist once the composition root wires
// them together: the resolver stack, because the same batch carries the
// velocity source and the engine gets exactly one resolver; the load gate,
// because a schema declaring an event source is admitted by the velocity plane
// and by nothing else; and the aggregation, because the answer the condition
// reads is a sum over rows the ingest route wrote.
func TestVelocityLimitIsJudgedEndToEnd(t *testing.T) {
	h := newHarness(t, harnessOptions{
		writerID: "velocity-writer",
		mutate: func(cfg *Config) {
			// The credential is named by the identifier the middleware derives
			// from the token this test presents, which is why it is built from
			// the issuer the harness just configured.
			caller := (&identity.Subject{
				Kind:   identity.SubjectWorkload,
				Issuer: cfg.OIDC.Issuers[0].Issuer,
				ID:     "svc-payments",
			}).CallerID()
			withVelocity(caller)(cfg)
		},
	})
	h.seed(velocitySchemaFor(velocitySchemaDecl()), velocityPolicy("transfer-velocity"))

	pep := h.idp.workload(t, "svc-payments")
	account := "1001"
	request := evaluation(account, "2002", "transfer")

	t.Run("with nothing ingested the account is under its limit", func(t *testing.T) {
		allowed, reason, _ := h.evaluate(t, pep, request)
		if !allowed {
			t.Fatalf("a transfer against an empty aggregate = deny (%s), want allow", reason)
		}
	})

	t.Run("an unauthenticated ingest is refused before it reaches a bucket", func(t *testing.T) {
		code, _ := h.do(http.MethodPost, api.SurfaceCallback, "/ingest/v1/events", "",
			ingestBody(stream.IngestEvent{
				EventID: "unauth-1", Subject: account, Value: 100000, ProducedAt: time.Now(),
			}), nil)
		if code != http.StatusUnauthorized {
			t.Fatalf("an unauthenticated ingest = %d, want %d", code, http.StatusUnauthorized)
		}
		if allowed, _, _ := h.evaluate(t, pep, request); !allowed {
			t.Fatal("a refused ingest moved the aggregate")
		}
	})

	t.Run("ingested events push the account over its limit", func(t *testing.T) {
		now := time.Now()
		body := ingestBody(
			stream.IngestEvent{EventID: "ev-1", Subject: account, Value: 400, ProducedAt: now.Add(-2 * time.Minute)},
			stream.IngestEvent{EventID: "ev-2", Subject: account, Value: 400, ProducedAt: now.Add(-time.Minute)},
			stream.IngestEvent{EventID: "ev-3", Subject: account, Value: 400, ProducedAt: now},
		)
		code, raw := h.do(http.MethodPost, api.SurfaceCallback, "/ingest/v1/events", pep, body, nil)
		if code != http.StatusAccepted {
			t.Fatalf("POST /ingest/v1/events = %d: %s", code, raw)
		}
		var resp api.IngestResponse
		h.decode(raw, &resp)
		if resp.Accepted != 3 || resp.Duplicates != 0 {
			t.Fatalf("ingest reported %d accepted and %d duplicate, want 3 and 0", resp.Accepted, resp.Duplicates)
		}

		allowed, reason, _ := h.evaluate(t, pep, request)
		if allowed {
			t.Fatalf("a transfer past the %d limit was allowed", velocityLimit)
		}
		// The deny is the condition being false, not a source that failed. The
		// difference is the whole point of the flow: the aggregate was read,
		// and the number it returned was over the limit.
		if reason != string(engine.ReasonConditionNotMet) {
			t.Errorf("reason = %q, want %q", reason, engine.ReasonConditionNotMet)
		}
	})

	t.Run("a redelivered batch does not count twice", func(t *testing.T) {
		// The subject below is a fresh one so the assertion is a number rather
		// than a verdict that was already deny.
		other := "2001"
		now := time.Now()
		body := ingestBody(stream.IngestEvent{
			EventID: "dup-1", Subject: other, Value: 250, ProducedAt: now,
		})
		for range 2 {
			code, raw := h.do(http.MethodPost, api.SurfaceCallback, "/ingest/v1/events", pep, body, nil)
			if code != http.StatusAccepted {
				t.Fatalf("POST /ingest/v1/events = %d: %s", code, raw)
			}
		}
		window, err := h.app.Store().Window(context.Background(), other, velocityMetric,
			time.Minute, now.Add(-10*time.Minute), now.Add(time.Minute))
		if err != nil {
			t.Fatalf("read the window: %v", err)
		}
		if window.Sum != 250 || window.Count != 1 {
			t.Fatalf("the redelivered event summed to %v over %d events, want 250 over 1",
				window.Sum, window.Count)
		}
	})

	t.Run("the credential may not write a source it is not scoped to", func(t *testing.T) {
		body := strings.Replace(ingestBody(stream.IngestEvent{
			EventID: "scope-1", Subject: account, Value: 1, ProducedAt: time.Now(),
		}), velocitySource, "some_other_source", 1)
		code, _ := h.do(http.MethodPost, api.SurfaceCallback, "/ingest/v1/events", pep, body, nil)
		if code != http.StatusForbidden {
			t.Fatalf("an out-of-scope ingest = %d, want %d", code, http.StatusForbidden)
		}
	})

	h.verifyChain()
}

// TestIngestRouteIsAbsentWithoutAVelocitySource pins the other half of the
// mounting rule: the ingest surface exists because a deployment configured
// something to ingest into, not because the consumer role is on.
func TestIngestRouteIsAbsentWithoutAVelocitySource(t *testing.T) {
	h := newHarness(t, harnessOptions{writerID: "no-ingest-writer"})
	code, _ := h.do(http.MethodPost, api.SurfaceCallback, "/ingest/v1/events", "", `{}`, nil)
	if code != http.StatusNotFound {
		t.Fatalf("the ingest route on a deployment with no velocity sources = %d, want %d",
			code, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// the load gate
// ---------------------------------------------------------------------------

// TestAnUnresolvableEventSourceIsRefusedAtLoad is the gap the resolver stack
// would otherwise leave open.
//
// [fact.Registry.VerifySchema] skips an event source deliberately — it is not
// the plane that would answer one — so on a deployment with no velocity plane
// the kind is checked by nobody unless the composition root supplies a gate
// that refuses it. Without this assertion the failure is silent at load and
// arrives as a resolver error inside the first request that reads the source.
func TestAnUnresolvableEventSourceIsRefusedAtLoad(t *testing.T) {
	t.Run("no velocity plane at all", func(t *testing.T) {
		h := newHarness(t, harnessOptions{writerID: "gate-none-writer"})
		err := h.trySeed(velocitySchemaFor(velocitySchemaDecl()), velocityPolicy("transfer-velocity"))
		if err == nil {
			t.Fatal("a schema declaring an event source loaded on a deployment that serves none")
		}
		if !errors.Is(err, fact.ErrLoad) {
			t.Fatalf("refusal = %v, want it to wrap %v", err, fact.ErrLoad)
		}
		if !strings.Contains(err.Error(), velocitySource) {
			t.Errorf("the refusal does not name the source: %v", err)
		}
	})

	t.Run("a velocity plane that does not serve this name", func(t *testing.T) {
		h := newHarness(t, harnessOptions{
			writerID: "gate-other-writer",
			mutate:   withVelocity("workload:nobody#nobody"),
		})
		other := velocitySchemaDecl()
		other.Name = "weekly_transfer_total"
		err := h.trySeed(velocitySchemaFor(other))
		if err == nil {
			t.Fatal("a schema declaring an unconfigured event source loaded")
		}
		if !errors.Is(err, fact.ErrLoad) {
			t.Fatalf("refusal = %v, want it to wrap %v", err, fact.ErrLoad)
		}
		if !strings.Contains(err.Error(), "weekly_transfer_total") {
			t.Errorf("the refusal does not name the source: %v", err)
		}
	})

	t.Run("a signature the deployment disagrees with", func(t *testing.T) {
		h := newHarness(t, harnessOptions{
			writerID: "gate-signature-writer",
			mutate:   withVelocity("workload:nobody#nobody"),
		})
		// The deployment serves this source returning a double; the schema
		// declares it returning an int. Two answers of different types is a
		// condition that would compile against one and be evaluated against the
		// other.
		mismatched := velocitySchemaDecl()
		mismatched.Returns = policy.TypeInt
		err := h.trySeed(velocitySchemaFor(mismatched))
		if err == nil {
			t.Fatal("a schema whose event source signature disagrees with the deployment loaded")
		}
		if !errors.Is(err, fact.ErrLoad) {
			t.Fatalf("refusal = %v, want it to wrap %v", err, fact.ErrLoad)
		}
	})

	t.Run("an idp group source nothing serves", func(t *testing.T) {
		// The same argument, one plane over: the registry skips this kind too.
		h := newHarness(t, harnessOptions{writerID: "gate-group-writer"})
		err := h.trySeed(velocitySchemaFor(policy.SourceDecl{
			Name:    "approver_group",
			Kind:    policy.SourceIdPGroup,
			Params:  []policy.Param{{Name: "group", Type: policy.TypeString}},
			Returns: policy.ListOf(policy.TypeString),
			OnError: policy.OnErrorDeny,
		}))
		if err == nil {
			t.Fatal("a schema declaring an idp group source loaded on a deployment that serves none")
		}
		if !errors.Is(err, fact.ErrLoad) {
			t.Fatalf("refusal = %v, want it to wrap %v", err, fact.ErrLoad)
		}
	})
}

// ---------------------------------------------------------------------------
// the retention sweep
// ---------------------------------------------------------------------------

// TestRetentionSweepPrunesPastTheHorizon gives U12's two prune helpers their
// first caller.
//
// Correctness never depended on the sweep — the port refuses an event older
// than the widest declarable window, so nothing outside the horizon can reach
// an answer — but two tables that only ever grow do, and until now nothing in
// the process called either helper.
func TestRetentionSweepPrunesPastTheHorizon(t *testing.T) {
	h := newHarness(t, harnessOptions{
		writerID: "sweep-writer",
		mutate:   withVelocity("workload:nobody#nobody"),
	})
	ctx := context.Background()
	s := h.app.Store()

	// Written straight to the store: the port would refuse this event, which is
	// exactly why a row this old can only get there by having been written when
	// it was young.
	stale := time.Now().Add(-store.DefaultDedupRetention() - time.Hour)
	if _, err := s.RecordEvent(ctx, store.BucketEvent{
		CallerID: "svc", EventID: "old-1", Metric: velocityMetric,
		SubjectID: "1001", Value: 10, At: stale, Width: time.Minute,
	}); err != nil {
		t.Fatalf("record a stale event: %v", err)
	}

	h.app.sweepOnce(ctx)

	window, err := s.Window(ctx, "1001", velocityMetric, time.Minute,
		stale.Add(-time.Hour), stale.Add(time.Hour))
	if err != nil {
		t.Fatalf("read the swept window: %v", err)
	}
	if window.Count != 0 {
		t.Fatalf("the sweep left %d events past the retention horizon, want 0", window.Count)
	}
}
