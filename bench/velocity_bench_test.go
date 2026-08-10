package bench_test

// The velocity scenario is the one the plan holds until U12 has landed. It is
// a third shape rather than a second copy of the whitelist scenario: an event
// source has no TTL cache in front of it, so every judgment reads an aggregate
// out of Postgres. Neither the warm nor the miss threshold describes it, which
// is why it gets its own scenario and its own row.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	stamp "github.com/d0lim/stamp/internal/runtime"
	"github.com/d0lim/stamp/internal/stream"
)

const (
	velocitySource = "daily_transfer_total"
	velocityMetric = "transfer_amount"
	velocityLimit  = 1_000_000
	velocityWindow = 10 * time.Minute
	velocityBucket = time.Minute
)

// withVelocity configures the ingestion plane: one event source and one ingest
// grant scoped to it.
//
// The grant names the identifier the identity layer derives from a verified
// token rather than the bare subject, which is the same shape the end-to-end
// tests use and the reason the caller is built from the configured issuer.
func withVelocity(cfg *stamp.Config) {
	caller := (&identity.Subject{
		Kind:   identity.SubjectWorkload,
		Issuer: cfg.OIDC.Issuers[0].Issuer,
		ID:     "svc-bench",
	}).CallerID()
	cfg.StreamSources = []stream.Declaration{{
		Name:        velocitySource,
		Metric:      velocityMetric,
		Adapter:     stamp.DefaultIngestAdapterName,
		Window:      velocityWindow,
		BucketWidth: velocityBucket,
		Params:      []policy.Param{{Name: "account", Type: policy.TypeString}},
		Returns:     policy.TypeDouble,
		OnError:     policy.OnErrorDeny,
	}}
	cfg.IngestCredentials = []stream.IngestCredential{{
		CallerID: caller,
		Scope:    []stream.ScopeEntry{{Source: velocitySource, Metric: velocityMetric}},
	}}
}

func velocitySchema() *policy.Schema {
	return &policy.Schema{
		Entities: []policy.EntityType{{
			Name:       "account",
			Attributes: []policy.Attribute{{Name: "number", Type: policy.TypeString}},
		}},
		Actions: []policy.Action{{Name: "transfer"}},
		Sources: []policy.SourceDecl{{
			Name:    velocitySource,
			Kind:    policy.SourceEvent,
			Params:  []policy.Param{{Name: "account", Type: policy.TypeString}},
			Returns: policy.TypeDouble,
			OnError: policy.OnErrorDeny,
		}},
	}
}

func velocityPolicy() *policy.Policy {
	return &policy.Policy{
		ID:          "transfer-velocity",
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

// BenchmarkCheckVelocity measures a judgment whose fact is an aggregate over
// ingested events.
//
// The account is seeded with enough buckets to make the aggregation read more
// than one row, because an aggregate over a single row would be a primary key
// lookup wearing an aggregate's name. The limit is set far above the seeded
// total so that every request allows: a scenario that started denying halfway
// through would be measuring two different code paths and averaging them.
func BenchmarkCheckVelocity(b *testing.B) {
	h := newHarness(b, options{velocity: true})
	h.seed(velocitySchema(), velocityPolicy())

	const account = "1001"
	h.ingest(account, 60)

	body := evaluationBody(account, destAccount, "transfer")
	result := drive(loadSpec{
		concurrency: benchCfg.concurrency,
		warmup:      benchCfg.warmup,
		window:      benchCfg.duration,
	}, func(_, _ int) (bool, error) { return h.evaluate(body) })

	run := result.run("check_velocity",
		"velocity limit, aggregate read from Postgres on every judgment (no TTL cache)",
		benchCfg.concurrency)
	run.Pressure = h.auditPressure()
	record(run)
	reportToGo(b, run)
}

// ingest writes count events for one account, spread across the declared
// window so that the aggregate sums real rows in several buckets rather than
// reading one.
func (h *harness) ingest(account string, count int) {
	h.tb.Helper()
	now := time.Now().UTC()
	spacing := velocityWindow / time.Duration(count+1)
	events := make([]string, 0, count)
	for i := range count {
		events = append(events, fmt.Sprintf(
			`{"event_id":%q,"subject":%q,"value":%d,"produced_at":%q}`,
			fmt.Sprintf("bench-%s-%d", account, i), account, 1,
			now.Add(-time.Duration(i)*spacing).Format(time.RFC3339Nano)))
	}
	body := fmt.Sprintf(`{"source":%q,"events":[%s]}`, velocitySource, strings.Join(events, ","))
	code, raw := h.post(api.SurfaceCallback, "/ingest/v1/events", body)
	if code != http.StatusAccepted && code != http.StatusOK {
		h.tb.Fatalf("ingest = %d: %s", code, raw)
	}
}
