package bench_test

// R26 asks for two thresholds, not one: the warm cache path and the path that
// includes misses. The reason they cannot be one number is visible in the
// scenarios below — every request in both of them runs the same policy against
// the same upstream answer, and the only difference is whether the answer was
// already in the TTL cache. A single blended scenario would report whatever
// hit rate the generator happened to produce, and a real regression on the miss
// path would disappear under a high hit rate.

import (
	"fmt"
	"testing"
	"time"

	"github.com/d0lim/stamp/bench"
	"github.com/d0lim/stamp/internal/policy"
)

// missOfferedRPS paces the forced-miss scenario.
//
// It is not a tuning knob, it is the boundary of what the miss path could be
// asked on a single host when this number was measured. At that time every miss
// opened a TCP connection, because the fact plane's egress client left
// MaxIdleConnsPerHost at Go's default of two, and the sustainable connection
// rate over loopback is ephemeral ports divided by TIME_WAIT: about 550/s on
// this macOS host and about 470/s on a stock Linux runner. 300 sits below both
// with room for the connections the rest of the process needs, and the unpaced
// attempt is what taught us the number — driven flat out, the third repeat of
// this scenario stopped measuring the check path and started reporting
// `connect: cannot assign requested address` at 30k/s.
//
// The egress client now keeps up to egressMaxIdleConns idle connections per
// host, so the premise this number rests on no longer holds. 300 is left
// unchanged anyway: what the new ceiling is has not been measured, and a paced
// number that is merely conservative still reports a valid latency
// distribution, while an unmeasured higher one would report a number nobody
// has stood behind. Raising it is a measurement, not an edit.
//
// The consequence is stated in the artifact rather than hidden: this scenario
// reports a latency distribution at a known offered rate, and the maximum QPS
// of the miss path is not a quantity this harness can produce on one host.
const missOfferedRPS = 300

// benchSchema is the vocabulary every check scenario is written against: an
// account with a number, a transfer, and the synchronous whitelist source.
func benchSchema() *policy.Schema {
	return &policy.Schema{
		Entities: []policy.EntityType{{
			Name:       "account",
			Attributes: []policy.Attribute{{Name: "number", Type: policy.TypeString}},
		}},
		Actions: []policy.Action{{Name: "transfer"}},
		Sources: []policy.SourceDecl{{
			Name:    "account_whitelist",
			Kind:    policy.SourceHTTP,
			Params:  []policy.Param{{Name: "account", Type: policy.TypeString}},
			Returns: policy.ListOf(policy.TypeString),
			OnError: policy.OnErrorDeny,
		}},
	}
}

// whitelistPolicy is F1, the representative scenario the plan starts this unit
// with: a transfer is allowed when the destination is on the source account's
// whitelist.
func whitelistPolicy() *policy.Policy {
	return &policy.Policy{
		ID:          "transfer-whitelist",
		Description: "a transfer may only reach a whitelisted destination",
		Subject:     "account",
		Resource:    "account",
		Actions:     []string{"transfer"},
		Condition: policy.Member{
			Left:       policy.Field(policy.RoleResource, "number"),
			Collection: policy.Source("account_whitelist", policy.Field(policy.RoleSubject, "number")),
		},
	}
}

// BenchmarkCheckWarmCache is the hot path: one account, whose whitelist answer
// is fetched once and served from the TTL cache for every request after.
//
// The warmup is doing real work here. The first request per account compiles
// the policy into the compile cache and fills the fact cache, and a measurement
// window that included those would report a cache-fill cost as if it were the
// steady state.
func BenchmarkCheckWarmCache(b *testing.B) {
	h := newHarness(b, options{})
	h.seed(benchSchema(), whitelistPolicy())

	body := evaluationBody("1001", destAccount, "transfer")
	var before int64
	result := drive(loadSpec{
		concurrency:  benchCfg.concurrency,
		warmup:       benchCfg.warmup,
		window:       benchCfg.duration,
		atWindowOpen: func() { before = h.upstream.calls.Load() },
	}, func(_, _ int) (bool, error) { return h.evaluate(body) })
	fetched := h.upstream.calls.Load() - before

	run := result.run("check_warm_cache",
		"whitelist transfer, one account, fact answer served from the TTL cache",
		benchCfg.concurrency)
	run.MissRate = missRate(fetched, result.requests)
	run.Pressure = h.auditPressure()
	record(run)
	reportToGo(b, run)
}

// BenchmarkCheckColdMiss forces a miss on every request by asking about an
// account nobody has asked about before.
//
// The upstream answers immediately over loopback, so this is the floor of the
// miss path and not its ceiling: what it measures is everything the check path
// does around a remote fetch, with the remote fetch itself as fast as it can
// possibly be. The ceiling is a separate scenario because it is set by a
// declaration rather than by any of this.
func BenchmarkCheckColdMiss(b *testing.B) {
	h := newHarness(b, options{})
	h.seed(benchSchema(), whitelistPolicy())

	var before int64
	result := drive(loadSpec{
		concurrency:  benchCfg.concurrency,
		warmup:       benchCfg.warmup,
		window:       benchCfg.duration,
		offeredRPS:   missOfferedRPS,
		atWindowOpen: func() { before = h.upstream.calls.Load() },
	}, func(worker, iteration int) (bool, error) {
		// A distinct account per request is a distinct fact cache key, and
		// the worker index keeps two workers from ever colliding on one.
		return h.evaluate(evaluationBody(
			fmt.Sprintf("9%03d%06d", worker, iteration), destAccount, "transfer"))
	})
	fetched := h.upstream.calls.Load() - before

	run := result.run("check_cold_miss",
		"whitelist transfer, a fresh account per request, every fact lookup fetched",
		benchCfg.concurrency)
	run.MissRate = missRate(fetched, result.requests)
	run.Pressure = h.auditPressure()
	run.Ceiling = &bench.Ceiling{
		DeclaredTimeoutMillis: float64(2 * time.Second / time.Millisecond),
		Source:                `fact.Declaration.Timeout on source "account_whitelist"`,
		Note: "this scenario's upstream answers immediately, so the measurement is the " +
			"floor of the miss path; the ceiling is the declared timeout and is measured " +
			"by the ceiling scenarios",
	}
	record(run)
	reportToGo(b, run)
}

// BenchmarkCheckMissCeiling150ms and its sibling are the same scenario run
// against two different declared timeouts, with an upstream that never answers.
//
// One of them would be an assertion. Two of them are a demonstration: the miss
// path's p99 lands where the declaration put it, and moving the declaration
// moves the p99 with it. That is the fact the artifact needs a reader to
// believe, because without it a miss threshold that the deployment itself chose
// reads as a performance problem.
func BenchmarkCheckMissCeiling150ms(b *testing.B) { missCeiling(b, 150*time.Millisecond) }

// BenchmarkCheckMissCeiling400ms is the second point on that line.
func BenchmarkCheckMissCeiling400ms(b *testing.B) { missCeiling(b, 400*time.Millisecond) }

func missCeiling(b *testing.B, timeout time.Duration) {
	// Blocked requests hold a goroutine and no CPU, so the ceiling scenarios
	// use more clients than the throughput ones — otherwise a window that fits
	// three requests per worker produces a p99 that is just the maximum of a
	// handful of samples.
	concurrency := benchCfg.concurrency * 4
	h := newHarness(b, options{factTimeout: timeout, concurrency: concurrency})
	h.seed(benchSchema(), whitelistPolicy())
	h.upstream.block.Store(true)

	result := drive(loadSpec{
		concurrency: concurrency,
		// One declared timeout of warmup: long enough for every client to have
		// a request in flight when the window opens.
		warmup: timeout,
		window: benchCfg.duration,
	}, func(worker, iteration int) (bool, error) {
		return h.evaluate(evaluationBody(
			fmt.Sprintf("8%03d%06d", worker, iteration), destAccount, "transfer"))
	})

	name := fmt.Sprintf("check_miss_ceiling_%dms", timeout/time.Millisecond)
	run := result.run(name,
		"every fact lookup times out; the deny is the declared failure behaviour",
		concurrency)
	run.Ceiling = &bench.Ceiling{
		DeclaredTimeoutMillis: float64(timeout / time.Millisecond),
		Source:                `fact.Declaration.Timeout on source "account_whitelist"`,
		Note: "the upstream never answers, so every request costs exactly the declared " +
			"timeout; the p99 is the declaration, not the system",
	}
	run.Pressure = h.auditPressure()
	record(run)
	reportToGo(b, run)
}

func missRate(fetched int64, requests int) *float64 {
	if requests == 0 {
		return nil
	}
	rate := float64(fetched) / float64(requests)
	return &rate
}

// reportToGo puts the headline numbers where `go test -bench` shows them, so a
// run is readable without opening the artifact.
func reportToGo(b *testing.B, run bench.Run) {
	b.ReportMetric(run.QPS, "qps")
	b.ReportMetric(run.Latency.P99, "p99ms")
	b.ReportMetric(run.Latency.P50, "p50ms")
	b.ReportMetric(float64(run.Errors), "errors")
}
