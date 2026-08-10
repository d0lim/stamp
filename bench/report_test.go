package bench_test

// These are the only tests in this package, and they are deliberately not
// tests of anything's performance. What they cover is the arithmetic and the
// rendering that decide what a run means — the percentile, the aggregation
// across repeats, the threshold comparison, the direction of the regression
// sign — because those run on every result and a mistake in them would be
// invisible in a number that looks plausible.
//
// They need no Docker daemon, which is why the container in the harness starts
// on first use rather than in TestMain.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/bench"
)

func TestPercentilesAreNearestRankOverTheSample(t *testing.T) {
	samples := make([]time.Duration, 100)
	for i := range samples {
		samples[i] = time.Duration(i+1) * time.Millisecond
	}
	got := bench.Summarize(samples)

	if got.P50 != 50 {
		t.Errorf("p50 = %v, want 50: the 50th of a hundred sorted samples", got.P50)
	}
	if got.P99 != 99 {
		t.Errorf("p99 = %v, want 99: nearest rank never interpolates between measurements", got.P99)
	}
	if got.Max != 100 {
		t.Errorf("max = %v, want 100", got.Max)
	}
	if got.Mean != 50.5 {
		t.Errorf("mean = %v, want 50.5", got.Mean)
	}
}

func TestSummarizingNothingIsZeroRatherThanAPanic(t *testing.T) {
	if got := bench.Summarize(nil); got != (bench.Latency{}) {
		t.Errorf("Summarize(nil) = %+v, want the zero distribution", got)
	}
}

func TestSummarizeDoesNotReorderTheCallersSlice(t *testing.T) {
	samples := []time.Duration{3, 1, 2}
	bench.Summarize(samples)
	if samples[0] != 3 || samples[1] != 1 || samples[2] != 2 {
		t.Errorf("the caller's sample was sorted in place: %v", samples)
	}
}

func TestRepeatsOfAScenarioBecomeOneAggregateWithItsSpread(t *testing.T) {
	r := &bench.Report{}
	for _, p99 := range []float64{10, 12, 14} {
		r.Add(bench.Run{Scenario: "warm", Latency: bench.Latency{P99: p99}, QPS: 1000})
	}

	aggs := r.Aggregates()
	if len(aggs) != 1 {
		t.Fatalf("aggregates = %d, want the three repeats reduced to one", len(aggs))
	}
	a := aggs[0]
	if a.Runs != 3 {
		t.Errorf("runs = %d, want 3", a.Runs)
	}
	if a.P99Median != 12 {
		t.Errorf("p99 median = %v, want 12: the middle repeat, not the mean", a.P99Median)
	}
	if a.P99Min != 10 || a.P99Max != 14 {
		t.Errorf("p99 range = %v–%v, want 10–14", a.P99Min, a.P99Max)
	}
	// (14-10)/12: the spread the artifact prints next to every threshold.
	if got := a.SpreadPct; got < 33.3 || got > 33.4 {
		t.Errorf("spread = %.2f%%, want (max-min)/median = 33.3%%", got)
	}
}

func TestRepeatsAreNumberedSoOneRunNeverOverwritesAnother(t *testing.T) {
	r := &bench.Report{}
	r.Add(bench.Run{Scenario: "warm"})
	r.Add(bench.Run{Scenario: "warm"})
	r.Add(bench.Run{Scenario: "miss"})

	if r.Runs[0].Index != 0 || r.Runs[1].Index != 1 {
		t.Errorf("repeat indices = %d,%d, want 0,1", r.Runs[0].Index, r.Runs[1].Index)
	}
	if r.Runs[2].Index != 0 {
		t.Errorf("a different scenario started at index %d, want 0", r.Runs[2].Index)
	}
}

func TestAnUncalibratedProfileConcludesNothing(t *testing.T) {
	r := &bench.Report{Runs: []bench.Run{{Scenario: "warm", Latency: bench.Latency{P99: 900}}}}
	profile := bench.Profile{
		Calibrated: false,
		Scenarios:  map[string]bench.Threshold{"warm": {MaxP99Millis: 1}},
	}

	ev := r.Evaluate("ci", profile, nil)
	if len(ev.Checks) != 1 {
		t.Fatalf("checks = %d, want 1", len(ev.Checks))
	}
	if ev.Checks[0].Verdict != bench.VerdictUncalibrated {
		t.Errorf("verdict = %q, want %q: a bound nobody measured on this runner is not a gate",
			ev.Checks[0].Verdict, bench.VerdictUncalibrated)
	}
	if len(ev.Warnings()) != 0 {
		t.Errorf("an uncalibrated profile produced warnings: %v", ev.Warnings())
	}
}

func TestACalibratedProfileWarnsInBothDirections(t *testing.T) {
	r := &bench.Report{Runs: []bench.Run{
		{Scenario: "warm", Latency: bench.Latency{P99: 5}, QPS: 100},
		{Scenario: "miss", Latency: bench.Latency{P99: 50}, QPS: 900},
	}}
	profile := bench.Profile{
		Calibrated: true,
		Scenarios: map[string]bench.Threshold{
			// warm passes on latency and fails on throughput.
			"warm": {MaxP99Millis: 10, MinQPS: 500, Basis: "measured 4ms, 700qps"},
			// miss fails on latency and passes on throughput.
			"miss": {MaxP99Millis: 20, MinQPS: 100, Basis: "measured 15ms, 800qps"},
		},
	}

	ev := r.Evaluate("local", profile, nil)
	got := map[string]bench.Verdict{}
	for _, c := range ev.Checks {
		got[c.Scenario+"/"+c.Metric] = c.Verdict
	}
	want := map[string]bench.Verdict{
		"warm/p99_ms": bench.VerdictPass,
		"warm/qps":    bench.VerdictWarn,
		"miss/p99_ms": bench.VerdictWarn,
		"miss/qps":    bench.VerdictPass,
	}
	for key, verdict := range want {
		if got[key] != verdict {
			t.Errorf("%s = %q, want %q", key, got[key], verdict)
		}
	}
	if len(ev.Warnings()) != 2 {
		t.Errorf("warnings = %v, want one per missed bound", ev.Warnings())
	}
}

func TestRegressionIsSignedTowardsWorseForBothMetrics(t *testing.T) {
	previous := &bench.Report{
		Schema: bench.Schema,
		Runs:   []bench.Run{{Scenario: "warm", Latency: bench.Latency{P99: 10}, QPS: 1000}},
	}
	// Latency doubled and throughput halved: both are the same amount worse.
	current := &bench.Report{
		Runs: []bench.Run{{Scenario: "warm", Latency: bench.Latency{P99: 20}, QPS: 500}},
	}

	ev := current.Evaluate("local",
		bench.Profile{Calibrated: true, RegressionTolerancePct: 25}, previous)
	if len(ev.Regressions) != 2 {
		t.Fatalf("regressions = %d, want one per metric", len(ev.Regressions))
	}
	for _, reg := range ev.Regressions {
		if reg.ChangePct <= 0 {
			t.Errorf("%s change = %+.1f%%, want positive: worse is always positive",
				reg.Metric, reg.ChangePct)
		}
		if reg.Verdict != bench.VerdictWarn {
			t.Errorf("%s verdict = %q, want a warning past the tolerance", reg.Metric, reg.Verdict)
		}
	}
	if ev.Regressions[0].ChangePct != 100 {
		t.Errorf("p99 change = %v, want 100%%", ev.Regressions[0].ChangePct)
	}
	if ev.Regressions[1].ChangePct != 50 {
		t.Errorf("qps change = %v, want 50%%", ev.Regressions[1].ChangePct)
	}
}

func TestAnImprovementIsNeverAWarning(t *testing.T) {
	previous := &bench.Report{
		Schema: bench.Schema,
		Runs:   []bench.Run{{Scenario: "warm", Latency: bench.Latency{P99: 20}, QPS: 500}},
	}
	current := &bench.Report{
		Runs: []bench.Run{{Scenario: "warm", Latency: bench.Latency{P99: 10}, QPS: 1000}},
	}
	ev := current.Evaluate("local",
		bench.Profile{Calibrated: true, RegressionTolerancePct: 5}, previous)
	for _, reg := range ev.Regressions {
		if reg.Verdict == bench.VerdictWarn {
			t.Errorf("%s warned on an improvement of %+.1f%%", reg.Metric, reg.ChangePct)
		}
	}
}

func TestAToleranceWiderThanTheChangeStaysQuiet(t *testing.T) {
	previous := &bench.Report{
		Schema: bench.Schema,
		Runs:   []bench.Run{{Scenario: "warm", Latency: bench.Latency{P99: 10}, QPS: 1000}},
	}
	current := &bench.Report{
		Runs: []bench.Run{{Scenario: "warm", Latency: bench.Latency{P99: 12}, QPS: 1000}},
	}
	ev := current.Evaluate("local",
		bench.Profile{Calibrated: true, RegressionTolerancePct: 30}, previous)
	if warnings := ev.Warnings(); len(warnings) != 0 {
		t.Errorf("a 20%% move warned under a 30%% tolerance: %v", warnings)
	}
}

func TestNoBaselineIsReportedRatherThanTreatedAsZero(t *testing.T) {
	r := &bench.Report{Runs: []bench.Run{{Scenario: "warm", Latency: bench.Latency{P99: 10}}}}
	ev := r.Evaluate("local", bench.Profile{Calibrated: true}, nil)
	if len(ev.Regressions) != 1 || ev.Regressions[0].Verdict != bench.VerdictNoBaseline {
		t.Fatalf("regressions = %+v, want a single no-baseline row", ev.Regressions)
	}
	if strings.Contains(ev.Markdown(), "| 0.00 | ") {
		t.Error("the artifact rendered a missing baseline as a previous value of zero")
	}
}

func TestTheArtifactSaysWhereTheMissCeilingComesFrom(t *testing.T) {
	timeout := 150.0
	r := &bench.Report{Runs: []bench.Run{{
		Scenario: "check_miss_ceiling_150ms",
		Latency:  bench.Latency{P99: 152},
		Ceiling: &bench.Ceiling{
			DeclaredTimeoutMillis: timeout,
			Source:                `fact.Declaration.Timeout on source "account_whitelist"`,
			Note:                  "the p99 is the declaration, not the system",
		},
	}}}
	md := r.Evaluate("local", bench.Profile{}, nil).Markdown()

	for _, want := range []string{
		"declared timeout **150 ms**",
		"fact.Declaration.Timeout",
		"the deployment getting the bound it asked for",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the artifact does not say %q", want)
		}
	}
}

func TestTheAuditConversionPublishesItsInputs(t *testing.T) {
	r := &bench.Report{Runs: []bench.Run{{
		Scenario: "audit_root_insert",
		QPS:      1500,
		Audit: &bench.AuditConversion{
			RootInsertsPerSec:   1500,
			CoverPerRoot:        256,
			CoverSource:         "api.DefaultAuditBatchSize",
			CoveredChecksPerSec: 384000,
			Formula:             "covered checks/s = root inserts/s x checks per root = 1500.0 x 256 = 384000",
		},
	}}}
	md := r.Evaluate("local", bench.Profile{}, nil).Markdown()

	for _, want := range []string{
		"api.DefaultAuditBatchSize",
		"1500.0 x 256 = 384000",
		"**384000/s**",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the artifact does not carry %q, so the conversion cannot be checked", want)
		}
	}
}

func TestMeasuredCoverIsChainedEventsOverBatchRows(t *testing.T) {
	p := bench.AuditPressure{ChainedEvents: 1280, BatchRows: 5}
	if got := p.MeanCover(); got != 256 {
		t.Errorf("measured cover = %v, want 256", got)
	}
	if got := (bench.AuditPressure{}).MeanCover(); got != 0 {
		t.Errorf("cover with no batch row = %v, want 0 rather than a division by zero", got)
	}
}

func TestTheAuditedFractionIsWhatReachedTheChain(t *testing.T) {
	p := bench.AuditPressure{ChainedEvents: 1, DroppedEvents: 3}
	if got := p.AuditedFraction(); got != 0.25 {
		t.Errorf("audited fraction = %v, want 0.25", got)
	}
	if got := (bench.AuditPressure{}).AuditedFraction(); got != 0 {
		t.Errorf("fraction of nothing = %v, want 0 rather than a division by zero", got)
	}
}

func TestRuntimeNotesReachTheArtifactAndTheAnnotations(t *testing.T) {
	r := &bench.Report{
		Runs:  []bench.Run{{Scenario: "warm"}},
		Notes: []string{`the process reported "audit chain sequence conflict" on shutdown`},
	}
	ev := r.Evaluate("local", bench.Profile{}, nil)
	if !strings.Contains(ev.Markdown(), "audit chain sequence conflict") {
		t.Error("a note the process made about itself did not reach the artifact")
	}
	var found bool
	for _, a := range ev.Annotations() {
		if strings.HasPrefix(a, "::warning") && strings.Contains(a, "audit chain sequence conflict") {
			found = true
		}
	}
	if !found {
		t.Errorf("the note produced no workflow annotation: %v", ev.Annotations())
	}
}

func TestAReportRoundTripsThroughItsOwnArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.json")
	original := &bench.Report{
		Commit:  "abc123",
		Profile: "local",
		Runs: []bench.Run{{
			Scenario: "warm", Latency: bench.Latency{P99: 1.5}, QPS: 2000, Requests: 6000,
		}},
	}
	if err := original.WriteJSON(path); err != nil {
		t.Fatalf("write: %v", err)
	}
	loaded, err := bench.LoadReport(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Commit != "abc123" || len(loaded.Runs) != 1 || loaded.Runs[0].QPS != 2000 {
		t.Fatalf("the round trip lost data: %+v", loaded)
	}
}

func TestADocumentOfTheWrongSchemaIsRefusedRatherThanCompared(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.json")
	if err := os.WriteFile(path, []byte(`{"schema":"stamp.bench.v0","runs":[]}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := bench.LoadReport(path); err == nil {
		t.Error("a report from another schema was accepted as a baseline")
	}
}

// TestTheCheckedInThresholdsAreUsable is the guard on the file this unit ships.
// A profile the bench cannot find, or a calibrated profile with no basis
// written down, would produce an artifact nobody can audit.
func TestTheCheckedInThresholdsAreUsable(t *testing.T) {
	thresholds, err := bench.LoadThresholds("thresholds.json")
	if err != nil {
		t.Fatalf("load thresholds: %v", err)
	}
	for _, name := range []string{"local", "ci"} {
		profile, ok := thresholds.Profile(name)
		if !ok {
			t.Fatalf("no profile named %q; the bench refuses to run without one", name)
		}
		if profile.Note == "" {
			t.Errorf("profile %q carries no note saying what it is", name)
		}
		if profile.RegressionTolerancePct <= 0 {
			t.Errorf("profile %q has no regression tolerance, so every run regresses", name)
		}
		if !profile.Calibrated {
			continue
		}
		if profile.Runner == "" || profile.MeasuredAt == "" {
			t.Errorf("profile %q is calibrated but does not say on what, or when", name)
		}
		for scenario, bound := range profile.Scenarios {
			if bound.Basis == "" {
				t.Errorf("%s/%s has a threshold with no basis: nobody can audit where it came from",
					name, scenario)
			}
			if bound.MaxP99Millis == 0 && bound.MinQPS == 0 {
				t.Errorf("%s/%s declares a threshold that bounds nothing", name, scenario)
			}
		}
	}
}
