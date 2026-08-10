// Package bench holds the performance benchmark scenarios and the artifact
// they produce.
//
// The scenarios live in this directory's test files; this file is the part
// that has to be right whether or not a Docker daemon is present: the latency
// summary, the threshold comparison, the regression comparison against the
// previous run, and the rendering of both into the artifact a CI job uploads.
//
// It is a separate compilation unit from the benchmarks for one reason. The
// numbers a benchmark produces are only as trustworthy as the arithmetic that
// summarizes them, and arithmetic that only runs when a container starts is
// arithmetic nobody checks. Everything here is pure and unit tested.
package bench

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Schema labels the results document. A reader — the next run comparing
// against this one, or a person opening the artifact a year from now — needs to
// know which shape it is holding before it can be believed.
const Schema = "stamp.bench.v1"

// Latency is one scenario's latency distribution, in milliseconds.
//
// Milliseconds rather than a [time.Duration] because the artifact is read by
// people and by whatever the next unit points at it, and a duration serialized
// as an integer count of nanoseconds is neither.
type Latency struct {
	Mean float64 `json:"mean_ms"`
	P50  float64 `json:"p50_ms"`
	P95  float64 `json:"p95_ms"`
	P99  float64 `json:"p99_ms"`
	Max  float64 `json:"max_ms"`
}

// Summarize reduces a sample of request latencies to the distribution the
// artifact records.
//
// The percentile is nearest-rank on the sorted sample: no interpolation, and
// the p99 of a hundred samples is the hundredth one. Interpolating would invent
// a value between two measurements, and this unit's whole discipline is that a
// number in the artifact was measured.
func Summarize(samples []time.Duration) Latency {
	if len(samples) == 0 {
		return Latency{}
	}
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var total time.Duration
	for _, s := range sorted {
		total += s
	}
	return Latency{
		Mean: millis(total / time.Duration(len(sorted))),
		P50:  millis(percentile(sorted, 0.50)),
		P95:  millis(percentile(sorted, 0.95)),
		P99:  millis(percentile(sorted, 0.99)),
		Max:  millis(sorted[len(sorted)-1]),
	}
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	rank := int(math.Ceil(p * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

func millis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

// AuditConversion is the audit throughput figure and the arithmetic behind it.
//
// The measured quantity is the rate at which batch root rows reach the chain.
// The quantity anyone cares about is how many check requests that covers, and
// the two differ by exactly the batch size the check surface flushes at. The
// conversion is recorded with its inputs and their provenance rather than as a
// finished number, because a reader who cannot see the cover count cannot tell
// a throughput result from a batching decision.
type AuditConversion struct {
	// RootInsertsPerSec is what was measured: batch root rows per second.
	RootInsertsPerSec float64 `json:"root_inserts_per_sec"`
	// CoverPerRoot is how many check events one root row summarizes.
	CoverPerRoot int `json:"cover_per_root"`
	// CoverSource names the Go symbol CoverPerRoot was read from. The bench
	// imports the constant rather than restating it, and this field is how the
	// artifact says so.
	CoverSource string `json:"cover_source"`
	// CoveredChecksPerSec is the product.
	CoveredChecksPerSec float64 `json:"covered_checks_per_sec"`
	// Formula spells the multiplication out for a reader of the artifact.
	Formula string `json:"formula"`
}

// AuditPressure is what the check path's audit buffer managed to put into the
// chain during a scenario, read back out of the chain itself.
//
// It is recorded next to every check scenario for two reasons. The buffer
// flushes on a timer with a bounded queue, so a sustained rate above that
// bound loses events — and a latency number taken while the audit path was
// silently shedding is a different number than one taken while it kept up.
// And ChainedEvents over BatchRows is the batch cover measured rather than
// configured, which is the one independent check on the conversion below.
type AuditPressure struct {
	ChainedEvents int64 `json:"chained_events"`
	BatchRows     int64 `json:"batch_rows"`
	DroppedEvents int64 `json:"dropped_events"`
	GapRows       int64 `json:"gap_rows"`
}

// MeanCover is the measured number of events per batch root row, or zero when
// no batch row was written.
func (p AuditPressure) MeanCover() float64 {
	if p.BatchRows == 0 {
		return 0
	}
	return float64(p.ChainedEvents) / float64(p.BatchRows)
}

// AuditedFraction is the share of the scenario's audit events that reached the
// chain, between 0 and 1.
//
// It is the number the conversion below has to be read against. The chain can
// absorb a rate the conversion states; whether the events get that far is a
// question about the buffer in front of it, and only this answers it.
func (p AuditPressure) AuditedFraction() float64 {
	total := p.ChainedEvents + p.DroppedEvents
	if total == 0 {
		return 0
	}
	return float64(p.ChainedEvents) / float64(total)
}

// Ceiling records that a scenario's latency is bounded by a declared timeout
// rather than by how fast the system is.
//
// R26 asks for the miss path to be tracked separately, and a separately tracked
// number is separately misread: a miss p99 sitting at the declared timeout
// looks like a performance problem to anyone who does not know that the
// deployment asked for exactly that bound. Recording the declaration next to
// the measurement is what keeps the two apart.
type Ceiling struct {
	// DeclaredTimeoutMillis is the configured per-call timeout.
	DeclaredTimeoutMillis float64 `json:"declared_timeout_ms"`
	// Source names where the timeout came from, as a Go field path.
	Source string `json:"source"`
	// Note is the sentence a reader of the artifact needs.
	Note string `json:"note"`
}

// Run is one execution of one scenario.
type Run struct {
	// Scenario is the stable identifier a threshold and a baseline join on.
	Scenario string `json:"scenario"`
	// Index distinguishes repeats of the same scenario in one report. Repeats
	// are how run-to-run spread gets measured rather than assumed.
	Index int `json:"index"`
	// Title is the one-line description that reaches the artifact.
	Title string `json:"title"`
	// Concurrency is how many clients drove the scenario.
	Concurrency int `json:"concurrency"`
	// OfferedRPS is the fixed rate the scenario was paced at, or zero when the
	// clients ran as fast as they could. A throughput number from a paced
	// scenario is the pacing, not a capacity, and this field is what stops a
	// reader from mistaking one for the other.
	OfferedRPS int `json:"offered_rps,omitempty"`
	// Requests, Errors and Denies count what the load generator saw. Denies
	// are not failures — a forced fact timeout denies by design — but a
	// scenario whose deny count moved is measuring something other than what
	// it measured last time.
	Requests int `json:"requests"`
	Errors   int `json:"errors"`
	Denies   int `json:"denies"`
	// FirstError is what the first failing request said, so that an error
	// count in the artifact comes with its cause.
	FirstError string `json:"first_error,omitempty"`
	// DurationMillis is the measurement window, excluding warmup.
	DurationMillis float64 `json:"duration_ms"`
	// QPS is Requests over the window.
	QPS float64 `json:"qps"`
	// Latency is the end-to-end distribution, measured at the client.
	Latency Latency `json:"latency"`
	// MissRate is the observed fraction of requests that reached the fact
	// source's upstream. It is measured from the upstream's own call counter,
	// not assumed from how the scenario was built.
	MissRate *float64 `json:"miss_rate,omitempty"`
	// Ceiling is set on scenarios whose latency is bounded by a declaration.
	Ceiling *Ceiling `json:"ceiling,omitempty"`
	// Audit is set on the audit throughput scenario.
	Audit *AuditConversion `json:"audit,omitempty"`
	// Pressure is what the audit chain received while the scenario ran.
	Pressure *AuditPressure `json:"audit_pressure,omitempty"`
}

// Environment is what the numbers are numbers of. Two reports from different
// environments are not comparable, and this is the field that lets a reader
// notice before comparing them anyway.
type Environment struct {
	GOOS          string `json:"goos"`
	GOARCH        string `json:"goarch"`
	NumCPU        int    `json:"num_cpu"`
	GoVersion     string `json:"go_version"`
	PostgresImage string `json:"postgres_image"`
	LoadModel     string `json:"load_model"`
	Host          string `json:"host,omitempty"`
}

// Report is one bench invocation's complete output.
type Report struct {
	Schema      string      `json:"schema"`
	GeneratedAt time.Time   `json:"generated_at"`
	Commit      string      `json:"commit"`
	Profile     string      `json:"profile"`
	Environment Environment `json:"environment"`
	Runs        []Run       `json:"runs"`
	// Notes are things the process said about itself while it was being
	// measured — most of the time nothing, and when it is something it is
	// worth more than any of the numbers.
	Notes []string `json:"notes,omitempty"`
}

// Add appends a run, numbering it by how many of that scenario are already in.
func (r *Report) Add(run Run) {
	for _, existing := range r.Runs {
		if existing.Scenario == run.Scenario {
			run.Index++
		}
	}
	r.Runs = append(r.Runs, run)
}

// Scenarios returns the scenario identifiers in first-seen order.
func (r *Report) Scenarios() []string {
	var out []string
	seen := map[string]bool{}
	for _, run := range r.Runs {
		if !seen[run.Scenario] {
			seen[run.Scenario] = true
			out = append(out, run.Scenario)
		}
	}
	return out
}

// Aggregate is a scenario's runs reduced to what a threshold is compared
// against, plus the spread that says whether comparing is meaningful at all.
//
// The median is the point estimate rather than the mean: one run that lost the
// CPU to another tenant of a shared runner should not move the number a gate
// reads.
type Aggregate struct {
	Scenario string `json:"scenario"`
	Title    string `json:"title"`
	Runs     int    `json:"runs"`

	P99Median float64 `json:"p99_median_ms"`
	P99Min    float64 `json:"p99_min_ms"`
	P99Max    float64 `json:"p99_max_ms"`

	QPSMedian float64 `json:"qps_median"`
	QPSMin    float64 `json:"qps_min"`
	QPSMax    float64 `json:"qps_max"`

	// SpreadPct is (max-min)/median over the p99 samples, in percent. It is
	// the number that decides whether a threshold on this runner is a gate or
	// a coin flip.
	SpreadPct float64 `json:"p99_spread_pct"`
	// QPSSpreadPct is the same for throughput.
	QPSSpreadPct float64 `json:"qps_spread_pct"`

	OfferedRPS int              `json:"offered_rps,omitempty"`
	Errors     int              `json:"errors"`
	FirstError string           `json:"first_error,omitempty"`
	Denies     int              `json:"denies"`
	MissRate   *float64         `json:"miss_rate,omitempty"`
	Ceiling    *Ceiling         `json:"ceiling,omitempty"`
	Audit      *AuditConversion `json:"audit,omitempty"`
	Pressure   *AuditPressure   `json:"audit_pressure,omitempty"`
}

// Aggregates reduces every scenario in the report.
func (r *Report) Aggregates() []Aggregate {
	var out []Aggregate
	for _, name := range r.Scenarios() {
		var p99s, qpss, missRates []float64
		agg := Aggregate{Scenario: name}
		for _, run := range r.Runs {
			if run.Scenario != name {
				continue
			}
			agg.Runs++
			agg.Title = run.Title
			agg.OfferedRPS = run.OfferedRPS
			agg.Errors += run.Errors
			agg.Denies += run.Denies
			if agg.FirstError == "" {
				agg.FirstError = run.FirstError
			}
			p99s = append(p99s, run.Latency.P99)
			qpss = append(qpss, run.QPS)
			if run.MissRate != nil {
				missRates = append(missRates, *run.MissRate)
			}
			if run.Ceiling != nil {
				agg.Ceiling = run.Ceiling
			}
			if run.Audit != nil {
				agg.Audit = run.Audit
			}
			if run.Pressure != nil {
				agg.Pressure = run.Pressure
			}
		}
		// The miss rate is a median across repeats like everything else. Taking
		// the last repeat's would let one degenerate run — the shape port
		// exhaustion produces, where requests fail before they reach the
		// source — describe the whole scenario.
		if len(missRates) > 0 {
			median, _, _ := medianMinMax(missRates)
			agg.MissRate = &median
		}
		agg.P99Median, agg.P99Min, agg.P99Max = medianMinMax(p99s)
		agg.QPSMedian, agg.QPSMin, agg.QPSMax = medianMinMax(qpss)
		agg.SpreadPct = spreadPct(agg.P99Median, agg.P99Min, agg.P99Max)
		agg.QPSSpreadPct = spreadPct(agg.QPSMedian, agg.QPSMin, agg.QPSMax)
		out = append(out, agg)
	}
	return out
}

func medianMinMax(values []float64) (median, minimum, maximum float64) {
	if len(values) == 0 {
		return 0, 0, 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	n := len(sorted)
	if n%2 == 1 {
		median = sorted[n/2]
	} else {
		median = (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return median, sorted[0], sorted[n-1]
}

func spreadPct(median, minimum, maximum float64) float64 {
	if median == 0 {
		return 0
	}
	return (maximum - minimum) / median * 100
}

// ---------------------------------------------------------------------------
// thresholds
// ---------------------------------------------------------------------------

// Threshold is one scenario's absolute bounds on one runner profile.
//
// Both bounds are optional. A scenario whose latency is set by a declared
// timeout has nothing useful to say about p99, and forcing a number there
// would be inventing one.
type Threshold struct {
	MaxP99Millis float64 `json:"max_p99_ms,omitempty"`
	MinQPS       float64 `json:"min_qps,omitempty"`
	// Basis is where the numbers came from: which measurement, and how much
	// headroom was added to it. A threshold whose basis is empty is a
	// threshold nobody can audit.
	Basis string `json:"basis"`
}

// Profile is one runner's thresholds.
type Profile struct {
	// Calibrated is whether the numbers below were measured on this runner.
	// An uncalibrated profile records and compares against the previous run
	// but issues no absolute verdict, because a bound copied from another
	// machine is noise wearing a gate's clothes.
	Calibrated bool `json:"calibrated"`
	// Runner describes the machine the profile was calibrated on.
	Runner string `json:"runner"`
	// MeasuredAt is when. Hardware and images move; a calibration has a date.
	MeasuredAt string `json:"measured_at,omitempty"`
	// Note carries whatever a reader needs before trusting the profile.
	Note string `json:"note"`
	// RegressionTolerancePct is how much worse than the previous run a metric
	// may be before the report calls it a regression. It has to exceed the
	// measured run-to-run spread on this runner or every run regresses.
	RegressionTolerancePct float64 `json:"regression_tolerance_pct"`
	// Scenarios holds the per-scenario bounds.
	Scenarios map[string]Threshold `json:"scenarios"`
}

// Thresholds is the whole thresholds document.
type Thresholds struct {
	Note     string             `json:"note"`
	Profiles map[string]Profile `json:"profiles"`
}

// LoadThresholds reads a thresholds document.
func LoadThresholds(path string) (*Thresholds, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path is the bench's own configuration file
	if err != nil {
		return nil, fmt.Errorf("bench: read thresholds: %w", err)
	}
	var t Thresholds
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("bench: decode thresholds: %w", err)
	}
	return &t, nil
}

// Profile returns one profile by name.
func (t *Thresholds) Profile(name string) (Profile, bool) {
	p, ok := t.Profiles[name]
	return p, ok
}

// Verdict is how one comparison came out.
type Verdict string

// The verdicts a comparison can produce.
//
// There is no failing verdict. U17 records and warns; promoting a warning to a
// merge failure is U18's release gate, and doing it here would put a gate on
// numbers whose runner-to-runner behaviour nobody has measured yet.
const (
	// VerdictPass means the metric met its bound.
	VerdictPass Verdict = "pass"
	// VerdictWarn means it did not.
	VerdictWarn Verdict = "warn"
	// VerdictUncalibrated means the profile has no measured bound to compare
	// against, so the number was recorded and nothing was concluded.
	VerdictUncalibrated Verdict = "uncalibrated"
	// VerdictNoBaseline means there was no previous run to compare against.
	VerdictNoBaseline Verdict = "no-baseline"
)

// Check is one metric compared against one bound.
type Check struct {
	Scenario string  `json:"scenario"`
	Metric   string  `json:"metric"`
	Observed float64 `json:"observed"`
	Bound    float64 `json:"bound,omitempty"`
	Verdict  Verdict `json:"verdict"`
	Detail   string  `json:"detail"`
}

// Regression is one metric compared against the previous run's value.
type Regression struct {
	Scenario string  `json:"scenario"`
	Metric   string  `json:"metric"`
	Previous float64 `json:"previous"`
	Current  float64 `json:"current"`
	// ChangePct is signed in the direction of worse: positive means this run
	// is worse than the previous one, for both latency and throughput. A
	// reader scanning the column should not have to remember which way each
	// metric points.
	ChangePct float64 `json:"change_pct"`
	Verdict   Verdict `json:"verdict"`
}

// Evaluation is a report compared against a profile and a baseline.
type Evaluation struct {
	Report      *Report      `json:"-"`
	ProfileName string       `json:"profile"`
	Profile     Profile      `json:"profile_detail"`
	Aggregates  []Aggregate  `json:"aggregates"`
	Checks      []Check      `json:"checks"`
	Regressions []Regression `json:"regressions"`
	// BaselineCommit names what the regression column compared against.
	BaselineCommit string `json:"baseline_commit,omitempty"`
}

// Evaluate compares a report against a profile's thresholds and, when one is
// supplied, against the previous run.
func (r *Report) Evaluate(profileName string, profile Profile, baseline *Report) Evaluation {
	ev := Evaluation{
		Report:      r,
		ProfileName: profileName,
		Profile:     profile,
		Aggregates:  r.Aggregates(),
	}
	if baseline != nil {
		ev.BaselineCommit = baseline.Commit
	}

	var baseAgg map[string]Aggregate
	if baseline != nil {
		baseAgg = map[string]Aggregate{}
		for _, a := range baseline.Aggregates() {
			baseAgg[a.Scenario] = a
		}
	}

	for _, agg := range ev.Aggregates {
		// A scenario that produced failed requests is describing a failing
		// system, and its latency and throughput describe that. The check goes
		// in ahead of the thresholds so a reader sees it before believing a
		// pass, because a fast failure is fast.
		if agg.Errors > 0 {
			ev.Checks = append(ev.Checks, Check{
				Scenario: agg.Scenario, Metric: "errors", Observed: float64(agg.Errors),
				Bound: 0, Verdict: VerdictWarn,
				Detail: "requests failed during the run; first: " + agg.FirstError,
			})
		}

		bound, hasBound := profile.Scenarios[agg.Scenario]
		switch {
		case !profile.Calibrated:
			ev.Checks = append(ev.Checks, Check{
				Scenario: agg.Scenario, Metric: "p99_ms", Observed: agg.P99Median,
				Verdict: VerdictUncalibrated,
				Detail:  "profile " + profileName + " has no measured bound on this runner",
			})
		case !hasBound:
			ev.Checks = append(ev.Checks, Check{
				Scenario: agg.Scenario, Metric: "p99_ms", Observed: agg.P99Median,
				Verdict: VerdictUncalibrated,
				Detail:  "no threshold declared for this scenario",
			})
		default:
			if bound.MaxP99Millis > 0 {
				ev.Checks = append(ev.Checks, compare(agg.Scenario, "p99_ms",
					agg.P99Median, bound.MaxP99Millis, lowerIsBetter, bound.Basis))
			}
			if bound.MinQPS > 0 {
				ev.Checks = append(ev.Checks, compare(agg.Scenario, "qps",
					agg.QPSMedian, bound.MinQPS, higherIsBetter, bound.Basis))
			}
		}

		if baseAgg == nil {
			ev.Regressions = append(ev.Regressions, Regression{
				Scenario: agg.Scenario, Metric: "p99_ms",
				Current: agg.P99Median, Verdict: VerdictNoBaseline,
			})
			continue
		}
		prev, ok := baseAgg[agg.Scenario]
		if !ok {
			ev.Regressions = append(ev.Regressions, Regression{
				Scenario: agg.Scenario, Metric: "p99_ms",
				Current: agg.P99Median, Verdict: VerdictNoBaseline,
			})
			continue
		}
		ev.Regressions = append(ev.Regressions,
			regress(agg.Scenario, "p99_ms", prev.P99Median, agg.P99Median,
				lowerIsBetter, profile.RegressionTolerancePct),
			regress(agg.Scenario, "qps", prev.QPSMedian, agg.QPSMedian,
				higherIsBetter, profile.RegressionTolerancePct))
	}
	return ev
}

type direction int

const (
	lowerIsBetter direction = iota
	higherIsBetter
)

func compare(scenario, metric string, observed, bound float64, dir direction, basis string) Check {
	verdict := VerdictPass
	if dir == lowerIsBetter && observed > bound {
		verdict = VerdictWarn
	}
	if dir == higherIsBetter && observed < bound {
		verdict = VerdictWarn
	}
	return Check{
		Scenario: scenario, Metric: metric, Observed: observed,
		Bound: bound, Verdict: verdict, Detail: basis,
	}
}

func regress(scenario, metric string, previous, current float64, dir direction, tolerance float64) Regression {
	change := 0.0
	if previous != 0 {
		if dir == lowerIsBetter {
			change = (current - previous) / previous * 100
		} else {
			change = (previous - current) / previous * 100
		}
	}
	verdict := VerdictPass
	if change > tolerance {
		verdict = VerdictWarn
	}
	return Regression{
		Scenario: scenario, Metric: metric,
		Previous: previous, Current: current, ChangePct: change, Verdict: verdict,
	}
}

// Warnings returns one line per warning verdict, threshold and regression
// alike. The bench job turns these into workflow annotations so that a
// warning is visible without opening the artifact.
func (e Evaluation) Warnings() []string {
	var out []string
	for _, c := range e.Checks {
		if c.Verdict != VerdictWarn {
			continue
		}
		out = append(out, fmt.Sprintf("%s %s = %.2f, threshold %.2f (%s)",
			c.Scenario, c.Metric, c.Observed, c.Bound, c.Detail))
	}
	for _, r := range e.Regressions {
		if r.Verdict != VerdictWarn {
			continue
		}
		out = append(out, fmt.Sprintf("%s %s regressed %.1f%% against the previous run (%.2f -> %.2f)",
			r.Scenario, r.Metric, r.ChangePct, r.Previous, r.Current))
	}
	return out
}

// ---------------------------------------------------------------------------
// artifacts
// ---------------------------------------------------------------------------

// WriteJSON writes the machine-readable half of the artifact.
func (r *Report) WriteJSON(path string) error {
	r.Schema = Schema
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("bench: encode report: %w", err)
	}
	return writeFile(path, append(raw, '\n'))
}

// LoadReport reads a results document, which is how a run compares itself
// against the previous one.
func LoadReport(path string) (*Report, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the path names a previous run's artifact
	if err != nil {
		return nil, fmt.Errorf("bench: read report: %w", err)
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("bench: decode report: %w", err)
	}
	if rep.Schema != Schema {
		return nil, fmt.Errorf("bench: report schema is %q, want %q", rep.Schema, Schema)
	}
	return &rep, nil
}

func writeFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("bench: create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("bench: write %s: %w", path, err)
	}
	return nil
}

// WriteMarkdown writes the half a person reads.
func (e Evaluation) WriteMarkdown(path string) error {
	return writeFile(path, []byte(e.Markdown()))
}

// Markdown renders the artifact.
func (e Evaluation) Markdown() string {
	var b strings.Builder
	r := e.Report

	fmt.Fprintf(&b, "# check path benchmark\n\n")
	fmt.Fprintf(&b, "- commit: `%s`\n", orDash(r.Commit))
	fmt.Fprintf(&b, "- generated: %s\n", r.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- profile: `%s` (%s)\n", e.ProfileName, calibrationWord(e.Profile))
	fmt.Fprintf(&b, "- runner: %s/%s, %d CPU, %s\n",
		r.Environment.GOOS, r.Environment.GOARCH, r.Environment.NumCPU, r.Environment.GoVersion)
	fmt.Fprintf(&b, "- database: %s\n", orDash(r.Environment.PostgresImage))
	fmt.Fprintf(&b, "- load model: %s\n\n", orDash(r.Environment.LoadModel))

	if e.Profile.Note != "" {
		fmt.Fprintf(&b, "> %s\n\n", e.Profile.Note)
	}

	b.WriteString("## measured\n\n")
	b.WriteString("Each row is the median over the repeats of that scenario in this run, ")
	b.WriteString("with the min–max spread across those repeats. ")
	b.WriteString("The spread is the number that decides whether a threshold on this runner ")
	b.WriteString("is a gate or a coin flip.\n\n")
	b.WriteString("| scenario | runs | p99 ms (min–max) | spread | QPS (min–max) | spread | errors | denies |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, a := range e.Aggregates {
		fmt.Fprintf(&b, "| `%s` | %d | %.2f (%.2f–%.2f) | %.1f%% | %.0f (%.0f–%.0f) | %.1f%% | %d | %d |\n",
			a.Scenario, a.Runs, a.P99Median, a.P99Min, a.P99Max, a.SpreadPct,
			a.QPSMedian, a.QPSMin, a.QPSMax, a.QPSSpreadPct, a.Errors, a.Denies)
	}
	b.WriteString("\n")

	for _, a := range e.Aggregates {
		if a.Title == "" {
			continue
		}
		fmt.Fprintf(&b, "- `%s`: %s", a.Scenario, a.Title)
		if a.MissRate != nil {
			fmt.Fprintf(&b, " — measured fact-source miss rate %.1f%%", *a.MissRate*100)
		}
		if a.OfferedRPS > 0 {
			fmt.Fprintf(&b, " — **paced at %d req/s**, so its QPS column is the pacing "+
				"rather than a capacity", a.OfferedRPS)
		}
		if a.Errors > 0 {
			fmt.Fprintf(&b, " — %d failed requests, first: `%s`", a.Errors, a.FirstError)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	b.WriteString("## the miss path's ceiling comes from a declaration\n\n")
	ceilings := 0
	for _, a := range e.Aggregates {
		if a.Ceiling == nil {
			continue
		}
		ceilings++
		fmt.Fprintf(&b, "- `%s`: declared timeout **%.0f ms** (%s), measured p99 %.2f ms. %s\n",
			a.Scenario, a.Ceiling.DeclaredTimeoutMillis, a.Ceiling.Source,
			a.P99Median, a.Ceiling.Note)
	}
	if ceilings == 0 {
		b.WriteString("- no scenario in this run carried a declared timeout.\n")
	}
	b.WriteString("\nA miss-path result at or near its declared timeout is the deployment ")
	b.WriteString("getting the bound it asked for, not the check path being slow. ")
	b.WriteString("Read the miss threshold against the declaration, never against the warm one.\n\n")

	b.WriteString("## audit insert throughput\n\n")
	audits := 0
	for _, a := range e.Aggregates {
		if a.Audit == nil {
			continue
		}
		audits++
		fmt.Fprintf(&b, "- %s\n", a.Audit.Formula)
		fmt.Fprintf(&b, "  - measured root inserts: **%.0f/s**\n", a.Audit.RootInsertsPerSec)
		fmt.Fprintf(&b, "  - checks covered by one root: **%d**, read from `%s`\n",
			a.Audit.CoverPerRoot, a.Audit.CoverSource)
		fmt.Fprintf(&b, "  - covered check rate: **%.0f/s**\n", a.Audit.CoveredChecksPerSec)
	}
	if audits == 0 {
		b.WriteString("- this run measured no audit scenario.\n")
	}
	b.WriteString("\n")

	b.WriteString("What the chain actually received while each check scenario ran. ")
	b.WriteString("`chained / batch rows` is the batch cover measured rather than configured, ")
	b.WriteString("and dropped events are the buffer shedding under load — a latency number ")
	b.WriteString("taken while the audit path was shedding is not the same number as one taken ")
	b.WriteString("while it kept up.\n\n")
	b.WriteString("| scenario | chained events | batch rows | measured cover | dropped | gap rows | audited |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, a := range e.Aggregates {
		if a.Pressure == nil {
			continue
		}
		fmt.Fprintf(&b, "| `%s` | %d | %d | %.1f | %d | %d | %.1f%% |\n",
			a.Scenario, a.Pressure.ChainedEvents, a.Pressure.BatchRows,
			a.Pressure.MeanCover(), a.Pressure.DroppedEvents, a.Pressure.GapRows,
			a.Pressure.AuditedFraction()*100)
	}
	b.WriteString("\nThe conversion above is the rate the chain can absorb. The audited column ")
	b.WriteString("is the share that got that far, and the two are bounded by different ")
	b.WriteString("things: the chain by its inserts, the buffer in front of it by its ")
	b.WriteString("capacity and its flush interval. A wide gap between them is the buffer ")
	b.WriteString("shedding and marking gaps, which is the designed behaviour and not a ")
	b.WriteString("chain problem.\n\n")

	b.WriteString("## thresholds\n\n")
	if len(e.Checks) == 0 {
		b.WriteString("No thresholds were evaluated.\n\n")
	} else {
		b.WriteString("| scenario | metric | observed | threshold | verdict | basis |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, c := range e.Checks {
			bound := "—"
			if c.Bound != 0 {
				bound = fmt.Sprintf("%.2f", c.Bound)
			}
			fmt.Fprintf(&b, "| `%s` | %s | %.2f | %s | %s | %s |\n",
				c.Scenario, c.Metric, c.Observed, bound, c.Verdict, orDash(c.Detail))
		}
		b.WriteString("\n")
	}
	b.WriteString("A missed threshold is a warning. Promoting it to a failing gate is the ")
	b.WriteString("release unit's decision, and it needs a calibrated profile first.\n\n")

	b.WriteString("## against the previous run\n\n")
	if e.BaselineCommit == "" {
		b.WriteString("No previous run was available; every regression verdict below is `no-baseline`.\n\n")
	} else {
		fmt.Fprintf(&b, "Baseline commit: `%s`. A change is signed so that positive always means worse. ",
			e.BaselineCommit)
		fmt.Fprintf(&b, "Tolerance: %.1f%%.\n\n", e.Profile.RegressionTolerancePct)
	}
	b.WriteString("| scenario | metric | previous | current | change | verdict |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, reg := range e.Regressions {
		prev := "—"
		change := "—"
		if reg.Verdict != VerdictNoBaseline {
			prev = fmt.Sprintf("%.2f", reg.Previous)
			change = fmt.Sprintf("%+.1f%%", reg.ChangePct)
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %.2f | %s | %s |\n",
			reg.Scenario, reg.Metric, prev, reg.Current, change, reg.Verdict)
	}
	b.WriteString("\n")

	if len(r.Notes) > 0 {
		b.WriteString("## what the process said while it was measured\n\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
		b.WriteString("\n")
	}

	if warnings := e.Warnings(); len(warnings) > 0 {
		b.WriteString("## warnings\n\n")
		for _, w := range warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
		b.WriteString("\n")
	}

	b.WriteString("## what these numbers are not\n\n")
	b.WriteString("- Not a comparison across runners. A report from one machine says nothing ")
	b.WriteString("about a report from another, and the profile is what pairs a threshold ")
	b.WriteString("with the machine it was measured on.\n")
	b.WriteString("- Not an absolute product target. The spike in `docs/spike-results.md` (S2) ")
	b.WriteString("is an order-of-magnitude probe and says so; nothing here inherits a target ")
	b.WriteString("from it.\n")
	b.WriteString("- Not an open-model load test. The generator is closed loop and shares the ")
	b.WriteString("machine with the process under test, so both the latency and the throughput ")
	b.WriteString("include that contention.\n")
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func calibrationWord(p Profile) string {
	if p.Calibrated {
		return "calibrated on " + orDash(p.Runner)
	}
	return "uncalibrated"
}

// Annotations renders the warnings and the runtime notes as GitHub workflow
// commands, so a run's summary carries them without anyone downloading the
// artifact.
func (e Evaluation) Annotations() []string {
	var out []string
	for _, w := range e.Warnings() {
		out = append(out, "::warning title=bench::"+w)
	}
	if e.Report != nil {
		for _, n := range e.Report.Notes {
			out = append(out, "::warning title=bench runtime::"+n)
		}
	}
	return out
}
