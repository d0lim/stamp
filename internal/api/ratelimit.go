package api

// ratelimit.go is the decide path's half of R43: a rate limit per caller and
// per subject, applied ahead of the evaluation, whose refusal is a deny and an
// audit record rather than a status code.
//
// R43 asks for two bounds and the repository already had one of them. The
// outstanding-decision cap — how many unresolved decisions one subject may hold
// — lives in decision.Service, is counted in the database, and therefore binds
// across every replica. This is the other one, and it is deliberately not built
// the same way.
//
// Where it stands is the whole point. A limit that is applied after the
// evaluation has not limited anything that costs: by then the policy set has
// been walked, the fact sources have been asked, and the work the limit exists
// to shed has been done. So the charge happens at the surface, before the
// request body has even been resolved against the schema, and the tests assert
// the negative — that nothing below this point ran.
//
// What it costs to stand there is that it cannot be a database limit. decide is
// the second hottest path this system has, and a limiter that queried per
// request would be paying, on the fast path, exactly the price it exists to
// avoid. So the buckets are in this process, and the honest consequence is
// this: **the configured rate is per instance, so N replicas admit N times it.**
// That is survivable only because it is the soft half of a pair. The absolute
// bound on what a subject can accumulate is the outstanding cap, which is in
// the database and is not per instance; this limit is the cushion above it that
// keeps a flood from reaching it. An operator sizing a fleet has to divide.
//
// The two keys differ from the ingest adapter's in one deliberate way, and it
// is a trade rather than an oversight. There, the per-subject key includes the
// caller, so that one caller flooding a subject cannot exhaust another caller's
// budget for that subject. Here the per-subject key is the subject alone, so
// the budget sums across callers. The reason is what the two paths create: an
// ingest event lands in an aggregate that is already bounded by the metric's
// window, while a decide creates a pending decision that occupies one of the
// subject's outstanding slots — and those slots are counted per subject, not
// per (caller, subject). A per-caller-per-subject key would let N callers open
// N times the subject's budget worth of decisions against the one cap that is
// supposed to bound them. The cost of the choice is real and worth naming: a
// caller that floods one subject does deny other callers that subject, for as
// long as the bucket takes to refill.

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/store"
	"github.com/d0lim/stamp/internal/stream"
)

// The rates a deployment that configured none runs at.
//
// They are real numbers rather than "unlimited" because an unconfigured
// deployment is the one most likely to be the one that needed the limit. An
// operator who genuinely wants no limit says so with a negative rate; leaving
// the variable unset is not that statement.
//
// The subject burst is chosen against the outstanding cap it protects.
// decision.DefaultMaxOutstanding is 32, so a burst of 10 cannot convert into an
// exhausted cap in one go, and the sustained rate reaches the cap in a handful
// of seconds of uninterrupted traffic — at which point the database-backed cap
// takes over and the refusal becomes one that holds across the fleet. The
// caller rate is an order of magnitude larger because one enforcement point
// legitimately serves many subjects at once.
var (
	// DefaultDecideRate is the per-caller rate for a deployment that set none.
	DefaultDecideRate = stream.RateLimit{PerSecond: 50, Burst: 100}
	// DefaultDecideSubjectRate is the per-subject rate for a deployment that set
	// none.
	DefaultDecideSubjectRate = stream.RateLimit{PerSecond: 5, Burst: 10}
)

// The two budgets, as they are named in the audit record.
const (
	rateScopeCaller  = "caller"
	rateScopeSubject = "subject"
)

// RetryAfterHeader is the one transport-level thing a shed request says.
//
// The header exists because the refusal's body does not travel. A denied
// decision object is legible to something that speaks this API, and the things
// between a PEP and this handler — a retry middleware, a gateway, a dashboard —
// do not: they read a status line and a header table. Without one of those
// saying anything, a request that was shed and a request that was judged are the
// same event to every one of them, which is the blindness #45 names.
const RetryAfterHeader = "Retry-After"

// maxRetryAfterSeconds bounds what a refusal will ask a caller to wait.
//
// A budget can be configured arbitrarily slow, and 1/PerSecond for a very small
// rate is a number no client will honour and float arithmetic will eventually
// stop representing. Clamping under-promises — a caller comes back too early and
// is refused again, which is the state it was already in. Over-promising is the
// failure that matters, because a caller told to wait longer than the budget
// needs has been made slower than the limit asks for, by the limit.
const maxRetryAfterSeconds = 3600

// retryAfterSeconds is how long until this budget has a token again, in the
// whole seconds RFC 9110 gives the header.
//
// It is the refill interval — one token's worth of time at the sustained rate —
// and not the time until the bucket is full. What a refused caller needs is the
// moment one more request will be admitted, and the burst above that is capacity
// they have already spent.
//
// It rounds up, because the alternative rounds a sub-second interval to zero and
// invites the retry storm the limit exists to shed: every budget this surface
// ships by default refills faster than once a second, so zero would be the
// common answer rather than the edge case.
func retryAfterSeconds(l stream.RateLimit) int {
	if l.PerSecond <= 0 {
		// Not reachable from a refusal — an unlimited budget refuses nothing —
		// but a header that said "0" or "-1" would be worse than the one second
		// this answers with if a later caller finds a path here.
		return 1
	}
	interval := math.Ceil(1 / l.PerSecond)
	if interval < 1 {
		return 1
	}
	if interval > maxRetryAfterSeconds {
		return maxRetryAfterSeconds
	}
	return int(interval)
}

// decideLimiter charges the two budgets and reports which one ran out.
//
// The two budgets get two tables, and that is the part worth stating, because
// one table with two key namespaces in it is the shape this started as. A
// bounded table refuses when it is full and a sweep frees nothing, so the
// entries in it are a resource the keys compete for: a flood of invented
// subjects would fill a shared table, and the next caller to arrive — one that
// had spent none of its own budget — would be refused for pressure it did not
// create. Prefixing the keys kept the two namespaces from naming the same
// bucket; it did nothing about the one cap they were both spending.
type decideLimiter struct {
	callers  *stream.Limiter
	subjects *stream.Limiter
	caller   stream.RateLimit
	subject  stream.RateLimit
}

// newDecideLimiter gives each budget a table of maxEntries.
//
// maxEntries bounds each table rather than the two together, so the split costs
// memory rather than capacity. Measured, a limiter entry — the bucket, the map
// slot and the key's bytes at the length the decide surface's keys actually run
// to — is 136 bytes, so a table at the 8192-entry default holds about 1.06 MiB
// and the second one costs that again. That is the whole of the price, and it
// is paid by a process that already holds a policy set, a schema cache and a
// database pool.
//
// The alternative was to divide the existing 8192 between the two tables, and it
// is the wrong trade in the direction that matters. The caller table needs one
// entry per credential — a deployment has as many as it has PEPs — while the
// subject table needs one per distinct subject in flight, which is the number
// that grows with traffic. Halving that one narrows the window before
// sweep-or-refuse starts refusing legitimate requests, which is to say it would
// buy back a megabyte by making the availability property worse under exactly
// the load this limit exists for.
func newDecideLimiter(caller, subject stream.RateLimit, maxEntries int, now func() time.Time) *decideLimiter {
	caller = caller.WithZeroDefault(DefaultDecideRate)
	subject = subject.WithZeroDefault(DefaultDecideSubjectRate)
	return &decideLimiter{
		callers:  stream.NewLimiter(maxEntries, now),
		subjects: stream.NewLimiter(maxEntries, now),
		caller:   caller,
		subject:  subject,
	}
}

// allowCaller charges one decide against the caller's budget.
//
// The key is the caller identifier unprefixed, because the table it goes in
// holds nothing else. A caller identifier and a subject identifier are unrelated
// strings from unrelated namespaces and both are attacker influenced, so one
// bucket answering for both would be a budget spendable by someone it was not
// measuring — that guarantee used to be a `\x1f` prefix on a shared table's key
// and is now the separation of the tables themselves. Merging them back
// reintroduces both the collision and the crowding out above it.
func (l *decideLimiter) allowCaller(callerID string) bool {
	return l.callers.Allow(callerID, l.caller, 1)
}

// allowSubject charges one decide against the subject's budget.
//
// The key is the subject identifier alone — no type, no caller. No type,
// because the outstanding cap this limit protects counts by subject identifier
// alone, and a limiter that split what the cap merges would let the same
// identifier be charged twice as much by being called two things. No caller, for
// the reason at the top of this file.
func (l *decideLimiter) allowSubject(subjectID string) bool {
	return l.subjects.Allow(subjectID, l.subject, 1)
}

// rateRefusal is everything the surface has to say about a request it shed.
type rateRefusal struct {
	scope string
	limit stream.RateLimit
	// req is the parsed request, empty when the caller's budget ran out before
	// the body was read.
	req EvaluationRequest
}

// refuseRate answers a rate-limited decide and records it.
//
// The answer is a denied decision object with HTTP 200, not a 429. R43 says a
// request over the limit is denied, and it is the same word the outstanding cap
// uses for the same kind of refusal; a PEP that has to branch on the transport
// to learn that its request was judged has two answers to keep in step. What
// makes this deny distinguishable from a policy deny is the reason, which is
// the mechanism decision.ReasonOutstandingCap already established.
//
// The response carries `Retry-After`, and that is the one part of it that is
// unusual enough to want stating. RFC 9110 specifies the header on 429, 503 and
// the 3xx redirects, and this is a 200 — so it is being used outside the letter
// of the specification, deliberately, and with its eyes open. The alternative
// was worse in both directions: changing the status to 429 breaks the property
// above (a PEP would have to read the transport to learn it was judged), and
// leaving the header off leaves every intermediary unable to tell a shed request
// from a judged one, which is the whole of #45. What is being claimed is narrow
// — the header is advisory in every direction, a client that ignores it is
// correct, and no cache or proxy behaviour keys on it at 200 — so an
// intermediary that reads it gains a true signal and one that does not loses
// nothing it had.
//
// The audit goes through the buffer rather than through a synchronous chain
// append, and the reasoning is in the shape of the thing being recorded. This is
// the path taken by a caller sending more than it is allowed to; a synchronous
// append would turn each refusal into a database transaction on the serialized
// audit chain, which is to say the limiter would generate load in proportion to
// the load it exists to shed, and the refusal would cost more than the request
// it refused. The price is that the buffer drops under saturation. It does not
// drop silently — a gap marker names the window and the count, so verification
// reports a hole rather than a clean chain — and what would be lost is the
// record of requests that were refused, never the record of anything that was
// allowed to persist. The bound that must not be lost is the outstanding cap,
// and that one is audited synchronously by decision.Service.refuse.
func (d *Decisions) refuseRate(w http.ResponseWriter, r *http.Request, callerID string, ref rateRefusal) {
	e := Event{
		Kind:     EventRateLimited,
		Time:     d.now(),
		CallerID: callerID,
		Decision: engine.Deny.String(),
		Reason:   string(decision.ReasonRateLimited),
		Method:   r.Method,
		Path:     DecisionsPath,
		Scope:    ref.scope,
		Limit:    formatRate(ref.limit),
	}
	if ref.req.Subject.ID != "" {
		e.Action = ref.req.Action.Name
		e.Subject = ref.req.Subject.Type + ":" + ref.req.Subject.ID
		e.Resource = ref.req.Resource.Type + ":" + ref.req.Resource.ID
	}
	d.audit.Record(r.Context(), e)

	// The budget that ran out is the one whose interval is named: a caller told
	// to wait the subject budget's interval when it was its own that was spent
	// has been handed a number about somebody else's traffic.
	w.Header().Set(RetryAfterHeader, strconv.Itoa(retryAfterSeconds(ref.limit)))
	writeJSON(w, http.StatusOK, decision.Result{
		State:       store.DecisionDenied,
		Outcome:     engine.Deny,
		Reason:      decision.ReasonRateLimited,
		Obligations: []decision.Obligation{},
	})
}

// formatRate renders a budget for the audit record, so that a reader can tell
// whether a refusal came from a limit that was later raised.
func formatRate(l stream.RateLimit) string {
	return fmt.Sprintf("%g/s burst %g", l.PerSecond, l.Burst)
}
