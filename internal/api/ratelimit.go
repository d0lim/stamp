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
	"net/http"
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

// decideLimiter charges the two budgets and reports which one ran out.
type decideLimiter struct {
	limiter *stream.Limiter
	caller  stream.RateLimit
	subject stream.RateLimit
}

func newDecideLimiter(caller, subject stream.RateLimit, maxEntries int, now func() time.Time) *decideLimiter {
	// A zero field takes the default for that field, so an operator who raised
	// the burst does not have to restate the rate.
	if caller.PerSecond == 0 {
		caller.PerSecond = DefaultDecideRate.PerSecond
	}
	if caller.Burst == 0 {
		caller.Burst = DefaultDecideRate.Burst
	}
	if subject.PerSecond == 0 {
		subject.PerSecond = DefaultDecideSubjectRate.PerSecond
	}
	if subject.Burst == 0 {
		subject.Burst = DefaultDecideSubjectRate.Burst
	}
	return &decideLimiter{
		limiter: stream.NewLimiter(maxEntries, now),
		caller:  caller,
		subject: subject,
	}
}

// allowCaller charges one decide against the caller's budget.
//
// The key is prefixed so that a caller identifier can never collide with a
// subject identifier: the two namespaces are unrelated and both are attacker
// influenced, and one budget answering for the other is a limit that can be
// spent by someone it was not measuring.
func (l *decideLimiter) allowCaller(callerID string) bool {
	return l.limiter.Allow("caller\x1f"+callerID, l.caller, 1)
}

// allowSubject charges one decide against the subject's budget.
//
// The key is the subject identifier alone — no type, no caller. No type,
// because the outstanding cap this limit protects counts by subject identifier
// alone, and a limiter that split what the cap merges would let the same
// identifier be charged twice as much by being called two things. No caller, for
// the reason at the top of this file.
func (l *decideLimiter) allowSubject(subjectID string) bool {
	return l.limiter.Allow("subject\x1f"+subjectID, l.subject, 1)
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
