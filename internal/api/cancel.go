package api

// cancel.go is the console side of a delay: the authority named by the policy
// stops the wait, and the decision resolves to deny.
//
// It is a route of its own rather than a body on the approval endpoint, for two
// reasons that are really one. An endpoint called "approvals" that sometimes
// withdraws the thing it is named after is a surprise, and surprises in an
// authorization surface get discovered by an audit. And the approval endpoint
// treats an empty body as consent — a convention that must not be inherited by
// a verb whose accidental invocation is a denied decision.
//
// The path states the action, so the submission this layer sends is built here
// rather than forwarded from the request. Whatever the caller put in the body,
// the handler is asked to cancel, which is what the caller asked for by posting
// to this path at all. That also means there is no body a client can craft that
// names somebody else as the canceller: the canceller is the token's subject,
// established by the middleware and passed down untouched.
//
// # The cancellation budget, and why it is the tightest one
//
// R43 names four write surfaces and this is the fifth. It was the last one
// without a budget, and what made that expensive is not what a *successful*
// cancellation costs — it is what a refused one costs.
//
// A cancellation from somebody without standing writes an access-refused entry
// through a synchronous chain append, inside the serialized audit write path,
// and decision.Service settles standing before it judges state. That ordering is
// right and stays (#38: the other order tells a stranger, by status code, when a
// decision resolved), but it widened the window: the append used to be reachable
// only while a decision was pending and is now reachable for the decision's
// whole life. So an authenticated console user holding one decision identifier —
// a value the engine hands out to whoever created the decision — could drive one
// chain append per request, indefinitely, against the one write path in this
// system that does not parallelise. That is free access to a contention point
// rather than mere waste, and it is why this surface is charged before the
// lifecycle is asked anything at all.
//
// The refusal is a 429 with `Retry-After` and not the decide path's 200 with a
// denied decision object. approvals.go argues that distinction where it first
// arose and the same argument holds here, with one addition: a cancellation
// creates no decision, so there is no decision object to answer with. What is on
// the other end is a person at a console who can press the button again.
//
// The limit is **per instance**, like every other budget here: the buckets live
// in this process, so a fleet of N replicas admits N times what is configured,
// and an operator sizing a fleet divides. What bounds the fleet as a whole is
// that a cancellation is idempotent in effect — the second one finds a decision
// that is no longer collecting — which is settled in the database.

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/stream"
)

// CancellationPattern is the endpoint a cancellation authority acts through.
const CancellationPattern = "POST /decisions/{id}/challenges/{ordinal}/cancellation"

// DefaultMaxTrackedCancellers bounds the cancellation-budget table, for the
// reason [DefaultMaxTrackedApprovers] bounds the submission one: the keys are
// caller identifiers out of verified tokens, and [stream.Limiter] refuses rather
// than grows when the table is full, which is what keeps "the limiter could not
// record a charge" from being a hole.
const DefaultMaxTrackedCancellers = 4096

// DefaultCancellationRate is how often one authority may attempt a cancellation,
// for a deployment that configured no budget (R43).
//
// It is deliberately tighter than [DefaultApprovalRate], because the action is
// rarer. An approver works through a queue: several decisions are waiting on
// them and each one is a submission, so a sustained couple a second is a person
// working. A cancellation is not a queue — it is one person stopping one wait
// they are named on, once. Having stopped it there is nothing left to stop: the
// decision is denied and a second attempt is refused by the lifecycle.
//
// So what the burst has to cover is not work, it is the ways one intent turns
// into more than one request: a double-clicked button, a page reloaded because
// the answer was slow, a second tab. Five covers all of those together and is
// still under the count of an operator having a bad day. The sustained rate is
// one a second, which is faster than a person can read the result of the last
// one, and slower by three orders of magnitude than what a loop does.
//
// Being wrong here is cheap in the direction it is likely to be wrong. The
// person refused is holding a `Retry-After` of one second and a console that
// says so, and they are cancelling something whose deadline is measured in
// hours — a delay challenge that expired in the second they waited was not a
// challenge this budget cost them.
//
// An operator who wants no limit says so with a negative rate.
var DefaultCancellationRate = stream.RateLimit{PerSecond: 1, Burst: 5}

// The vocabulary of a cancellation refused under the budget.
const (
	// CancellationRateLimitedCode is the error code the console reads. It is the
	// same code the approval surface answers with, because a console does the
	// same thing with it — say "slow down" and offer the button again — and the
	// error vocabulary is documented per meaning rather than per route.
	CancellationRateLimitedCode = "rate_limited"

	// CancellationRateLimitedReason is the ground written into the audit record.
	//
	// It is its own word, distinct from the approval surface's
	// `approval_rate_limited` and the decide path's `rate_limited`, for the
	// reason those two are distinct from each other: an operator reading the
	// chain has to know which surface shed. The three answer different
	// questions — a PEP asking for too many decisions, an approver submitting
	// too often, an authority hammering a cancellation — and they are three
	// different settings to reach for.
	CancellationRateLimitedReason = "cancellation_rate_limited"

	// rateScopeCanceller names the budget in the audit record, alongside the
	// "caller", "subject" and "approver" the other surfaces write.
	rateScopeCanceller = "canceller"
)

// CancellationsConfig configures a [Cancellations].
type CancellationsConfig struct {
	// Decisions collects submissions. Required.
	Decisions ApprovalSubmitter
	// Rate bounds cancellation attempts per authority (R43). A zero field
	// selects [DefaultCancellationRate] for that field; a negative rate removes
	// the limit.
	Rate stream.RateLimit
	// MaxTrackedCancellers overrides [DefaultMaxTrackedCancellers].
	MaxTrackedCancellers int
	// Audit records refusals under the budget. It is optional only so that a
	// test of this surface need not stand up a chain writer; a deployment that
	// leaves it nil has a limit that sheds silently, which is why the wiring
	// passes the same buffer the approval and decide surfaces write through.
	Audit EventRecorder
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Cancellations serves the delay cancellation endpoint.
type Cancellations struct {
	decisions ApprovalSubmitter
	limiter   *stream.Limiter
	rate      stream.RateLimit
	audit     EventRecorder
	now       func() time.Time
}

var _ Provider = (*Cancellations)(nil)

// NewCancellations builds the cancellation surface.
func NewCancellations(cfg CancellationsConfig) (*Cancellations, error) {
	if cfg.Decisions == nil {
		return nil, errors.New("api: the cancellation surface requires a decision service")
	}
	c := &Cancellations{
		decisions: cfg.Decisions,
		rate:      cfg.Rate,
		audit:     cfg.Audit,
		now:       cfg.Now,
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.rate = c.rate.WithZeroDefault(DefaultCancellationRate)
	tracked := cfg.MaxTrackedCancellers
	if tracked <= 0 {
		tracked = DefaultMaxTrackedCancellers
	}
	c.limiter = stream.NewLimiter(tracked, func() time.Time { return c.now() })
	return c, nil
}

// Routes implements [Provider]. A cancellation is a console action behind an
// end-user credential, which is the only pair the mount table admits there — so
// a workload cannot reach this endpoint at all, quite apart from the handler
// refusing one.
func (c *Cancellations) Routes() []Route {
	return []Route{{
		Name:    "delay-cancel",
		Surface: SurfaceConsole,
		Pattern: CancellationPattern,
		Auth:    AuthUser,
		Handler: http.HandlerFunc(c.cancel),
	}}
}

func (c *Cancellations) cancel(w http.ResponseWriter, r *http.Request) {
	caller, ok := identity.SubjectFromContext(r.Context())
	if !ok || caller == nil {
		// Unreachable behind RequireUser, and still checked: the day this route
		// is mounted somewhere else, the failure should be a 401 and not a
		// cancellation attributed to nobody.
		writeError(w, http.StatusUnauthorized, "unauthenticated", "this endpoint requires an end-user credential")
		return
	}
	// Charged before the path is parsed, because everything below this line is
	// work a caller over its budget has already been told it may not have — and
	// on this surface "everything below" includes a synchronous audit-chain
	// append for a caller with no standing, which is the cost this budget
	// exists to bound. The key is the caller identifier the verified token
	// established and never anything from the request, so a budget cannot be
	// escaped by spelling a decision differently.
	if !c.limiter.Allow("canceller\x1f"+caller.CallerID(), c.rate, 1) {
		c.refuseCancellation(w, r, caller)
		return
	}

	id, ordinal, err := challengeRef(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	result, err := c.decisions.Submit(r.Context(), decision.Submission{
		Caller:     caller,
		DecisionID: id,
		Ordinal:    ordinal,
		Payload:    challenge.DelayCancelPayload(),
	})
	if err != nil {
		// The same table the approval surface uses. A cancellation refused for
		// not holding the authority has to be indistinguishable from a decision
		// that does not exist, and that mapping already exists in one place.
		status, code, message := approvalError(err)
		writeError(w, status, code, message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// refuseCancellation answers a cancellation over the budget and records it.
//
// The audit goes through the buffer and not through a synchronous chain append,
// which is the whole point of this unit rather than a detail of it: the append
// on the refusal path is the cost being bounded, and paying it again to record
// that it was bounded would leave the surface generating exactly the load the
// limit exists to shed — one append per request either way, with a 429 instead
// of a 404 to show for it.
//
// What can be lost that way is the record of a refusal, never the record of a
// cancellation that took effect: that one is written by the lifecycle, inside
// the transaction that denied the decision.
//
// `Retry-After` carries the budget's refill interval, and here the header is in
// the place RFC 9110 defines it — a 429 is one of the three statuses it names —
// so the console in front of the person, and everything between, read the same
// number.
func (c *Cancellations) refuseCancellation(w http.ResponseWriter, r *http.Request, caller *identity.Subject) {
	if c.audit != nil {
		c.audit.Record(r.Context(), Event{
			Kind:     EventRateLimited,
			Time:     c.now(),
			CallerID: caller.CallerID(),
			Reason:   CancellationRateLimitedReason,
			Method:   r.Method,
			Path:     r.URL.Path,
			Scope:    rateScopeCanceller,
			Limit:    formatRate(c.rate),
		})
	}
	w.Header().Set(RetryAfterHeader, strconv.Itoa(retryAfterSeconds(c.rate)))
	writeError(w, http.StatusTooManyRequests, CancellationRateLimitedCode,
		"too many cancellation attempts; try again shortly")
}
