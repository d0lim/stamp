package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/store"
	"github.com/d0lim/stamp/internal/stream"
)

// R43's rate limit on the decide creation path.
//
// The half of R43 that bounds *state* — how many unresolved decisions one
// subject may hold — was already there, counted in the database by
// decision.Service. This is the half that bounds *work*, and the two are built
// differently on purpose: the cap has to be exact across a fleet, and this one
// has to be cheap enough to stand in front of an evaluation.
//
// These tests are about five claims. That the limit refuses. That its refusal
// is a deny a PEP can tell apart from a policy deny. That the refusal happens
// before anything expensive runs — which is the only reason a rate limit is
// worth having. That the limiter itself cannot be turned into the memory leak
// its keys would otherwise invite. And that the two budgets are two budgets all
// the way down: not merely two keys in one bounded table, whose entries they
// would then be competing for.

// generous is a budget large enough not to be the limit under test, so that a
// test about one budget is not silently also a test about the other.
var generous = stream.RateLimit{PerSecond: 1e6, Burst: 1e6}

// denied reads a decide response as the denied decision object a rate-limited
// request gets, and reports whether that is what it is.
func denied(t *testing.T, rec *httptest.ResponseRecorder) (reason string, isDeny bool) {
	t.Helper()
	if rec.Code != http.StatusOK {
		return "", false
	}
	var body struct {
		ID     string `json:"id"`
		State  string `json:"state"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if body.ID != "" {
		// A refusal must not name a decision: there is no row to follow, and an
		// identifier that leads nowhere is worse than none.
		t.Errorf("a refused decide carries an identifier %q", body.ID)
	}
	return body.Reason, body.State == string(store.DecisionDenied)
}

// ---------------------------------------------------------------------------
// the refusal, and what makes it distinguishable
// ---------------------------------------------------------------------------

// TestDecideRefusesACallerOverItsBurst is the unit's red: with no limiter, a
// caller creates decisions as fast as it can send them.
//
// The refusal is a deny with HTTP 200 and not a 429, because R43 says a request
// over the limit is denied and the outstanding cap already answers the same way.
// What separates it from a policy deny is the reason.
func TestDecideRefusesACallerOverItsBurst(t *testing.T) {
	f := newDecideFixture(t, decideOptions{
		rate:        stream.RateLimit{PerSecond: 1000, Burst: 3},
		subjectRate: generous,
	})
	token := f.workload(t, "svc-flood")

	for i := range 3 {
		if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
			t.Fatalf("request %d within the burst = %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	rec := f.create(t, token, decideBody(""))
	reason, isDeny := denied(t, rec)
	if !isDeny {
		t.Fatalf("the request over the burst = %d %s, want a denied decision", rec.Code, rec.Body.String())
	}
	if reason != string(decision.ReasonRateLimited) {
		t.Errorf("reason = %q, want %q", reason, decision.ReasonRateLimited)
	}
	// The point of the reason: a PEP that retries a policy deny forever is
	// broken, and a PEP that gives up on a rate limit forever is also broken, so
	// the two must not arrive wearing the same word.
	if reason == string(engine.ReasonNoMatchingPolicy) || reason == string(decision.ReasonOutstandingCap) {
		t.Errorf("a rate-limit deny is indistinguishable from another refusal: %q", reason)
	}
}

// TestDecideSubjectBudgetsAreSeparate: the same caller asking about a different
// subject spends a different budget. A per-subject limit that one busy subject
// could exhaust for every other subject would be an availability bug wearing a
// security control's clothes.
func TestDecideSubjectBudgetsAreSeparate(t *testing.T) {
	f := newDecideFixture(t, decideOptions{
		rate:        generous,
		subjectRate: stream.RateLimit{PerSecond: 1000, Burst: 2},
	})
	token := f.workload(t, "svc-payments")

	for i := range 2 {
		if rec := f.create(t, token, decideBodyFor("acct-a")); rec.Code != http.StatusCreated {
			t.Fatalf("request %d for the first subject = %d", i, rec.Code)
		}
	}
	if _, isDeny := denied(t, f.create(t, token, decideBodyFor("acct-a"))); !isDeny {
		t.Fatal("the first subject was not limited after its burst")
	}

	// A second subject, same caller, same instant: its own bucket, untouched.
	if rec := f.create(t, token, decideBodyFor("acct-b")); rec.Code != http.StatusCreated {
		t.Errorf("a second subject = %d %s, want the request admitted on its own budget",
			rec.Code, rec.Body.String())
	}
}

// TestDecideSubjectBudgetSumsAcrossCallers: one subject's budget is one budget,
// however many callers spend it.
//
// This is the deliberate divergence from the ingest adapter, where the
// per-subject key includes the caller. What a decide creates is a pending
// decision that occupies one of *the subject's* outstanding slots, and those are
// counted per subject; a key that split the budget per caller would let N
// callers open N times the subject's budget worth of decisions against the one
// cap meant to bound them. The cost — a caller flooding a subject does deny
// other callers that subject until the bucket refills — is the price of the
// bound being about the subject.
func TestDecideSubjectBudgetSumsAcrossCallers(t *testing.T) {
	f := newDecideFixture(t, decideOptions{
		rate:        generous,
		subjectRate: stream.RateLimit{PerSecond: 1000, Burst: 2},
	})

	for _, caller := range []string{"svc-one", "svc-two"} {
		if rec := f.create(t, f.workload(t, caller), decideBodyFor("acct-hot")); rec.Code != http.StatusCreated {
			t.Fatalf("%s within the subject's burst = %d", caller, rec.Code)
		}
	}

	// A third caller, well inside its own budget, finds the subject's spent.
	rec := f.create(t, f.workload(t, "svc-three"), decideBodyFor("acct-hot"))
	if _, isDeny := denied(t, rec); !isDeny {
		t.Fatalf("a third caller on the same subject = %d %s, want the subject's budget to have summed",
			rec.Code, rec.Body.String())
	}
	events := f.audit.snapshot()
	if len(events) != 1 || events[0].Scope != "subject" {
		t.Errorf("the refusal was attributed to the wrong budget: %+v", events)
	}
}

// ---------------------------------------------------------------------------
// the audit record
// ---------------------------------------------------------------------------

// TestDecideRateRefusalIsAudited: R43 asks the refusal itself to be recorded,
// and a refusal that leaves no trace is indistinguishable from a request that
// was never made. The row has to carry enough to answer "who, about whom, and
// against what limit" — the last of which nobody can reconstruct later, because
// the limit is a setting that changes.
func TestDecideRateRefusalIsAudited(t *testing.T) {
	limit := stream.RateLimit{PerSecond: 1000, Burst: 1}
	f := newDecideFixture(t, decideOptions{rate: generous, subjectRate: limit})
	token := f.workload(t, "svc-auditable")

	if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
		t.Fatalf("the first request = %d", rec.Code)
	}
	if _, isDeny := denied(t, f.create(t, token, decideBody(""))); !isDeny {
		t.Fatal("the second request was not limited")
	}

	events := f.audit.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly the one refusal: %+v", len(events), events)
	}
	e := events[0]
	switch {
	case e.Kind != api.EventRateLimited:
		t.Errorf("kind = %q, want %q", e.Kind, api.EventRateLimited)
	case e.CallerID == "" || !strings.Contains(e.CallerID, "svc-auditable"):
		t.Errorf("caller = %q, want the authenticated caller", e.CallerID)
	case e.Subject != "account:acct-src":
		t.Errorf("subject = %q, want the subject the request was about", e.Subject)
	case e.Scope != "subject":
		t.Errorf("scope = %q, want the budget that ran out", e.Scope)
	case e.Limit != "1000/s burst 1":
		t.Errorf("limit = %q, want the budget as it was configured", e.Limit)
	case e.Reason != string(decision.ReasonRateLimited):
		t.Errorf("reason = %q, want %q", e.Reason, decision.ReasonRateLimited)
	case e.Decision != engine.Deny.String():
		t.Errorf("decision = %q, want a deny", e.Decision)
	case !e.Time.Equal(f.clock.Now()):
		t.Errorf("time = %v, want the surface's clock", e.Time)
	}
}

// TestDecideRateRefusalOnTheCallerBudgetIsAudited: a caller that trips its own
// budget is refused before its body is read, so the row names no subject — and
// still names the caller, the scope and the limit, which is what an operator
// diagnosing a shed load needs.
func TestDecideRateRefusalOnTheCallerBudgetIsAudited(t *testing.T) {
	f := newDecideFixture(t, decideOptions{
		rate:        stream.RateLimit{PerSecond: 4, Burst: 1},
		subjectRate: generous,
	})
	token := f.workload(t, "svc-noisy")

	if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
		t.Fatalf("the first request = %d", rec.Code)
	}
	if _, isDeny := denied(t, f.create(t, token, decideBody(""))); !isDeny {
		t.Fatal("the second request was not limited")
	}

	events := f.audit.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want one: %+v", len(events), events)
	}
	if events[0].Scope != "caller" {
		t.Errorf("scope = %q, want the caller's budget", events[0].Scope)
	}
	if events[0].Limit != "4/s burst 1" {
		t.Errorf("limit = %q", events[0].Limit)
	}
	if events[0].Subject != "" {
		t.Errorf("subject = %q, want none: the body was never read", events[0].Subject)
	}
}

// TestTheNewEventFieldsDoNotDisturbTheChain: the audit chain records Merkle
// roots over event leaves, and a leaf is the event's JSON. Two fields were added
// to Event for this unit, and an event of any other kind has to hash to exactly
// what it hashed to before — otherwise every root written by an older process
// becomes unverifiable by a newer one.
func TestTheNewEventFieldsDoNotDisturbTheChain(t *testing.T) {
	at := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	check := api.Event{
		Kind: api.EventCheck, Time: at, CallerID: "workload:svc-a",
		Action: "read", Subject: "user:alice", Resource: "doc:doc-1",
		Decision: "allow", Reason: "policy_matched", PolicyID: "p", Revision: "rev-1",
		Method: http.MethodPost, Path: api.EvaluationPath, Allowed: true,
	}
	// The digest is pinned rather than recomputed, because a test that recomputes
	// it from the same struct would agree with any encoding at all. The value was
	// taken from the Event as it stood before the two fields were added.
	const wantCheck = "cfed2be90060d2644a5a3dad149678213a7b6d957476256343ff7a3d73cfc3bf"
	if got := fmt.Sprintf("%x", check.Leaf()); got != wantCheck {
		t.Errorf("the check event's leaf changed:\n got %s\nwant %s", got, wantCheck)
	}
}

// ---------------------------------------------------------------------------
// the limiter standing where it has to stand
// ---------------------------------------------------------------------------

// TestARateLimitedDecideEvaluatesNothing is the point of the unit.
//
// A limit applied after the evaluation has not limited anything that costs: by
// then the schema has been read, the input built, the policy set walked and the
// fact sources asked. So the assertion is the negative one — that a refused
// request reached neither the schema nor the lifecycle. Fact resolution is
// strictly inside the lifecycle's Decide, and the outstanding-cap query is too,
// so a request that did not reach it did neither.
func TestARateLimitedDecideEvaluatesNothing(t *testing.T) {
	t.Run("the caller's budget", func(t *testing.T) {
		f := newDecideFixture(t, decideOptions{
			rate:        stream.RateLimit{PerSecond: 1000, Burst: 1},
			subjectRate: generous,
		})
		token := f.workload(t, "svc-flood")
		if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
			t.Fatalf("the first request = %d", rec.Code)
		}
		decided, reads := f.life.decided(), f.schema.reads.Load()

		if _, isDeny := denied(t, f.create(t, token, decideBody(""))); !isDeny {
			t.Fatal("the second request was not limited")
		}
		if got := f.life.decided(); got != decided {
			t.Errorf("the lifecycle ran %d times over the limit, want none", got-decided)
		}
		if got := f.schema.reads.Load(); got != reads {
			t.Errorf("the policy schema was read %d times over the limit, want none", got-reads)
		}
	})

	t.Run("the subject's budget", func(t *testing.T) {
		f := newDecideFixture(t, decideOptions{
			rate:        generous,
			subjectRate: stream.RateLimit{PerSecond: 1000, Burst: 1},
		})
		token := f.workload(t, "svc-flood")
		if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
			t.Fatalf("the first request = %d", rec.Code)
		}
		decided, reads := f.life.decided(), f.schema.reads.Load()

		if _, isDeny := denied(t, f.create(t, token, decideBody(""))); !isDeny {
			t.Fatal("the second request was not limited")
		}
		if got := f.life.decided(); got != decided {
			t.Errorf("the lifecycle ran %d times over the limit, want none", got-decided)
		}
		// The body had to be read to learn the subject, but nothing after that
		// did: no schema read means no evaluation input was ever built.
		if got := f.schema.reads.Load(); got != reads {
			t.Errorf("the policy schema was read %d times over the limit, want none", got-reads)
		}
	})
}

// TestDecideBudgetsRefill: the limit is a rate and not a quota, so a caller that
// waits gets its budget back without anything having to be reset.
func TestDecideBudgetsRefill(t *testing.T) {
	f := newDecideFixture(t, decideOptions{
		rate:        generous,
		subjectRate: stream.RateLimit{PerSecond: 2, Burst: 2},
	})
	token := f.workload(t, "svc-patient")

	for range 2 {
		if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
			t.Fatalf("a request within the burst = %d", rec.Code)
		}
	}
	if _, isDeny := denied(t, f.create(t, token, decideBody(""))); !isDeny {
		t.Fatal("the request over the burst was admitted")
	}

	// Half a second buys one token at two per second, and no more than one: the
	// bucket refills at the rate, not to the burst.
	f.clock.Advance(500 * time.Millisecond)
	if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
		t.Errorf("after the budget refilled = %d %s", rec.Code, rec.Body.String())
	}
	if _, isDeny := denied(t, f.create(t, token, decideBody(""))); !isDeny {
		t.Error("the refill handed back more than it had accrued")
	}
}

// TestDecideRateLimiterTablesAreBounded: the limiter's keys are request-derived
// — the subject identifier comes out of the body — so an unbounded table would
// let an authenticated caller grow this process's memory by inventing subjects.
//
// When a table is full it is swept of buckets that have refilled to full, and a
// sweep that frees nothing refuses: a limiter that cannot record a charge has
// not applied a limit, and admitting the request unmetered is the one answer
// that would make the bound exploitable rather than merely inconvenient.
//
// There are two tables and the bound is each table's own, so both halves are
// exercised: a table that was bounded only in company with the other would be a
// table nothing had checked.
func TestDecideRateLimiterTablesAreBounded(t *testing.T) {
	// Enormous budgets, so every refusal below is a full table and not a spent
	// bucket.
	huge := stream.RateLimit{PerSecond: 1000, Burst: 1000}

	t.Run("the subject table", func(t *testing.T) {
		f := newDecideFixture(t, decideOptions{rate: huge, subjectRate: huge, maxRateEntries: 2})
		token := f.workload(t, "svc-inventive")

		// Two invented subjects fill the subject table. The caller's own table
		// holds one entry and is not what is being filled here.
		for i := range 2 {
			rec := f.create(t, token, decideBodyFor(fmt.Sprintf("acct-%d", i)))
			if rec.Code != http.StatusCreated {
				t.Fatalf("subject %d = %d %s", i, rec.Code, rec.Body.String())
			}
		}
		// Every further subject has nowhere to be recorded, and no bucket has
		// refilled to full, so each is refused rather than admitted unmetered.
		for i := 2; i < 200; i++ {
			rec := f.create(t, token, decideBodyFor(fmt.Sprintf("acct-%d", i)))
			if _, isDeny := denied(t, rec); !isDeny {
				t.Fatalf("subject %d with the table full = %d %s, want a refusal", i, rec.Code, rec.Body.String())
			}
		}

		// Once the buckets have refilled the sweep frees them, and an invented
		// subject is charged again rather than being refused forever.
		f.clock.Advance(2 * time.Second)
		if rec := f.create(t, token, decideBodyFor("acct-200")); rec.Code != http.StatusCreated {
			t.Errorf("a new subject after the buckets refilled = %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("the caller table", func(t *testing.T) {
		f := newDecideFixture(t, decideOptions{rate: huge, subjectRate: huge, maxRateEntries: 2})

		// One subject throughout, so the subject table holds a single entry and
		// the table that fills is the callers'.
		for _, caller := range []string{"svc-1", "svc-2"} {
			rec := f.create(t, f.workload(t, caller), decideBodyFor("acct-shared"))
			if rec.Code != http.StatusCreated {
				t.Fatalf("%s = %d %s", caller, rec.Code, rec.Body.String())
			}
		}

		rec := f.create(t, f.workload(t, "svc-3"), decideBodyFor("acct-shared"))
		if _, isDeny := denied(t, rec); !isDeny {
			t.Fatalf("a third caller with the caller table full = %d %s, want a refusal",
				rec.Code, rec.Body.String())
		}
		events := f.audit.snapshot()
		if len(events) != 1 || events[0].Scope != "caller" {
			t.Errorf("the refusal was attributed to the wrong budget: %+v", events)
		}

		f.clock.Advance(2 * time.Second)
		if rec := f.create(t, f.workload(t, "svc-4"), decideBodyFor("acct-shared")); rec.Code != http.StatusCreated {
			t.Errorf("a new caller after the buckets refilled = %d %s", rec.Code, rec.Body.String())
		}
	})
}

// TestDecideSubjectPressureDoesNotCrowdOutCallers is #47(b).
//
// The two budgets used to share one bounded table, keyed apart by a prefix. The
// prefix kept the *keys* from colliding, which is not the same guarantee as
// keeping the *budgets* apart: one table has one entry cap, and the entries a
// flood of invented subjects puts in it are entries a caller's bucket cannot
// have. A caller that had spent none of its own budget was then refused for a
// table it had not filled — the limit answering for traffic it was not
// measuring, which is the thing the prefix was there to prevent.
//
// So the assertion is about a caller that has done nothing: it arrives while
// subject pressure holds the table at its cap and it is still admitted.
func TestDecideSubjectPressureDoesNotCrowdOutCallers(t *testing.T) {
	f := newDecideFixture(t, decideOptions{
		// Both budgets are enormous, so nothing here is a rate refusal: the only
		// thing under test is which table the pressure lands in.
		rate:           generous,
		subjectRate:    generous,
		maxRateEntries: 4,
	})

	busy := f.workload(t, "svc-busy")
	for i := range 3 {
		if rec := f.create(t, busy, decideBodyFor(fmt.Sprintf("acct-%d", i))); rec.Code != http.StatusCreated {
			t.Fatalf("subject %d for the busy caller = %d %s", i, rec.Code, rec.Body.String())
		}
	}

	// Three subjects now hold the subject table at its cap, and no bucket has
	// refilled, so a sweep would free nothing. A second caller has spent no part
	// of its own budget and asks about a subject that is already tracked.
	rec := f.create(t, f.workload(t, "svc-fresh"), decideBodyFor("acct-0"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("a caller that had spent nothing = %d %s, want the request admitted: "+
			"subject pressure is being paid for out of the caller budget's table",
			rec.Code, rec.Body.String())
	}
	if events := f.audit.snapshot(); len(events) != 0 {
		t.Errorf("subject pressure produced %d refusal(s) on another budget: %+v", len(events), events)
	}
}

// TestDecideCallerAndSubjectKeysCannotCollide: an identifier that names a caller
// and an identifier that names a subject are unrelated strings from unrelated
// namespaces, and both are attacker-influenced. One bucket answering for both
// would be a budget spendable by someone it was not measuring.
//
// That guarantee used to live in a `\x1f` prefix on the key. It now lives in the
// structure — two tables — and this test is what keeps it from being deleted
// along with the prefix.
func TestDecideCallerAndSubjectKeysCannotCollide(t *testing.T) {
	f := newDecideFixture(t, decideOptions{
		// Two requests' worth of caller budget, and no subject limit worth
		// hitting: if a subject charge landed in the caller's bucket, the second
		// request would spend the budget twice and be refused.
		rate:        stream.RateLimit{PerSecond: 1000, Burst: 2},
		subjectRate: generous,
	})
	token := f.workload(t, "svc-collide")

	if rec := f.create(t, token, decideBodyFor("acct-ordinary")); rec.Code != http.StatusCreated {
		t.Fatalf("the first request = %d %s", rec.Code, rec.Body.String())
	}
	// The caller identifier as the surface itself renders it, used as a subject
	// identifier — the collision an attacker who knows the format would try.
	callerID := f.lastCaller(t).CallerID()

	if rec := f.create(t, token, decideBodyFor(callerID)); rec.Code != http.StatusCreated {
		t.Fatalf("a subject named %q = %d %s, want the request admitted: the subject charge "+
			"landed in the caller's bucket", callerID, rec.Code, rec.Body.String())
	}
}

// TestDecideRateDefaultsAndTheWayToTurnItOff: an unconfigured deployment is
// limited, because the deployment that configured nothing is the one most likely
// to have needed the limit. An operator who means "no limit" says so.
func TestDecideRateDefaultsAndTheWayToTurnItOff(t *testing.T) {
	t.Run("unset takes the default", func(t *testing.T) {
		f := newDecideFixture(t, decideOptions{})
		token := f.workload(t, "svc-default")
		burst := int(api.DefaultDecideSubjectRate.Burst)
		for i := range burst {
			if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
				t.Fatalf("request %d within the default burst = %d", i, rec.Code)
			}
		}
		if _, isDeny := denied(t, f.create(t, token, decideBody(""))); !isDeny {
			t.Errorf("an unconfigured deployment admitted more than %v", api.DefaultDecideSubjectRate)
		}
	})

	t.Run("a negative rate removes the limit", func(t *testing.T) {
		f := newDecideFixture(t, decideOptions{
			rate:        stream.RateLimit{PerSecond: -1},
			subjectRate: stream.RateLimit{PerSecond: -1},
		})
		token := f.workload(t, "svc-unlimited")
		for i := range 400 {
			if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
				t.Fatalf("request %d with the limit removed = %d %s", i, rec.Code, rec.Body.String())
			}
		}
		if events := f.audit.snapshot(); len(events) != 0 {
			t.Errorf("a deployment with no limit recorded %d refusals", len(events))
		}
	})

	t.Run("a zero field takes only that field's default", func(t *testing.T) {
		// The burst is the operator's, the rate is the default's: raising one
		// knob must not silently restate the other.
		f := newDecideFixture(t, decideOptions{
			rate:        generous,
			subjectRate: stream.RateLimit{Burst: 3},
		})
		token := f.workload(t, "svc-partial")
		for i := range 3 {
			if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
				t.Fatalf("request %d = %d", i, rec.Code)
			}
		}
		if _, isDeny := denied(t, f.create(t, token, decideBody(""))); !isDeny {
			t.Error("the configured burst was not the one applied")
		}
		events := f.audit.snapshot()
		if len(events) != 1 || events[0].Limit != "5/s burst 3" {
			t.Errorf("the applied limit = %+v, want the default rate with the configured burst", events)
		}
	})
}

// ---------------------------------------------------------------------------
// the transport-level signal (#45)
// ---------------------------------------------------------------------------

// TestARateLimitedDecideCarriesRetryAfter is #45's first half.
//
// The refusal is a denied decision object with HTTP 200 and stays one — a PEP
// that had to branch on the transport to learn its request was judged would have
// two answers to keep in step. But the *body* is only legible to something that
// speaks this API, and a rate limit is the one deny in the vocabulary whose
// answer to "should I come back" is yes. Everything between the PEP and here — a
// retry middleware, a gateway, a dashboard — reads headers and status codes, and
// with neither of those saying anything it cannot tell a shed request from a
// judged one.
//
// The value is the refill interval, so a caller that honours it arrives when
// there is a token waiting rather than into the same refusal.
func TestARateLimitedDecideCarriesRetryAfter(t *testing.T) {
	// One token every two seconds: a refill interval that is a whole number of
	// seconds, so the header can be compared with the budget rather than with
	// whatever rounding produced it.
	limit := stream.RateLimit{PerSecond: 0.5, Burst: 1}
	f := newDecideFixture(t, decideOptions{rate: generous, subjectRate: limit})
	token := f.workload(t, "svc-shed")

	if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
		t.Fatalf("the first request = %d: %s", rec.Code, rec.Body.String())
	}
	rec := f.create(t, token, decideBody(""))
	if _, isDeny := denied(t, rec); !isDeny {
		t.Fatalf("the second request = %d %s, want a denied decision", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want %q — the interval this budget refills in", got, "2")
	}

	// The header is not decoration: coming back earlier than it says is refused,
	// and coming back when it says is admitted. A number that promised a token
	// which is not there would send a well-behaved client into a retry loop.
	f.clock.Advance(time.Second)
	if _, isDeny := denied(t, f.create(t, token, decideBody(""))); !isDeny {
		t.Error("a retry before Retry-After was admitted; the header over-promises")
	}
	f.clock.Advance(time.Second)
	if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
		t.Errorf("a retry at Retry-After = %d %s, want the budget to have refilled",
			rec.Code, rec.Body.String())
	}
}

// TestTheCallerBudgetRefusalCarriesItsOwnInterval: the two budgets refill at
// different rates, and the header names the one that actually ran out. A caller
// told to wait the subject budget's interval when it was its own that was spent
// has been told a number about somebody else.
func TestTheCallerBudgetRefusalCarriesItsOwnInterval(t *testing.T) {
	f := newDecideFixture(t, decideOptions{
		rate:        stream.RateLimit{PerSecond: 0.25, Burst: 1},
		subjectRate: generous,
	})
	token := f.workload(t, "svc-noisy")

	if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
		t.Fatalf("the first request = %d", rec.Code)
	}
	rec := f.create(t, token, decideBody(""))
	if _, isDeny := denied(t, rec); !isDeny {
		t.Fatalf("the second request = %d, want a denied decision", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "4" {
		t.Errorf("Retry-After = %q, want %q — the caller budget's interval, not the subject's", got, "4")
	}
}

// TestRetryAfterIsClampedForAVerySlowBudget: the clamp is reachable from an
// ordinary refusal, so it is tested from one.
//
// A budget of one request every three hours is a configuration an operator can
// write, and 1/PerSecond for it is a number no client will honour. Clamping
// under-promises — a caller comes back too early and is refused again, which is
// the state it was already in — and over-promising is the failure that matters,
// because a caller told to wait longer than the budget needs has been made
// slower than the limit asks for, by the limit.
func TestRetryAfterIsClampedForAVerySlowBudget(t *testing.T) {
	// One token every 10,000 seconds: an interval well past the hour the clamp
	// allows.
	f := newDecideFixture(t, decideOptions{
		rate:        generous,
		subjectRate: stream.RateLimit{PerSecond: 0.0001, Burst: 1},
	})
	token := f.workload(t, "svc-glacial")

	if rec := f.create(t, token, decideBody("")); rec.Code != http.StatusCreated {
		t.Fatalf("the first request = %d %s", rec.Code, rec.Body.String())
	}
	rec := f.create(t, token, decideBody(""))
	if _, isDeny := denied(t, rec); !isDeny {
		t.Fatalf("the second request = %d %s, want a denied decision", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "3600" {
		t.Errorf("Retry-After = %q, want %q — the clamp, not the budget's 10000s interval", got, "3600")
	}

	// The clamp under-promises on purpose: at the hour it names the budget still
	// has no token, and the caller is refused again rather than admitted.
	f.clock.Advance(time.Hour)
	if _, isDeny := denied(t, f.create(t, token, decideBody(""))); !isDeny {
		t.Error("the clamped header was treated as a promise the budget had not made")
	}
}

// TestAPolicyDenyCarriesNoRetryAfter is the other side of the same claim. A
// policy deny is a judgement, and a judgement does not expire on a timer; a
// caller that retried it would get the same answer forever. The header is what
// separates the retryable deny from the final one at the transport level, so
// putting it on both would be worse than putting it on neither.
func TestAPolicyDenyCarriesNoRetryAfter(t *testing.T) {
	f := newDecideFixture(t, decideOptions{})
	f.life.result = decision.Result{
		State:       store.DecisionDenied,
		Outcome:     engine.Deny,
		Reason:      engine.ReasonNoMatchingPolicy,
		Obligations: []decision.Obligation{},
	}

	rec := f.create(t, f.workload(t, "svc-payments"), decideBody(""))
	reason, isDeny := denied(t, rec)
	if !isDeny {
		t.Fatalf("a policy deny = %d %s, want a denied decision", rec.Code, rec.Body.String())
	}
	if reason != string(engine.ReasonNoMatchingPolicy) {
		t.Fatalf("reason = %q, want the policy's ground", reason)
	}
	if got := rec.Header().Get("Retry-After"); got != "" {
		t.Errorf("a policy deny carries Retry-After %q; retrying it is not a thing to invite", got)
	}
}

// ---------------------------------------------------------------------------
// the two budgets under concurrent load
// ---------------------------------------------------------------------------
//
// Every test above drives the surface one request at a time, which is not how
// the surface is used and is the gap the previous round's mutation audit wrote
// down: the two limiter tables had no dedicated concurrency test and `-race`
// had only brushed them incidentally.
//
// What a sequential test cannot see is a budget that leaks under contention.
// The refusal a PEP gets is identical either way — one deny looks like another
// — so the only observable difference is the *count*: with a burst of B and N
// requests in flight, exactly B are admitted. B+1 is a limit that reports more
// than it does, and R43's bound then holds in the response body and nowhere
// else. The limiter's own arithmetic is pinned in internal/stream; this is the
// same claim made through the assembled surface, where the caller table and the
// subject table are charged on the way through one request and a test can be
// sure it is the real pairing rather than two limiters a test wired up.

// decideStorm fires n concurrent creates through the decide surface, released
// together, and reports how many were created, how many were refused as denied
// decisions, and the highest number of requests that were inside the handler at
// once.
//
// Every token is minted before the barrier. Minting inside a goroutine would
// put a t.Fatalf on the wrong stack, and it would also mean the requests were
// not really simultaneous — they would be staggered by RSA signing.
func decideStorm(t *testing.T, f *decideFixture, n int, request func(i int) (token, body string),
) (created, refused, peak int) {
	t.Helper()
	tokens := make([]string, n)
	bodies := make([]string, n)
	for i := range n {
		tokens[i], bodies[i] = request(i)
	}

	var (
		arrived sync.WaitGroup
		done    sync.WaitGroup
		release = make(chan struct{})

		ok      atomic.Int64
		denies  atomic.Int64
		inside  atomic.Int64
		highest atomic.Int64
	)
	arrived.Add(n)
	done.Add(n)
	for i := range n {
		go func() {
			defer done.Done()
			arrived.Done()
			<-release

			depth := inside.Add(1)
			for {
				high := highest.Load()
				if depth <= high || highest.CompareAndSwap(high, depth) {
					break
				}
			}
			rec := f.do(api.SurfacePEP, http.MethodPost, api.DecisionsPath, tokens[i], bodies[i])
			inside.Add(-1)

			switch {
			case rec.Code == http.StatusCreated:
				ok.Add(1)
			case rec.Code == http.StatusOK && strings.Contains(rec.Body.String(),
				`"`+string(decision.ReasonRateLimited)+`"`):
				denies.Add(1)
			default:
				// Neither a creation nor a rate refusal: counted in neither, so
				// the arithmetic below fails loudly rather than balancing.
				t.Errorf("request %d = %d %s, want either a creation or a rate-limit deny",
					i, rec.Code, rec.Body.String())
			}
		}()
	}
	arrived.Wait()
	close(release)
	done.Wait()

	t.Logf("%d concurrent decides, %d of them inside the surface at once", n, int(highest.Load()))
	if runtime.GOMAXPROCS(0) >= 2 && highest.Load() < 2 {
		// A concurrency test that ran sequentially asserts nothing about
		// concurrency, and would keep passing against a limiter with no lock at
		// all. Skipped on a single-P runtime, where the scheduler cannot produce
		// simultaneity and the check would be a lie rather than a control.
		t.Errorf("no two of the %d requests were ever inside the surface at the same time", n)
	}
	return int(ok.Load()), int(denies.Load()), int(highest.Load())
}

// TestDecideBudgetsAreExactUnderConcurrentLoad is the mutation audit's gap
// closed where R43 is enforced.
//
// Both tables are charged in both halves — one caller against many subjects,
// then many callers against one subject — so the budget that binds is filling
// its table at the same instant the other one is filling its own. The clock
// does not move for the length of the storm, so a refill cannot explain an
// admission: every request over the burst that got through would be a token
// spent twice.
func TestDecideBudgetsAreExactUnderConcurrentLoad(t *testing.T) {
	const (
		burst    = 8
		inFlight = 128
	)

	t.Run("the caller budget", func(t *testing.T) {
		f := newDecideFixture(t, decideOptions{
			rate:        stream.RateLimit{PerSecond: 1000, Burst: burst},
			subjectRate: generous,
		})
		// One caller, and a distinct subject per request: the subject table is
		// being filled by every goroutine while the caller's bucket is the one
		// being spent.
		token := f.workload(t, "svc-flood")
		created, refused, _ := decideStorm(t, f, inFlight, func(i int) (string, string) {
			return token, decideBodyFor(fmt.Sprintf("acct-%d", i))
		})

		if created != burst {
			t.Errorf("%d of %d concurrent requests were created against a caller burst of %d, "+
				"want exactly %d. more is a budget that leaks under contention — the surface "+
				"answers that it limited and the work it was shedding went through; fewer is a "+
				"limiter charging requests it refused", created, inFlight, burst, burst)
		}
		if created+refused != inFlight {
			t.Errorf("%d created + %d refused != %d requests: something answered neither way",
				created, refused, inFlight)
		}
		// R43 asks the refusal to be audited, and a storm is where a dropped
		// audit record would hide. Every refusal has one, attributed to the
		// budget that actually ran out.
		events := f.audit.snapshot()
		if len(events) != refused {
			t.Errorf("%d refusals produced %d audit records, want one each", refused, len(events))
		}
		for _, e := range events {
			if e.Scope != "caller" {
				t.Errorf("a refusal was attributed to the %q budget, want the caller's: %+v", e.Scope, e)
				break
			}
		}
	})

	t.Run("the subject budget", func(t *testing.T) {
		f := newDecideFixture(t, decideOptions{
			rate:        generous,
			subjectRate: stream.RateLimit{PerSecond: 1000, Burst: burst},
		})
		// The mirror image: one subject, a distinct caller per request. This is
		// also the concurrent form of the property that one subject's budget is
		// one budget however many callers spend it.
		created, refused, _ := decideStorm(t, f, inFlight, func(i int) (string, string) {
			return f.workload(t, fmt.Sprintf("svc-%d", i)), decideBodyFor("acct-shared")
		})

		if created != burst {
			t.Errorf("%d of %d concurrent requests were created against a subject burst of %d, "+
				"want exactly %d: the budget that the outstanding cap depends on for its cushion "+
				"has to hold when the requests arrive together, which is the only way they arrive",
				created, inFlight, burst, burst)
		}
		if created+refused != inFlight {
			t.Errorf("%d created + %d refused != %d requests", created, refused, inFlight)
		}
		events := f.audit.snapshot()
		if len(events) != refused {
			t.Errorf("%d refusals produced %d audit records, want one each", refused, len(events))
		}
		for _, e := range events {
			if e.Scope != "subject" {
				t.Errorf("a refusal was attributed to the %q budget, want the subject's: %+v", e.Scope, e)
				break
			}
		}
	})
}
