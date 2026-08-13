package runtime

// perinstance_test.go measures the claim docs/operations/failure-modes.md makes
// and had never checked: the decide budget is per instance, so N replicas admit
// N times the configured rate.
//
// The claim has been written down since the rate limits landed, and an operator
// is told to "size a fleet by dividing". Nothing verified it. It is the kind of
// statement that is easy to believe and easy to have wrong in either direction —
// a shared table in the database would make it false, and so would a budget
// keyed on something fleet-wide.
//
// This round does not fix it. Making one budget hold across replicas is a
// distributed-counter decision with its own failure modes, and the absolute
// fleet-wide bound that does exist — the outstanding-decision cap, counted in
// the database — is the control that actually limits what one subject can
// accumulate. What was missing was the measurement, so that the number in the
// document is one somebody observed.

import (
	"net/http"
	"testing"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/stream"
)

// TestTheDecideBudgetIsPerInstanceAndNotFleetWide stands two instances on one
// database and spends the same caller's budget against each.
//
// Both instances get the same configured burst. If the budget were fleet-wide,
// the second instance would refuse from its first request, because the first
// instance already spent it. What is observed instead is the number the document
// claims: each instance admits a full burst, so the fleet admits N times one.
func TestTheDecideBudgetIsPerInstanceAndNotFleetWide(t *testing.T) {
	// Refills once every thousand seconds, so what this measures is the burst
	// and never a refill that happened to land mid-loop.
	const burst = 3
	dsn := freshDB(t)
	perInstance := func(c *Config) {
		c.DecideRate = stream.RateLimit{PerSecond: 0.001, Burst: burst}
	}

	// Distinct writer identifiers are not incidental. Two processes claiming
	// one audit-writer identity is a boot failure by design (ErrWriterTaken),
	// because two writers on one chain fork it — so a real two-replica
	// deployment gives each its own, and so does this.
	first := newHarness(t, harnessOptions{dsn: dsn, writerID: "per-instance-a", mutate: perInstance})
	// The second instance trusts the first's IdP. Without that each harness
	// mints tokens only it accepts, and two callers that merely share a subject
	// name are not the same caller — which is the thing being measured.
	second := newHarness(t, harnessOptions{dsn: dsn, writerID: "per-instance-b", mutate: func(c *Config) {
		perInstance(c)
		c.InstanceID = "e2e-b"
		c.OIDC.Issuers = []IssuerConfig{{
			Issuer:          first.idp.server.URL,
			JWKSURL:         first.idp.server.URL + "/jwks",
			WorkloadClients: []string{testWorkload},
		}}
	}})

	first.seed(tenantSchema(), whitelistPolicy("per-instance-allow"))

	// The decide surface, not the check surface. R43 scopes the budget to the
	// operations that create state — decide creation, challenge issuance,
	// approval submission, and the rest — and a stateless evaluation is
	// deliberately not among them. Driving the check surface here would have
	// measured an absence and called it a budget; the first attempt at this
	// test did exactly that and admitted every request.
	token := first.idp.workload(t, "svc-payments")

	// A refused decide is a 200 carrying a denied decision whose reason is
	// rate_limited, not a 4xx. That is this project's deliberate shape — an
	// authorization engine answers "denied", it does not error — and it is why
	// the count below reads the reason rather than the status. Counting statuses
	// was the first attempt here and it scored every refusal as an admission.
	admittedBy := func(h *harness) int {
		t.Helper()
		admitted := 0
		for range burst + 2 {
			code, body := h.do(http.MethodPost, api.SurfacePEP, api.DecisionsPath, token,
				decideRequest("acct-src", "close", 5000, "45m"), nil)
			if code != http.StatusOK && code != http.StatusCreated {
				t.Fatalf("POST %s = %d: %s", api.DecisionsPath, code, body)
			}
			var answer struct {
				Reason string `json:"reason"`
			}
			h.decode(body, &answer)
			if answer.Reason != "rate_limited" {
				admitted++
			}
		}
		return admitted
	}

	firstAdmitted := admittedBy(first)
	if firstAdmitted != burst {
		t.Fatalf("the first instance admitted %d of %d, want exactly the burst (%d): "+
			"the budget is not being applied as configured, so nothing below measures what it claims to",
			firstAdmitted, burst+2, burst)
	}

	secondAdmitted := admittedBy(second)
	if secondAdmitted == 0 {
		t.Fatalf("the second instance admitted nothing after the first spent its budget: the budget is " +
			"fleet-wide after all, and docs/operations/failure-modes.md is wrong to tell operators to " +
			"size a fleet by dividing")
	}
	if secondAdmitted != burst {
		t.Errorf("the second instance admitted %d, want %d: the two instances neither share one budget "+
			"nor each hold a full one, so the fleet-wide rate is some third number nobody has written down",
			secondAdmitted, burst)
	}

	// The measured number, stated as the document states it.
	total := firstAdmitted + secondAdmitted
	if total != 2*burst {
		t.Errorf("two instances admitted %d against a configured burst of %d, want %d (N x burst)",
			total, burst, 2*burst)
	}
	t.Logf("measured: %d instances x burst %d = %d admitted; the fleet-wide rate is N times the configured one",
		2, burst, total)
}
