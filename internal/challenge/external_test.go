package challenge_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/stream"
)

// The external tests are about a trust boundary and a fail-closed default.
//
// The boundary is D21's: a policy author names an operator allowlist entry, not
// a URL, and the URL the operator configured is checked by U6's gate at load
// and again at call time. The tests that matter most here are the ones that
// name a metadata address by every route a policy or a DNS zone could take, and
// find it refused each time.
//
// The default is that a round trip which did not happen leaves the challenge
// failed rather than pending. An unreachable target, a timeout, a redirect, a
// non-2xx answer and a callback that never arrives all come out the same way,
// and none of them can produce an allow.

const testExternalSecret = "an-operator-configured-shared-secret"

func externalContext() challenge.DecisionContext {
	return challenge.DecisionContext{
		DecisionID:   "3f1b0f2a-0000-4000-8000-0000000000e1",
		CallerID:     "workload:https://idp.test#payments",
		SubjectID:    "alice",
		ResourceID:   "acct-1",
		Action:       "transfer",
		PolicyID:     "high-value-transfer",
		Request:      json.RawMessage(`{"action":"transfer"}`),
		FactSnapshot: json.RawMessage(`{}`),
		Obligations:  json.RawMessage(`[]`),
		CreatedAt:    testNow,
		ExpiresAt:    testNow.Add(time.Hour),
	}
}

func externalInstance() challenge.Instance {
	return challenge.Instance{DecisionID: externalContext().DecisionID, Ordinal: 0, Kind: policy.ChallengeExternal}
}

// notifiedTarget is a webhook receiver that records what STAMP sent it.
type notifiedTarget struct {
	server *httptest.Server

	mu       sync.Mutex
	bodies   [][]byte
	headers  []http.Header
	status   int
	delay    time.Duration
	location string
}

func newNotifiedTarget(t *testing.T) *notifiedTarget {
	t.Helper()
	tgt := &notifiedTarget{status: http.StatusAccepted}
	tgt.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0, 1024)
		buf := make([]byte, 1024)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}
		tgt.mu.Lock()
		tgt.bodies = append(tgt.bodies, body)
		tgt.headers = append(tgt.headers, r.Header.Clone())
		status, delay, location := tgt.status, tgt.delay, tgt.location
		tgt.mu.Unlock()

		if delay > 0 {
			time.Sleep(delay)
		}
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(tgt.server.Close)
	return tgt
}

func (t *notifiedTarget) set(status int, delay time.Duration, location string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status, t.delay, t.location = status, delay, location
}

func (t *notifiedTarget) received() ([][]byte, []http.Header) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([][]byte(nil), t.bodies...), append([]http.Header(nil), t.headers...)
}

// loopbackGate admits exactly the origins named, on loopback. It is the same
// shape a deployment uses for a fact endpoint it fronts itself.
func loopbackGate(t *testing.T, origins ...string) *fact.Gate {
	t.Helper()
	g, err := fact.NewGate(fact.EgressConfig{Allow: origins, AllowLoopback: true})
	if err != nil {
		t.Fatalf("new gate: %v", err)
	}
	return g
}

func originOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Scheme + "://" + u.Host
}

func issueExternal(t *testing.T, h *challenge.External, target string) (challenge.IssueResult, json.RawMessage, error) {
	t.Helper()
	issued, err := h.Issue(context.Background(), challenge.IssueRequest{
		Instance: externalInstance(),
		Spec:     policy.External{Target: target},
		Decision: externalContext(),
		Now:      testNow,
	})
	if err != nil {
		return issued, nil, err
	}
	raw, merr := json.Marshal(issued.Detail)
	if merr != nil {
		t.Fatalf("encode external detail: %v", merr)
	}
	return issued, raw, nil
}

// ---------------------------------------------------------------------------
// the trust boundary
// ---------------------------------------------------------------------------

// TestExternalRefusesOperatorTargetsTheGateWouldNotDial is the load-bearing
// SSRF test at load time. Every one of these destinations is named by an
// operator, which is the *most* privileged way a destination can be named here,
// and each is still refused before the process finishes starting.
func TestExternalRefusesOperatorTargetsTheGateWouldNotDial(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		url     string
		private bool
	}{
		"the IMDS link-local address":   {url: "http://169.254.169.254/latest/meta-data/"},
		"link-local even when private":  {url: "http://169.254.169.254/latest/meta-data/", private: true},
		"the IPv6 link-local range":     {url: "http://[fe80::1]/"},
		"an IPv4-mapped metadata IPv6":  {url: "http://[::ffff:169.254.169.254]/"},
		"an RFC 1918 address":           {url: "http://10.0.0.5:8080/hook"},
		"a unique-local IPv6 address":   {url: "http://[fd00::1]/hook"},
		"an origin nobody allowlisted":  {url: "https://attacker.example/hook"},
		"a destination carrying a user": {url: "http://user:pass@allowed.test/hook"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gate, err := fact.NewGate(fact.EgressConfig{
				// The allowlist is deliberately generous: the origin of every
				// destination under test is on it, so what refuses them is the
				// range rule and not a missing entry.
				Allow: []string{
					"http://169.254.169.254:80", "http://[fe80::1]:80",
					"http://10.0.0.5:8080", "http://[fd00::1]:80",
					"http://allowed.test:80",
				},
				AllowLoopback: true,
				AllowPrivate:  tc.private,
			})
			if err != nil {
				t.Fatalf("new gate: %v", err)
			}
			_, err = challenge.NewExternal(challenge.ExternalConfig{
				Gate:    gate,
				Targets: []challenge.ExternalTarget{{Name: "hook", URL: tc.url, Secret: testExternalSecret}},
			})
			if err == nil {
				t.Fatalf("NewExternal accepted %s", tc.url)
			}
			if !errors.Is(err, fact.ErrBlocked) {
				t.Fatalf("err = %v, want it to wrap fact.ErrBlocked", err)
			}
		})
	}
}

// TestExternalIsIssuedAgainstANameAndNotAURL states D21 from the policy side: a
// policy author selects from what the operator configured, and a document that
// tries to name a destination directly gets a refusal rather than a request.
func TestExternalIsIssuedAgainstANameAndNotAURL(t *testing.T) {
	t.Parallel()
	tgt := newNotifiedTarget(t)
	h, err := challenge.NewExternal(challenge.ExternalConfig{
		Gate:    loopbackGate(t, originOf(t, tgt.server.URL)),
		Targets: []challenge.ExternalTarget{{Name: "risk-engine", URL: tgt.server.URL, Secret: testExternalSecret}},
	})
	if err != nil {
		t.Fatalf("new external handler: %v", err)
	}

	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://localhost:1/",
		"unconfigured",
		"",
	} {
		_, _, err := issueExternal(t, h, target)
		if !errors.Is(err, challenge.ErrUnsupportedSpec) {
			t.Fatalf("issue against %q: err = %v, want ErrUnsupportedSpec", target, err)
		}
	}
	if bodies, _ := tgt.received(); len(bodies) != 0 {
		t.Fatalf("a refused target still produced %d outbound call(s)", len(bodies))
	}
}

// TestExternalBlocksAHostnameThatResolvesToLinkLocal closes the hole a
// load-time URL check leaves open: the operator's allowlisted hostname is fine
// on paper and the zone answers with the metadata address. The refusal happens
// in the gate's dialler, and the challenge fails closed rather than the call
// succeeding against an address nobody allowed.
func TestExternalBlocksAHostnameThatResolvesToLinkLocal(t *testing.T) {
	t.Parallel()

	for name, addr := range map[string]string{
		"link-local": "169.254.169.254",
		"private":    "10.1.2.3",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gate, err := fact.NewGate(fact.EgressConfig{
				Allow: []string{"http://risk.example:80"},
				Resolve: func(_ context.Context, _ string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr(addr)}, nil
				},
			})
			if err != nil {
				t.Fatalf("new gate: %v", err)
			}
			h, err := challenge.NewExternal(challenge.ExternalConfig{
				Gate: gate,
				Targets: []challenge.ExternalTarget{{
					Name: "risk-engine", URL: "http://risk.example/hook", Secret: testExternalSecret,
				}},
			})
			if err != nil {
				t.Fatalf("new external handler: %v", err)
			}

			issued, raw, err := issueExternal(t, h, "risk-engine")
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			if issued.State != challenge.StateFailed {
				t.Fatalf("issued state = %q, want failed: a blocked destination must not leave a challenge open",
					issued.State)
			}
			if issued.Deadline != nil {
				t.Fatalf("a failed round trip set a timer: %s", issued.Deadline)
			}

			var detail challenge.ExternalDetail
			if err := json.Unmarshal(raw, &detail); err != nil {
				t.Fatalf("decode detail: %v", err)
			}
			if detail.Failure != challenge.ExternalFailureEgressBlocked {
				t.Fatalf("failure = %q, want %q", detail.Failure, challenge.ExternalFailureEgressBlocked)
			}
			if detail.Acknowledged {
				t.Fatal("a blocked call was recorded as acknowledged")
			}

			// The lifecycle drops Issue's state and asks Status, so the refusal
			// has to survive in the detail or the challenge silently reopens.
			got, err := h.Status(context.Background(), challenge.StatusRequest{
				Instance: externalInstance(),
				Decision: externalContext(),
				Detail:   raw,
				Stored:   challenge.StatePending,
				Now:      testNow.Add(time.Second),
			})
			if err != nil {
				t.Fatalf("status: %v", err)
			}
			if got.State != challenge.StateFailed {
				t.Fatalf("status after a blocked call = %q, want failed", got.State)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the round trip
// ---------------------------------------------------------------------------

func TestExternalNotifiesTheTargetAndWaitsForTheCallback(t *testing.T) {
	t.Parallel()
	tgt := newNotifiedTarget(t)
	h, err := challenge.NewExternal(challenge.ExternalConfig{
		Gate:            loopbackGate(t, originOf(t, tgt.server.URL)),
		CallbackBaseURL: "https://stamp.example/callbacks",
		Targets: []challenge.ExternalTarget{{
			Name: "risk-engine", URL: tgt.server.URL, Secret: testExternalSecret,
			RespondWithin: 15 * time.Minute,
		}},
	})
	if err != nil {
		t.Fatalf("new external handler: %v", err)
	}

	issued, raw, err := issueExternal(t, h, "risk-engine")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.State != challenge.StatePending {
		t.Fatalf("issued state = %q, want pending", issued.State)
	}
	if issued.Deadline == nil || !issued.Deadline.Equal(testNow.Add(15*time.Minute)) {
		t.Fatalf("deadline = %v, want %s", issued.Deadline, testNow.Add(15*time.Minute))
	}

	var detail challenge.ExternalDetail
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if !detail.Acknowledged || detail.Failure != "" {
		t.Fatalf("detail = %+v, want an acknowledged round trip", detail)
	}
	if len(detail.Nonce) < 32 {
		t.Fatalf("nonce %q is too short to be a correlator", detail.Nonce)
	}

	bodies, headers := tgt.received()
	if len(bodies) != 1 {
		t.Fatalf("target received %d calls, want 1", len(bodies))
	}
	var sent challenge.ExternalNotification
	if err := json.Unmarshal(bodies[0], &sent); err != nil {
		t.Fatalf("decode notification: %v", err)
	}
	if sent.DecisionID != externalContext().DecisionID || sent.Ordinal != 0 {
		t.Fatalf("notification named %s#%d", sent.DecisionID, sent.Ordinal)
	}
	if sent.Nonce != detail.Nonce {
		t.Fatalf("the nonce sent (%q) is not the nonce frozen (%q)", sent.Nonce, detail.Nonce)
	}
	if sent.CallbackURL == "" || !strings.HasPrefix(sent.CallbackURL, "https://stamp.example/callbacks") {
		t.Fatalf("callback_url = %q", sent.CallbackURL)
	}

	// The signature is the target's only proof the call came from STAMP, and
	// it is recomputed here the way the target would.
	sig := headers[0].Get(challenge.ExternalSignatureHeader)
	want := "v1=" + challenge.ExternalNotificationSignature(testExternalSecret, bodies[0])
	if sig != want {
		t.Fatalf("signature header = %q, want %q", sig, want)
	}
	if got := headers[0].Get("Authorization"); got != "" {
		t.Fatalf("the outbound call carried an Authorization header: %q", got)
	}
	if got := headers[0].Get("Cookie"); got != "" {
		t.Fatalf("the outbound call carried a cookie: %q", got)
	}
}

func TestExternalCallbackCarriesTheVerdictThroughToTheChallengeState(t *testing.T) {
	t.Parallel()

	for verdict, want := range map[string]challenge.State{
		challenge.ExternalVerdictApproved: challenge.StateSatisfied,
		challenge.ExternalVerdictDenied:   challenge.StateFailed,
	} {
		t.Run(verdict, func(t *testing.T) {
			t.Parallel()
			tgt := newNotifiedTarget(t)
			h, err := challenge.NewExternal(challenge.ExternalConfig{
				Gate: loopbackGate(t, originOf(t, tgt.server.URL)),
				Targets: []challenge.ExternalTarget{{
					Name: "risk-engine", URL: tgt.server.URL, Secret: testExternalSecret,
				}},
			})
			if err != nil {
				t.Fatalf("new external handler: %v", err)
			}
			_, raw, err := issueExternal(t, h, "risk-engine")
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			var detail challenge.ExternalDetail
			if err := json.Unmarshal(raw, &detail); err != nil {
				t.Fatalf("decode detail: %v", err)
			}

			out, err := h.Submit(context.Background(), challenge.SubmitRequest{
				Instance: externalInstance(),
				Decision: externalContext(),
				Detail:   raw,
				Payload:  callbackBody(t, detail.Nonce, verdict, testExternalSecret, externalInstance()),
				Now:      testNow.Add(time.Minute),
			})
			if err != nil {
				t.Fatalf("callback: %v", err)
			}
			if out.State != want {
				t.Fatalf("verdict %q produced %q, want %q", verdict, out.State, want)
			}
			recorded, ok := out.Detail.(challenge.ExternalDetail)
			if !ok {
				t.Fatalf("callback returned detail of type %T", out.Detail)
			}
			if recorded.Verdict != verdict || recorded.RespondedAt == nil {
				t.Fatalf("recorded detail = %+v", recorded)
			}

			// The recorded verdict is what Status recomputes from, which is how
			// a crash between the two writes still lands on the same answer.
			raw2, err := json.Marshal(recorded)
			if err != nil {
				t.Fatalf("encode recorded detail: %v", err)
			}
			got, err := h.Status(context.Background(), challenge.StatusRequest{
				Instance: externalInstance(),
				Decision: externalContext(),
				Detail:   raw2,
				Stored:   challenge.StatePending,
				Now:      testNow.Add(2 * time.Minute),
			})
			if err != nil {
				t.Fatalf("status: %v", err)
			}
			if got.State != want {
				t.Fatalf("status recomputed %q, want %q", got.State, want)
			}
		})
	}
}

// TestExternalRefusesForgedAndReplayedCallbacks is the callback's whole
// authentication story: the caller holds no credential, so the correlator and
// the signature are what stand between an unauthenticated listener and an
// allow.
func TestExternalRefusesForgedAndReplayedCallbacks(t *testing.T) {
	t.Parallel()
	tgt := newNotifiedTarget(t)
	h, err := challenge.NewExternal(challenge.ExternalConfig{
		Gate: loopbackGate(t, originOf(t, tgt.server.URL)),
		Targets: []challenge.ExternalTarget{{
			Name: "risk-engine", URL: tgt.server.URL, Secret: testExternalSecret,
		}},
	})
	if err != nil {
		t.Fatalf("new external handler: %v", err)
	}
	_, raw, err := issueExternal(t, h, "risk-engine")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	var detail challenge.ExternalDetail
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}

	// A second issuance, so that "somebody else's nonce" is a real nonce from a
	// real challenge rather than a value a test made up.
	other, err := h.Issue(context.Background(), challenge.IssueRequest{
		Instance: challenge.Instance{DecisionID: externalContext().DecisionID, Ordinal: 1, Kind: policy.ChallengeExternal},
		Spec:     policy.External{Target: "risk-engine"},
		Decision: externalContext(),
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("issue second: %v", err)
	}
	otherDetail, ok := other.Detail.(challenge.ExternalDetail)
	if !ok {
		t.Fatalf("issue returned detail of type %T", other.Detail)
	}
	if otherDetail.Nonce == detail.Nonce {
		t.Fatal("two issuances shared a nonce: the correlator is not per-challenge")
	}

	good := challenge.ExternalCallbackSignature(
		testExternalSecret, externalInstance().DecisionID, 0, detail.Nonce, challenge.ExternalVerdictApproved)

	cases := map[string]json.RawMessage{
		"a forged signature": mustJSONBody(t, map[string]any{
			"nonce": detail.Nonce, "verdict": challenge.ExternalVerdictApproved,
			"signature": strings.Repeat("00", 32),
		}),
		"another challenge's nonce": callbackBody(t, otherDetail.Nonce, challenge.ExternalVerdictApproved,
			testExternalSecret, externalInstance()),
		"a signature from another challenge": mustJSONBody(t, map[string]any{
			"nonce": detail.Nonce, "verdict": challenge.ExternalVerdictApproved,
			"signature": challenge.ExternalCallbackSignature(
				testExternalSecret, externalInstance().DecisionID, 1, detail.Nonce, challenge.ExternalVerdictApproved),
		}),
		"a verdict flipped after signing": mustJSONBody(t, map[string]any{
			"nonce": detail.Nonce, "verdict": challenge.ExternalVerdictApproved,
			"signature": challenge.ExternalCallbackSignature(
				testExternalSecret, externalInstance().DecisionID, 0, detail.Nonce, challenge.ExternalVerdictDenied),
		}),
		"a signature under the wrong secret": mustJSONBody(t, map[string]any{
			"nonce": detail.Nonce, "verdict": challenge.ExternalVerdictApproved,
			"signature": challenge.ExternalCallbackSignature(
				"a-secret-the-operator-never-configured", externalInstance().DecisionID, 0,
				detail.Nonce, challenge.ExternalVerdictApproved),
		}),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := h.Submit(context.Background(), challenge.SubmitRequest{
				Instance: externalInstance(),
				Decision: externalContext(),
				Detail:   raw,
				Payload:  body,
				Now:      testNow.Add(time.Minute),
			})
			if !errors.Is(err, challenge.ErrNotTarget) {
				t.Fatalf("err = %v, want ErrNotTarget", err)
			}
		})
	}

	// The honest callback still works after every forgery above, so the
	// refusals are not a handler that refuses everything.
	out, err := h.Submit(context.Background(), challenge.SubmitRequest{
		Instance: externalInstance(),
		Decision: externalContext(),
		Detail:   raw,
		Payload: mustJSONBody(t, map[string]any{
			"nonce": detail.Nonce, "verdict": challenge.ExternalVerdictApproved, "signature": good,
		}),
		Now: testNow.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("honest callback: %v", err)
	}
	if out.State != challenge.StateSatisfied {
		t.Fatalf("honest callback produced %q", out.State)
	}
}

// TestExternalCallbackIsNotSatisfiedByACredential states that a console user
// with a perfectly good token is no closer to satisfying an external challenge
// than a stranger. The proof of a callback is the signature, and nothing else
// is accepted in its place.
func TestExternalCallbackIsNotSatisfiedByACredential(t *testing.T) {
	t.Parallel()
	idp := newMockIdP(t)
	tgt := newNotifiedTarget(t)
	h, err := challenge.NewExternal(challenge.ExternalConfig{
		Gate: loopbackGate(t, originOf(t, tgt.server.URL)),
		Targets: []challenge.ExternalTarget{{
			Name: "risk-engine", URL: tgt.server.URL, Secret: testExternalSecret,
		}},
	})
	if err != nil {
		t.Fatalf("new external handler: %v", err)
	}
	_, raw, err := issueExternal(t, h, "risk-engine")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	var detail challenge.ExternalDetail
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}

	// The body is well formed and even carries the right correlator, so what
	// is missing is only the signature. A credential does not stand in for it.
	_, err = h.Submit(context.Background(), challenge.SubmitRequest{
		Instance:  externalInstance(),
		Decision:  externalContext(),
		Detail:    raw,
		Submitter: idp.user(t, "mallory", nil),
		Payload: mustJSONBody(t, map[string]any{
			"nonce":     detail.Nonce,
			"verdict":   challenge.ExternalVerdictApproved,
			"signature": strings.Repeat("ab", 32),
		}),
		Now: testNow.Add(time.Minute),
	})
	if !errors.Is(err, challenge.ErrNotTarget) {
		t.Fatalf("err = %v, want ErrNotTarget", err)
	}
}

func TestExternalRefusesUnreadableCallbackBodies(t *testing.T) {
	t.Parallel()
	tgt := newNotifiedTarget(t)
	h, err := challenge.NewExternal(challenge.ExternalConfig{
		Gate: loopbackGate(t, originOf(t, tgt.server.URL)),
		Targets: []challenge.ExternalTarget{{
			Name: "risk-engine", URL: tgt.server.URL, Secret: testExternalSecret,
		}},
	})
	if err != nil {
		t.Fatalf("new external handler: %v", err)
	}
	_, raw, err := issueExternal(t, h, "risk-engine")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	for name, body := range map[string]string{
		"an empty body":        "",
		"not an object":        `"approved"`,
		"an unknown verdict":   `{"nonce":"aa","verdict":"maybe","signature":"00"}`,
		"an unknown member":    `{"nonce":"aa","verdict":"approved","signature":"00","approver":"mallory"}`,
		"a non-hex signature":  `{"nonce":"aa","verdict":"approved","signature":"zz"}`,
		"no signature at all":  `{"nonce":"aa","verdict":"approved"}`,
		"a missing nonce":      `{"verdict":"approved","signature":"00"}`,
		"a truncated document": `{"nonce":`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var payload json.RawMessage
			if body != "" {
				payload = json.RawMessage(body)
			}
			_, err := h.Submit(context.Background(), challenge.SubmitRequest{
				Instance: externalInstance(),
				Decision: externalContext(),
				Detail:   raw,
				Payload:  payload,
				Now:      testNow.Add(time.Minute),
			})
			if !errors.Is(err, challenge.ErrInvalidPayload) {
				t.Fatalf("err = %v, want ErrInvalidPayload", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// failing closed
// ---------------------------------------------------------------------------

func TestExternalFailsClosedWhenTheRoundTripDoesNotHappen(t *testing.T) {
	t.Parallel()

	t.Run("a target that answers with an error", func(t *testing.T) {
		t.Parallel()
		tgt := newNotifiedTarget(t)
		tgt.set(http.StatusInternalServerError, 0, "")
		detail := issueAgainst(t, tgt, 0)
		if detail.Failure != challenge.ExternalFailureStatus {
			t.Fatalf("failure = %q, want %q", detail.Failure, challenge.ExternalFailureStatus)
		}
	})

	t.Run("a target that redirects", func(t *testing.T) {
		t.Parallel()
		tgt := newNotifiedTarget(t)
		tgt.set(http.StatusFound, 0, "http://169.254.169.254/latest/meta-data/")
		detail := issueAgainst(t, tgt, 0)
		if detail.Failure != challenge.ExternalFailureRedirect {
			t.Fatalf("failure = %q, want %q", detail.Failure, challenge.ExternalFailureRedirect)
		}
	})

	t.Run("a target that does not answer in time", func(t *testing.T) {
		t.Parallel()
		tgt := newNotifiedTarget(t)
		tgt.set(http.StatusAccepted, 300*time.Millisecond, "")
		detail := issueAgainst(t, tgt, 20*time.Millisecond)
		if detail.Failure != challenge.ExternalFailureTimeout {
			t.Fatalf("failure = %q, want %q", detail.Failure, challenge.ExternalFailureTimeout)
		}
	})

	t.Run("a target that is not listening", func(t *testing.T) {
		t.Parallel()
		addr := deadLoopbackAddr(t)
		h, err := challenge.NewExternal(challenge.ExternalConfig{
			Gate: loopbackGate(t, "http://"+addr),
			Targets: []challenge.ExternalTarget{{
				Name: "risk-engine", URL: "http://" + addr + "/hook", Secret: testExternalSecret,
			}},
		})
		if err != nil {
			t.Fatalf("new external handler: %v", err)
		}
		issued, raw, err := issueExternal(t, h, "risk-engine")
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if issued.State != challenge.StateFailed {
			t.Fatalf("issued state = %q, want failed", issued.State)
		}
		var detail challenge.ExternalDetail
		if err := json.Unmarshal(raw, &detail); err != nil {
			t.Fatalf("decode detail: %v", err)
		}
		if detail.Failure != challenge.ExternalFailureTransport {
			t.Fatalf("failure = %q, want %q", detail.Failure, challenge.ExternalFailureTransport)
		}
	})
}

// TestExternalStopsDispatchingOverTheSubjectBudget is R43's dispatch half.
//
// The refusal shape is the point of the test. There is no HTTP response of this
// handler's own to put a 429 on — Issue is answering the decide path, not the
// target — so the limit has to be expressible as challenge state, and it is: a
// failed challenge with its own word on the row, which the lifecycle turns into
// a denied decision. What must not happen is the notification going out anyway,
// which is why the target's own count is the assertion that matters.
func TestExternalStopsDispatchingOverTheSubjectBudget(t *testing.T) {
	t.Parallel()
	tgt := newNotifiedTarget(t)
	const burst = 3
	h, err := challenge.NewExternal(challenge.ExternalConfig{
		Gate: loopbackGate(t, originOf(t, tgt.server.URL)),
		Targets: []challenge.ExternalTarget{{
			Name: "risk-engine", URL: tgt.server.URL + "/hook", Secret: testExternalSecret,
		}},
		SubjectRate: stream.RateLimit{PerSecond: 1, Burst: burst},
	})
	if err != nil {
		t.Fatalf("new external handler: %v", err)
	}

	issueAt := func(id string, subject string, at time.Time) challenge.ExternalDetail {
		t.Helper()
		dec := externalContext()
		dec.DecisionID = id
		dec.SubjectID = subject
		issued, ierr := h.Issue(context.Background(), challenge.IssueRequest{
			Instance: challenge.Instance{DecisionID: id, Ordinal: 0, Kind: policy.ChallengeExternal},
			Spec:     policy.External{Target: "risk-engine"},
			Decision: dec,
			Now:      at,
		})
		if ierr != nil {
			t.Fatalf("issue %s: %v", id, ierr)
		}
		detail, ok := issued.Detail.(challenge.ExternalDetail)
		if !ok {
			t.Fatalf("issue returned detail of type %T", issued.Detail)
		}
		// Status has to agree with what Issue returned, because the lifecycle
		// writes every challenge pending and asks Status afterwards.
		raw := mustJSONBody(t, detail)
		st, serr := h.Status(context.Background(), challenge.StatusRequest{
			Instance: challenge.Instance{DecisionID: id, Ordinal: 0, Kind: policy.ChallengeExternal},
			Decision: dec, Detail: raw, Stored: challenge.StatePending, Now: at.Add(time.Second),
		})
		if serr != nil {
			t.Fatalf("status %s: %v", id, serr)
		}
		if st.State != issued.State {
			t.Fatalf("status of %s = %q but issue returned %q", id, st.State, issued.State)
		}
		// And it has to agree about *why*. Shed is set for the one failure that
		// means the target was never called, and for no other — it is what the
		// decision layer reads to deny on load shedding rather than on a refusal
		// somebody made, and a bit that were set for every failure would collapse
		// the two back together.
		if want := detail.Failure == challenge.ExternalFailureRateLimited; st.Shed != want {
			t.Fatalf("status of %s reported Shed=%v with failure %q, want %v",
				id, st.Shed, detail.Failure, want)
		}
		return detail
	}

	for i := range burst {
		if d := issueAt(fmt.Sprintf("dec-%02d", i), "alice", testNow); d.Failure != "" {
			t.Fatalf("issue %d within the burst failed with %q", i, d.Failure)
		}
	}
	shed := issueAt("dec-over", "alice", testNow)
	if shed.Failure != challenge.ExternalFailureRateLimited {
		t.Fatalf("failure = %q, want %q", shed.Failure, challenge.ExternalFailureRateLimited)
	}
	bodies, _ := tgt.received()
	if len(bodies) != burst {
		t.Errorf("the target received %d notifications, want %d: the refusal happened after the POST",
			len(bodies), burst)
	}

	// Another subject is unaffected, and the budget comes back with time.
	if d := issueAt("dec-other", "bob", testNow); d.Failure != "" {
		t.Errorf("a second subject's first notification failed with %q", d.Failure)
	}
	if d := issueAt("dec-later", "alice", testNow.Add(time.Second)); d.Failure != "" {
		t.Errorf("a refill window later the notification still failed with %q", d.Failure)
	}
}

// TestExternalStatusFailsWhenTheCallbackNeverArrives is the other half of the
// inversion the delay tests assert: the same elapsed timer that satisfies a
// wait fails a round trip nobody answered.
func TestExternalStatusFailsWhenTheCallbackNeverArrives(t *testing.T) {
	t.Parallel()
	tgt := newNotifiedTarget(t)
	h, err := challenge.NewExternal(challenge.ExternalConfig{
		Gate: loopbackGate(t, originOf(t, tgt.server.URL)),
		Targets: []challenge.ExternalTarget{{
			Name: "risk-engine", URL: tgt.server.URL, Secret: testExternalSecret,
			RespondWithin: 10 * time.Minute,
		}},
	})
	if err != nil {
		t.Fatalf("new external handler: %v", err)
	}
	issued, raw, err := issueExternal(t, h, "risk-engine")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	pending, err := h.Status(context.Background(), challenge.StatusRequest{
		Instance: externalInstance(), Decision: externalContext(), Detail: raw,
		Stored: challenge.StatePending, Deadline: issued.Deadline, Now: testNow.Add(9 * time.Minute),
	})
	if err != nil {
		t.Fatalf("status before the deadline: %v", err)
	}
	if pending.State != challenge.StatePending {
		t.Fatalf("state nine minutes in = %q, want pending", pending.State)
	}

	elapsed, err := h.Status(context.Background(), challenge.StatusRequest{
		Instance: externalInstance(), Decision: externalContext(), Detail: raw,
		Stored: challenge.StatePending, Deadline: issued.Deadline, Now: testNow.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("status at the deadline: %v", err)
	}
	if elapsed.State != challenge.StateFailed {
		t.Fatalf("state at the deadline = %q, want failed", elapsed.State)
	}
}

func TestExternalConfigurationIsRefusedRatherThanDegraded(t *testing.T) {
	t.Parallel()
	tgt := newNotifiedTarget(t)
	gate := loopbackGate(t, originOf(t, tgt.server.URL))

	cases := map[string]challenge.ExternalConfig{
		"no gate": {
			Targets: []challenge.ExternalTarget{{Name: "a", URL: tgt.server.URL, Secret: testExternalSecret}},
		},
		"a target with no secret": {
			Gate:    gate,
			Targets: []challenge.ExternalTarget{{Name: "a", URL: tgt.server.URL}},
		},
		"a target with a short secret": {
			Gate:    gate,
			Targets: []challenge.ExternalTarget{{Name: "a", URL: tgt.server.URL, Secret: "hunter2"}},
		},
		"a target with no name": {
			Gate:    gate,
			Targets: []challenge.ExternalTarget{{URL: tgt.server.URL, Secret: testExternalSecret}},
		},
		"two targets with one name": {
			Gate: gate,
			Targets: []challenge.ExternalTarget{
				{Name: "a", URL: tgt.server.URL, Secret: testExternalSecret},
				{Name: "a", URL: tgt.server.URL, Secret: testExternalSecret},
			},
		},
		"a callback base that is not absolute": {
			Gate:            gate,
			CallbackBaseURL: "/callbacks",
			Targets:         []challenge.ExternalTarget{{Name: "a", URL: tgt.server.URL, Secret: testExternalSecret}},
		},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := challenge.NewExternal(cfg); err == nil {
				t.Fatal("NewExternal accepted a configuration it cannot serve")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// issueAgainst opens one challenge against a target that is about to misbehave
// and returns the detail the failure was recorded in.
func issueAgainst(t *testing.T, tgt *notifiedTarget, timeout time.Duration) challenge.ExternalDetail {
	t.Helper()
	h, err := challenge.NewExternal(challenge.ExternalConfig{
		Gate: loopbackGate(t, originOf(t, tgt.server.URL)),
		Targets: []challenge.ExternalTarget{{
			Name: "risk-engine", URL: tgt.server.URL, Secret: testExternalSecret, Timeout: timeout,
		}},
	})
	if err != nil {
		t.Fatalf("new external handler: %v", err)
	}
	issued, raw, err := issueExternal(t, h, "risk-engine")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.State != challenge.StateFailed {
		t.Fatalf("issued state = %q, want failed", issued.State)
	}
	var detail challenge.ExternalDetail
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	return detail
}

func callbackBody(t *testing.T, nonce, verdict, secret string, in challenge.Instance) json.RawMessage {
	t.Helper()
	return mustJSONBody(t, map[string]any{
		"nonce":     nonce,
		"verdict":   verdict,
		"signature": challenge.ExternalCallbackSignature(secret, in.DecisionID, in.Ordinal, nonce, verdict),
	})
}

func mustJSONBody(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}
	return raw
}

// deadLoopbackAddr returns a loopback address nothing is listening on, by
// taking a port and giving it straight back.
func deadLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release the port: %v", err)
	}
	return addr
}
