package mfa

// ciba_test.go verifies the CIBA client against a mock OP, which is exactly the
// verification D26 left it with: the demo path is a step-up redirect, because
// no self-hostable IdP ships the decoupled authentication server a real CIBA
// round trip needs.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// mockOP is an OIDC OP that speaks just enough CIBA to answer this client, and
// records what it was sent.
type mockOP struct {
	server *httptest.Server

	backchannelForm url.Values
	tokenForm       url.Values
	authHeader      string

	backchannelStatus int
	backchannelBody   string
	tokenStatus       int
	tokenBody         string
}

func newMockOP(t *testing.T) *mockOP {
	t.Helper()
	m := &mockOP{
		backchannelStatus: http.StatusOK,
		backchannelBody:   `{"auth_req_id":"1c266114-a1be","expires_in":120,"interval":2}`,
		tokenStatus:       http.StatusOK,
		tokenBody:         `{"id_token":"header.payload.signature","token_type":"Bearer"}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ciba/auth", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		m.backchannelForm = r.PostForm
		m.authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(m.backchannelStatus)
		_, _ = w.Write([]byte(m.backchannelBody))
	})
	mux.HandleFunc("/ciba/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		m.tokenForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(m.tokenStatus)
		_, _ = w.Write([]byte(m.tokenBody))
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockOP) client(t *testing.T) *CIBA {
	t.Helper()
	c, err := NewCIBA(CIBAConfig{
		BackchannelEndpoint:    m.server.URL + "/ciba/auth",
		TokenEndpoint:          m.server.URL + "/ciba/token",
		ClientID:               "stamp-ciba",
		ClientSecret:           "s3cret",
		AllowInsecureTransport: true,
	})
	if err != nil {
		t.Fatalf("build ciba client: %v", err)
	}
	return c
}

func testInitiateRequest(correlator string) InitiateRequest {
	return InitiateRequest{
		SubjectID:  testSubject,
		Correlator: correlator,
		Reference:  ReferenceCode(correlator),
		Nonce:      NonceFor(correlator),
		ACRValues:  []string{acrGold},
		Now:        testNow,
	}
}

// TestCIBACarriesTheBindingMessage is the plan's CIBA scenario. What travels is
// the reference code and not the correlator: the correlator is what satisfies
// the challenge, and a value the OP prints on somebody's phone is not a place
// for it.
func TestCIBACarriesTheBindingMessage(t *testing.T) {
	t.Parallel()
	op := newMockOP(t)
	out, err := op.client(t).Initiate(t.Context(), testInitiateRequest("correlator-value"))
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if out.Method != MethodCIBA {
		t.Fatalf("method = %q, want %q", out.Method, MethodCIBA)
	}
	if out.AuthReqID != "1c266114-a1be" {
		t.Fatalf("auth_req_id = %q", out.AuthReqID)
	}

	form := op.backchannelForm
	if got, want := form.Get("binding_message"), ReferenceCode("correlator-value"); got != want {
		t.Fatalf("binding_message = %q, want %q", got, want)
	}
	if got := form.Get("acr_values"); got != acrGold {
		t.Fatalf("acr_values = %q, want %q", got, acrGold)
	}
	if got := form.Get("login_hint"); got != testSubject {
		t.Fatalf("login_hint = %q, want %q", got, testSubject)
	}
	for _, leaked := range []string{"correlator-value"} {
		for key, values := range form {
			for _, v := range values {
				if strings.Contains(v, leaked) {
					t.Fatalf("the correlator leaked into the backchannel request as %s=%q", key, v)
				}
			}
		}
	}
	if !strings.HasPrefix(op.authHeader, "Basic ") {
		t.Fatalf("client credentials were not sent in the Authorization header: %q", op.authHeader)
	}
}

// TestCIBARefusesABindingMessageTheIdPWouldRefuse enforces U0's measured limits
// before the request goes out, so a deployment that customizes the reference
// code learns at issue rather than when a human is waiting for a prompt.
func TestCIBARefusesABindingMessageTheIdPWouldRefuse(t *testing.T) {
	t.Parallel()
	op := newMockOP(t)
	c := op.client(t)

	for name, reference := range map[string]string{
		"with a space": "TXN 4417",
		"too long":     strings.Repeat("A", MaxBindingMessageLength+1),
		"punctuated":   "amount=250000;payee=acme",
		"empty":        "",
		"non-ascii":    "송금-4417",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := testInitiateRequest("c")
			req.Reference = reference
			if _, err := c.Initiate(t.Context(), req); !errors.Is(err, ErrBindingMessage) {
				t.Fatalf("initiate err = %v, want ErrBindingMessage", err)
			}
		})
	}
	if op.backchannelForm != nil {
		t.Fatal("a refused binding message still reached the op")
	}
}

// TestReferenceCodeIsAlwaysAcceptable is the property that makes the check
// above a guard against customization rather than a landmine in the default
// path: every code this package derives passes it.
func TestReferenceCodeIsAlwaysAcceptable(t *testing.T) {
	t.Parallel()
	for i := range 512 {
		correlator, err := randomCorrelator()
		if err != nil {
			t.Fatalf("correlator: %v", err)
		}
		code := ReferenceCode(correlator)
		if err := ValidateBindingMessage(code); err != nil {
			t.Fatalf("iteration %d produced %q, which an idp would refuse: %v", i, code, err)
		}
	}
}

// TestCIBAClassifiesTheIdPsRefusals maps the OP's error document onto this
// package's sentinels. The `server_error` row is the one U0 actually met: a
// formally valid request the IdP accepted and then could not route to any
// authentication device.
func TestCIBAClassifiesTheIdPsRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		status int
		body   string
		want   error
	}{
		"no authentication channel": {
			http.StatusInternalServerError,
			`{"error":"server_error","error_description":"Failed to send authentication request"}`,
			ErrInitiationUnsupported,
		},
		"binding message refused": {
			http.StatusBadRequest,
			`{"error":"invalid_binding_message","error_description":"max 50 characters, no spaces"}`,
			ErrBindingMessage,
		},
		"grant not offered": {
			http.StatusBadRequest,
			`{"error":"unsupported_grant_type"}`,
			ErrInitiationUnsupported,
		},
		"endpoint absent": {http.StatusNotFound, `not found`, ErrInitiationUnsupported},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			op := newMockOP(t)
			op.backchannelStatus = tc.status
			op.backchannelBody = tc.body
			_, err := op.client(t).Initiate(t.Context(), testInitiateRequest("c"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("initiate err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCIBAPollClassifiesTokenEndpointAnswers(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		status int
		body   string
		want   error
		token  string
	}{
		"granted":  {http.StatusOK, `{"id_token":"a.b.c"}`, nil, "a.b.c"},
		"pending":  {http.StatusBadRequest, `{"error":"authorization_pending"}`, ErrAuthorizationPending, ""},
		"slow":     {http.StatusBadRequest, `{"error":"slow_down"}`, ErrSlowDown, ""},
		"declined": {http.StatusBadRequest, `{"error":"access_denied"}`, ErrAuthorizationDeclined, ""},
		"expired":  {http.StatusBadRequest, `{"error":"expired_token"}`, ErrAuthorizationDeclined, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			op := newMockOP(t)
			op.tokenStatus = tc.status
			op.tokenBody = tc.body
			token, err := op.client(t).Poll(t.Context(), "1c266114-a1be")
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("poll err = %v, want %v", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("poll: %v", err)
			}
			if token != tc.token {
				t.Fatalf("id_token = %q, want %q", token, tc.token)
			}
			if got := op.tokenForm.Get("grant_type"); got != "urn:openid:params:grant-type:ciba" {
				t.Fatalf("grant_type = %q", got)
			}
			if got := op.tokenForm.Get("auth_req_id"); got != "1c266114-a1be" {
				t.Fatalf("auth_req_id = %q", got)
			}
		})
	}
}

func TestCIBAHonoursTheOPsPollInterval(t *testing.T) {
	t.Parallel()
	op := newMockOP(t)
	auth, err := op.client(t).Authenticate(t.Context(), testInitiateRequest("c"))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if auth.Interval != 2*time.Second {
		t.Fatalf("interval = %s, want 2s", auth.Interval)
	}
	if auth.ExpiresIn != 2*time.Minute {
		t.Fatalf("expires_in = %s, want 2m", auth.ExpiresIn)
	}

	op.backchannelBody = `{"auth_req_id":"x"}`
	silent, err := op.client(t).Authenticate(t.Context(), testInitiateRequest("c"))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if silent.Interval != DefaultCIBAPollInterval {
		t.Fatalf("interval = %s, want the default", silent.Interval)
	}
}

func TestNewCIBARefusesAnIncompleteConfiguration(t *testing.T) {
	t.Parallel()
	base := CIBAConfig{
		BackchannelEndpoint:    "http://op.example.test/ciba/auth",
		ClientID:               "stamp-ciba",
		ClientSecret:           "s3cret",
		AllowInsecureTransport: true,
	}
	for name, mutate := range map[string]func(*CIBAConfig){
		"no endpoint":  func(c *CIBAConfig) { c.BackchannelEndpoint = "" },
		"no client id": func(c *CIBAConfig) { c.ClientID = "" },
		"no secret":    func(c *CIBAConfig) { c.ClientSecret = "" },
		// CIBA has no public clients, so the credentials travel on every call —
		// over plaintext they travel to whoever is on the path.
		"plaintext": func(c *CIBAConfig) { c.AllowInsecureTransport = false },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := base
			mutate(&cfg)
			if _, err := NewCIBA(cfg); err == nil {
				t.Fatal("an incomplete ciba configuration was accepted")
			}
		})
	}
}

// TestFallbackRedirectsWhenTheOPCannotDoCIBA is D26's promotion of the fallback
// to the default path, verified as a branch: an OP that cannot reach an
// authentication device sends the subject to a browser instead.
func TestFallbackRedirectsWhenTheOPCannotDoCIBA(t *testing.T) {
	t.Parallel()
	op := newMockOP(t)
	op.backchannelStatus = http.StatusInternalServerError
	op.backchannelBody = `{"error":"server_error","error_description":"Failed to send authentication request"}`

	secondary := &recordingInitiator{}
	chain, err := NewFallback(op.client(t), secondary)
	if err != nil {
		t.Fatalf("build fallback: %v", err)
	}
	out, err := chain.Initiate(t.Context(), testInitiateRequest("c"))
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if out.Method != MethodStepUp {
		t.Fatalf("method = %q, want %q", out.Method, MethodStepUp)
	}
	if len(secondary.calls) != 1 {
		t.Fatalf("the fallback was called %d times, want 1", len(secondary.calls))
	}
}

// TestFallbackDoesNotHideAnOutage is the other half of that branch. An IdP that
// is down is not a capability the IdP lacks, and turning an outage into a
// different flow would hide it behind a demo that looks like it works.
func TestFallbackDoesNotHideAnOutage(t *testing.T) {
	t.Parallel()
	op := newMockOP(t)
	op.backchannelStatus = http.StatusServiceUnavailable
	op.backchannelBody = `{"error":"temporarily_unavailable"}`

	secondary := &recordingInitiator{}
	chain, err := NewFallback(op.client(t), secondary)
	if err != nil {
		t.Fatalf("build fallback: %v", err)
	}
	if _, err := chain.Initiate(t.Context(), testInitiateRequest("c")); err == nil {
		t.Fatal("an outage fell through to the step-up path")
	}
	if len(secondary.calls) != 0 {
		t.Fatalf("the fallback ran %d times for an outage, want 0", len(secondary.calls))
	}
}
