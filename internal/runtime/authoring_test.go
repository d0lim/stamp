package runtime

// authoring_test.go is M4's exit condition: the file authoring path driven
// through the assembled process rather than through the revision package's own
// seams.
//
// The failure this file exists to catch is not a wrong answer, it is a missing
// one. Every rule these tests exercise was already implemented and already
// tested inside `internal/policy/revision`; what was missing was the four lines
// of the composition root that hand the service its capability source and hand
// the HTTP surface the service. A deployment with those lines absent compiles,
// boots, serves, passes every package test — and answers 501 to `apply` and 403
// to every `export`, which is indistinguishable from a deployment that decided
// not to ship R45-R49 at all.
//
// So each test here is written to go red when one specific wire is cut, and the
// wires are named in the comments that say so.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// ---------------------------------------------------------------------------
// F6 — File-authored set revision, as a round trip (R45, R46, R48, R54)
// ---------------------------------------------------------------------------

// TestF6FileAuthoringThroughTheCompositionRoot is the round trip the
// verification contract names — export, then apply, and nothing changes —
// asserted over the real server instead of over the package.
//
// U19 proved the property inside the revision package, where the round trip is
// a function call on a Service the test constructed. That proof says nothing
// about a process nobody handed a Service to. This one runs over HTTP, through
// the mount table, the identity middleware and the capability gate, against the
// same Postgres the deployment would use.
func TestF6FileAuthoringThroughTheCompositionRoot(t *testing.T) {
	h := newHarness(t, harnessOptions{writerID: "f4-writer"})
	h.seed(tenantSchema(), whitelistPolicy("whitelist-transfer"))

	// Two callers who differ in exactly one way: one token carries the
	// capability claim, the other is an ordinary console login. Both are
	// authenticated, both reach the handler, and R48's whole point is that
	// being authenticated is not enough.
	author := h.idp.capable(t, "author", "", revision.CapabilityAuthor)
	auditor := h.idp.capable(t, "auditor", "", revision.CapabilityAudit)
	bystander := h.idp.user(t, "bystander")

	t.Run("a caller holding no capability is refused, and the refusal is recorded", func(t *testing.T) {
		// Cutting the Capabilities wire does not fail this half — an
		// unconfigured service refuses everyone, which is what this asserts.
		// The next subtest is the one that fails.
		code, body := h.do(http.MethodGet, api.SurfaceConsole, api.PolicyExportPath, bystander, "", nil)
		if code != http.StatusForbidden {
			t.Fatalf("GET %s as a caller with no capability = %d: %s", api.PolicyExportPath, code, body)
		}
		var refusal api.ErrorResponse
		h.decode(body, &refusal)
		if refusal.Error != "capability_required" {
			t.Errorf("refusal code = %q, want %q", refusal.Error, "capability_required")
		}

		// R48 is explicit that a refusal leaves a trace: a read that was turned
		// away and a read nobody attempted have to be different rows.
		rows := h.auditPayloads(revision.AuditKindPolicyExportRefused)
		if len(rows) != 1 {
			t.Fatalf("%d %s audit rows, want 1", len(rows), revision.AuditKindPolicyExportRefused)
		}
		// A refusal that did not name who was refused would be a row nobody can
		// act on.
		if caller, _ := rows[0]["caller"].(string); !strings.HasSuffix(caller, "#bystander") {
			t.Errorf("the refusal names caller %q, want the bystander", caller)
		}
	})

	var exported revision.Export
	t.Run("a caller holding the authoring capability receives the effective set", func(t *testing.T) {
		// This is the assertion that dies when `Capabilities` is not wired: a
		// nil capability source refuses this caller too, and the whole of R48
		// is closed to everyone.
		code, body := h.do(http.MethodGet, api.SurfaceConsole, api.PolicyExportPath, author, "", nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s as a policy author = %d: %s", api.PolicyExportPath, code, body)
		}
		h.decode(body, &exported)
		if exported.PolicyCount != 1 {
			t.Errorf("exported policy count = %d, want the one seeded policy", exported.PolicyCount)
		}
		names := exportedNames(exported)
		if !contains(names, revision.ExportSchemaFile) {
			t.Errorf("the export carries no %s: %v", revision.ExportSchemaFile, names)
		}
		if !contains(names, revision.ExportPolicyDir+"/whitelist-transfer.yaml") {
			t.Errorf("the export carries no policy document: %v", names)
		}
		// The reserved governance policy is written against its own schema and
		// cannot be authored from a file, so an export that carried it would be
		// an export that does not apply.
		if contains(names, revision.ExportPolicyDir+"/"+revision.GovernancePolicyID+".yaml") {
			t.Errorf("the export carries the reserved policy: %v", names)
		}

		rows := h.auditPayloads(revision.AuditKindPolicyExported)
		if len(rows) != 1 {
			t.Fatalf("%d %s audit rows, want 1", len(rows), revision.AuditKindPolicyExported)
		}
		if n, _ := rows[0]["policy_count"].(float64); int(n) != exported.PolicyCount {
			t.Errorf("audited policy count = %v, want %d", rows[0]["policy_count"], exported.PolicyCount)
		}
	})

	t.Run("the audit capability opens the same read", func(t *testing.T) {
		// R48 admits two capabilities and not one: an auditor who could not
		// read the policy set could not check a past decision against the rules
		// that produced it.
		code, body := h.do(http.MethodGet, api.SurfaceConsole, api.PolicyExportPath, auditor, "", nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s as an auditor = %d: %s", api.PolicyExportPath, code, body)
		}
	})

	t.Run("applying the export verbatim is no change", func(t *testing.T) {
		// R48's entry ramp, end to end. It also proves the apply route is
		// wired: with `Files` absent this answers 501 rather than 200, and no
		// amount of capability configuration changes that.
		code, body := h.apply(t, author, exported.Payload(), nil)
		if code != http.StatusOK {
			t.Fatalf("POST %s with the export verbatim = %d: %s", api.PolicyApplyPath, code, body)
		}
		var result revision.FileApplyResult
		h.decode(body, &result)
		if !result.NoChange {
			t.Fatalf("the export applied as a change: %+v", result.Proposal.Delta)
		}
		if n := h.revisionCount(); n != 0 {
			t.Errorf("%d revision rows after a no-change apply, want 0", n)
		}
	})

	t.Run("a directory that differs opens one revision and it takes effect", func(t *testing.T) {
		// R45 end to end, and R54 with it: the policy this apply creates is
		// owned by the file path from the moment it exists.
		payload := exported.Payload()
		payload.Documents = append(payload.Documents, policyDocument(t,
			"policies/whitelist-transfer-file.yaml", whitelistPolicy("whitelist-transfer-file")))

		code, body := h.apply(t, author, payload,
			map[string]string{api.BootstrapTokenHeader: h.app.BootstrapToken()})
		if code != http.StatusAccepted {
			t.Fatalf("POST %s with one added policy = %d: %s", api.PolicyApplyPath, code, body)
		}
		var result revision.FileApplyResult
		h.decode(body, &result)
		if result.NoChange {
			t.Fatal("an apply that adds a policy reported no change")
		}
		// Solo-admin governance resolves the revision inside the submission, so
		// by the time this returns the change is in force. R46's asynchronous
		// answer is the quorum case, which F2 owns.
		if result.Proposal.State != revision.StateApplied {
			t.Fatalf("proposal state = %q, want %q", result.Proposal.State, revision.StateApplied)
		}
		if len(result.Proposal.Delta.Changes) != 1 {
			t.Fatalf("%d changes in the revision, want the single addition: %+v",
				len(result.Proposal.Delta.Changes), result.Proposal.Delta.Changes)
		}
		if _, ok := h.effective("whitelist-transfer-file"); !ok {
			t.Fatal("the applied policy is not in force")
		}
		if origin := h.originOf(t, "whitelist-transfer-file"); origin != store.OriginFile {
			t.Errorf("the applied policy's origin = %q, want %q", origin, store.OriginFile)
		}
	})

	t.Run("the round trip still holds once the file path owns a policy", func(t *testing.T) {
		// The first round trip ran over a set the console authored. This one
		// runs over a mixed set, which is the state D23 describes and the one a
		// CI actually applies against on every merge.
		code, body := h.do(http.MethodGet, api.SurfaceConsole, api.PolicyExportPath, author, "", nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", api.PolicyExportPath, code, body)
		}
		var again revision.Export
		h.decode(body, &again)
		if again.PolicyCount != 2 {
			t.Fatalf("exported policy count = %d, want both policies", again.PolicyCount)
		}
		code, body = h.apply(t, author, again.Payload(), nil)
		if code != http.StatusOK {
			t.Fatalf("POST %s with the second export = %d: %s", api.PolicyApplyPath, code, body)
		}
		var result revision.FileApplyResult
		h.decode(body, &result)
		if !result.NoChange {
			t.Fatalf("the second export applied as a change: %+v", result.Proposal.Delta)
		}
	})

	t.Run("the audit chain still verifies", func(t *testing.T) {
		h.verifyChain()
	})
}

// TestTheExportGateStaysFailClosedPerCaller is the property the default
// capability source must not quietly remove.
//
// Wiring [revision.ClaimCapabilities] means every deployment has a capability
// source, and the risk in that is obvious: a source that answers "yes" for
// everyone is worse than no source at all, because the endpoint now looks
// configured. So this asserts the shape rather than the absence — a deployment
// pointed at a claim its IdP does not issue refuses every caller, which is
// exactly the behaviour an unconfigured deployment had.
func TestTheExportGateStaysFailClosedPerCaller(t *testing.T) {
	const unissued = "entitlements"
	h := newHarness(t, harnessOptions{
		writerID: "f4-closed",
		mutate:   func(cfg *Config) { cfg.CapabilityClaim = unissued },
	})
	h.seed(tenantSchema(), whitelistPolicy("whitelist-transfer"))

	for name, token := range map[string]string{
		"a token carrying no capability claim at all": h.idp.user(t, "plain"),
		"a token carrying the default claim instead": h.idp.capable(t, "misconfigured", "",
			revision.CapabilityAuthor, revision.CapabilityAudit),
		"a token whose named claim holds no recognized capability": h.idp.capable(t, "wrong-values",
			unissued, "policy.read"),
	} {
		t.Run(name, func(t *testing.T) {
			code, body := h.do(http.MethodGet, api.SurfaceConsole, api.PolicyExportPath, token, "", nil)
			if code != http.StatusForbidden {
				t.Fatalf("GET %s = %d, want the export refused: %s", api.PolicyExportPath, code, body)
			}
		})
	}

	t.Run("the claim the deployment names is the one that opens it", func(t *testing.T) {
		token := h.idp.capable(t, "entitled", unissued, revision.CapabilityAuthor)
		code, body := h.do(http.MethodGet, api.SurfaceConsole, api.PolicyExportPath, token, "", nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s with the configured claim = %d: %s", api.PolicyExportPath, code, body)
		}
	})
}

// ---------------------------------------------------------------------------
// the authoring mode (R49)
// ---------------------------------------------------------------------------

// TestTheAuthoringModeClosesOnePathAndLeavesTheRestOpen is R49 at the
// composition root.
//
// The second half of each case matters as much as the first. R49 is explicit
// that the approval inbox, the audit views, the dry run and the lock stay open
// in every mode — an operator who turned on `file` at install time and found
// the lock screen switched off with the authoring module would be stuck in
// solo-admin governance with no way out except the offline procedure.
func TestTheAuthoringModeClosesOnePathAndLeavesTheRestOpen(t *testing.T) {
	cases := []struct {
		mode          revision.AuthoringMode
		writer        string
		wantFileApply int
		wantFormEdit  int
	}{
		{
			mode: revision.AuthoringFile, writer: "mode-file",
			wantFileApply: http.StatusAccepted, wantFormEdit: http.StatusForbidden,
		},
		{
			mode: revision.AuthoringConsole, writer: "mode-console",
			wantFileApply: http.StatusForbidden, wantFormEdit: http.StatusAccepted,
		},
	}

	for _, tc := range cases {
		t.Run("mode="+string(tc.mode), func(t *testing.T) {
			h := newHarness(t, harnessOptions{
				writerID: tc.writer,
				mutate:   func(cfg *Config) { cfg.AuthoringMode = tc.mode },
			})
			h.seed(tenantSchema(), whitelistPolicy("whitelist-transfer"))
			author := h.idp.capable(t, "author", "", revision.CapabilityAuthor)
			bootstrap := map[string]string{api.BootstrapTokenHeader: h.app.BootstrapToken()}

			// Each submission adds a policy of its own, so whichever of the two
			// lands does not leave a pending revision the other would trip over.
			t.Run("the file path", func(t *testing.T) {
				code, body := h.do(http.MethodGet, api.SurfaceConsole, api.PolicyExportPath, author, "", nil)
				if code != http.StatusOK {
					t.Fatalf("GET %s = %d: %s", api.PolicyExportPath, code, body)
				}
				var exported revision.Export
				h.decode(body, &exported)
				payload := exported.Payload()
				payload.Documents = append(payload.Documents, policyDocument(t,
					"policies/from-file.yaml", whitelistPolicy("from-file")))

				code, body = h.apply(t, author, payload, bootstrap)
				if code != tc.wantFileApply {
					t.Fatalf("POST %s under %q = %d, want %d: %s",
						api.PolicyApplyPath, tc.mode, code, tc.wantFileApply, body)
				}
				if code == http.StatusForbidden {
					var refusal api.ErrorResponse
					h.decode(body, &refusal)
					if refusal.Error != "authoring_locked" {
						t.Errorf("refusal code = %q, want %q", refusal.Error, "authoring_locked")
					}
				}
			})

			t.Run("the console path", func(t *testing.T) {
				delta := revision.Single(nil, whitelistPolicy("from-console"))
				code, body := h.do(http.MethodPost, api.SurfaceConsole, "/policies/revisions", author,
					h.revisionBody(t, delta, ""), bootstrap)
				if code != tc.wantFormEdit {
					t.Fatalf("POST /policies/revisions under %q = %d, want %d: %s",
						tc.mode, code, tc.wantFormEdit, body)
				}
			})

			// R49's floor: closing an authoring window never closes the way out
			// of solo-admin governance, nor the surfaces an approver and an
			// auditor work from.
			t.Run("the inbox, the dry run and the lock stay open", func(t *testing.T) {
				if code, body := h.do(http.MethodGet, api.SurfaceConsole,
					"/decisions/inbox", author, "", nil); code != http.StatusOK {
					t.Errorf("GET /decisions/inbox under %q = %d: %s", tc.mode, code, body)
				}
				draft := policyDocument(t, "draft.yaml", whitelistPolicy("draft"))
				dry, err := json.Marshal(api.DryRunRequest{
					Document: string(draft.Content),
					Input: api.DryRunInput{
						Action: "transfer",
						Subject: api.EntityInput{Type: "account", ID: "acct-src",
							Attributes: map[string]any{"number": "1001"}},
						Resource: api.EntityInput{Type: "account", ID: "acct-dst",
							Attributes: map[string]any{"number": "2002"}},
					},
				})
				if err != nil {
					t.Fatalf("encode the dry run: %v", err)
				}
				if code, body := h.do(http.MethodPost, api.SurfaceConsole,
					api.DryRunPath, author, string(dry), nil); code != http.StatusOK {
					t.Errorf("POST %s under %q = %d: %s", api.DryRunPath, tc.mode, code, body)
				}
				// The lock is the one that would strand an operator: turning on
				// `file` mode at install time and finding the way out of
				// solo-admin governance turned off with it leaves the offline
				// break-glass procedure as the only exit.
				if code, body := h.do(http.MethodPost, api.SurfaceConsole, "/governance/lock",
					h.idp.user(t, "root"), `{"threshold": 2, "approvers": ["alice", "bob"]}`,
					bootstrap); code != http.StatusOK {
					t.Fatalf("POST /governance/lock under %q = %d: %s", tc.mode, code, body)
				}
			})
		})
	}
}

// TestAnUnknownAuthoringModeFailsStartup is the half of R49 that a config knob
// gets wrong silently: a misspelling resolving to the permissive default would
// open the very window the operator wrote the setting down to close, and the
// process would say nothing about it.
//
// It needs no database — the configuration is refused before anything is built.
func TestAnUnknownAuthoringModeFailsStartup(t *testing.T) {
	roles, err := ParseRoles("all")
	if err != nil {
		t.Fatalf("parse roles: %v", err)
	}
	cfg := Config{
		DSN:       "postgres://stamp@127.0.0.1:1/stamp",
		Addresses: map[api.Surface]string{api.SurfacePEP: "127.0.0.1:0"},
		OIDC: OIDCConfig{
			Issuers:    []IssuerConfig{{Issuer: "https://idp.invalid", JWKSURL: "https://idp.invalid/jwks"}},
			Audience:   testAudience,
			Algorithms: []string{"RS256"},
		},
		AuthoringMode: "File",
	}
	_, err = Assemble(context.Background(), cfg, roles, nil)
	if err == nil {
		t.Fatal("assembling with an unrecognized authoring mode succeeded, want a startup failure")
	}
	// The refusal has to happen in the configuration check and not somewhere
	// downstream: this DSN points nowhere, so a message naming the variable is
	// also the evidence that nothing was opened, claimed or migrated before the
	// typo was noticed.
	if !strings.Contains(err.Error(), EnvAuthoringMode) {
		t.Errorf("the startup failure is %q, want it to name %s", err, EnvAuthoringMode)
	}

	t.Run("and the environment reader refuses it too", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(EnvDSN, "postgres://stamp@127.0.0.1:1/stamp")
		t.Setenv(EnvOIDCIssuer, "https://idp.invalid")
		t.Setenv(EnvOIDCJWKSURL, "https://idp.invalid/jwks")
		t.Setenv(EnvOIDCAudience, testAudience)
		t.Setenv(EnvAuthoringMode, "readonly")
		if _, err := ConfigFromEnv(); err == nil {
			t.Fatalf("%s=readonly was accepted, want a configuration error", EnvAuthoringMode)
		}
	})

	t.Run("and every declared mode is accepted", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(EnvDSN, "postgres://stamp@127.0.0.1:1/stamp")
		t.Setenv(EnvOIDCIssuer, "https://idp.invalid")
		t.Setenv(EnvOIDCJWKSURL, "https://idp.invalid/jwks")
		t.Setenv(EnvOIDCAudience, testAudience)
		for _, mode := range revision.AuthoringModes() {
			t.Setenv(EnvAuthoringMode, string(mode))
			got, err := ConfigFromEnv()
			if err != nil {
				t.Fatalf("%s=%s: %v", EnvAuthoringMode, mode, err)
			}
			if got.AuthoringMode != mode {
				t.Errorf("%s=%s read back as %q", EnvAuthoringMode, mode, got.AuthoringMode)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// the operator's bounds (R45, D24)
// ---------------------------------------------------------------------------

// TestTheOperatorBoundsReachTheGovernanceService is the mutation test for the
// three remaining fields of the governance config: a payload limit, a
// submission rate and the bootstrap warning interval.
//
// Each of them has a sane package default, which is exactly why an unwired one
// is invisible: the process behaves correctly and the operator's setting does
// nothing. So each assertion here is written against a value no default would
// produce.
func TestTheOperatorBoundsReachTheGovernanceService(t *testing.T) {
	h := newHarness(t, harnessOptions{
		writerID: "f4-bounds",
		mutate: func(cfg *Config) {
			// Three documents is the schema plus two policies: enough for the
			// applies below to be possible and far below the package default
			// of 1000, so nothing here can pass on the default.
			cfg.ApplyLimits.MaxDocuments = 3
			// One revision an hour is a bound no default reaches, and the
			// window outlives the test so the second apply cannot age out of
			// it.
			cfg.RevisionRate = revision.Rate{Window: time.Hour, Burst: 1}
			cfg.BootstrapWarnInterval = 100 * time.Millisecond
		},
	})
	h.seed(tenantSchema(), whitelistPolicy("whitelist-transfer"))
	author := h.idp.capable(t, "author", "", revision.CapabilityAuthor)
	bootstrap := map[string]string{api.BootstrapTokenHeader: h.app.BootstrapToken()}

	code, body := h.do(http.MethodGet, api.SurfaceConsole, api.PolicyExportPath, author, "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", api.PolicyExportPath, code, body)
	}
	var exported revision.Export
	h.decode(body, &exported)

	t.Run("a payload over the operator's document count is refused before it is parsed", func(t *testing.T) {
		payload := exported.Payload()
		payload.Documents = append(payload.Documents,
			policyDocument(t, "policies/one.yaml", whitelistPolicy("one")),
			policyDocument(t, "policies/two.yaml", whitelistPolicy("two")),
			// The last document is deliberately unparseable. A refusal that
			// named it would mean the limit was checked after the parser, which
			// is the order R45 fixes.
			revision.Document{Name: "policies/three.yaml", Content: []byte("{{{ not yaml")})

		code, body := h.apply(t, author, payload, bootstrap)
		if code != http.StatusRequestEntityTooLarge {
			t.Fatalf("POST %s with %d documents = %d, want 413: %s",
				api.PolicyApplyPath, len(payload.Documents), code, body)
		}
		var refusal api.ErrorResponse
		h.decode(body, &refusal)
		if refusal.Error != "payload_too_large" {
			t.Errorf("refusal code = %q, want %q", refusal.Error, "payload_too_large")
		}
		if n := h.revisionCount(); n != 0 {
			t.Errorf("%d revision rows after a refused payload, want 0", n)
		}
	})

	t.Run("the operator's submission rate bounds the file path", func(t *testing.T) {
		first := exported.Payload()
		first.Documents = append(first.Documents,
			policyDocument(t, "policies/first.yaml", whitelistPolicy("first")))
		if code, body := h.apply(t, author, first, bootstrap); code != http.StatusAccepted {
			t.Fatalf("the first apply = %d: %s", code, body)
		}

		// The gate is free — the first revision resolved inside its submission
		// — and this payload is inside the document limit, so the only thing
		// that can turn it away is the rate.
		second := exported.Payload()
		second.Documents = append(second.Documents,
			policyDocument(t, "policies/second.yaml", whitelistPolicy("second")))
		code, body := h.apply(t, author, second, bootstrap)
		if code != http.StatusTooManyRequests {
			t.Fatalf("the second apply inside the window = %d, want 429: %s", code, body)
		}
		var refusal api.ErrorResponse
		h.decode(body, &refusal)
		if refusal.Error != "rate_limited" {
			t.Errorf("refusal code = %q, want %q", refusal.Error, "rate_limited")
		}
	})

	t.Run("the operator's warning interval reaches the bootstrap gate", func(t *testing.T) {
		// The default is an hour, so a row inside this deadline can only come
		// from the configured interval.
		rows := h.awaitAudit(t, revision.AuditKindBootstrapUnused, 1)
		if severity, _ := rows[0][revision.SeverityKey].(string); severity != revision.SeverityCritical {
			t.Errorf("the unused-token warning is %q, want %q", severity, revision.SeverityCritical)
		}
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// capable mints a console token carrying the export gate's capability claim.
//
// The claim is read off a subject the identity layer already verified, so this
// is a token like any other: nothing about holding a capability changes how the
// credential is checked.
func (m *mockIdP) capable(t *testing.T, subject, claim string, caps ...revision.Capability) string {
	t.Helper()
	if claim == "" {
		claim = revision.DefaultCapabilityClaim
	}
	held := make([]any, 0, len(caps))
	for _, c := range caps {
		held = append(held, string(c))
	}
	now := time.Now()
	return m.sign(t, map[string]any{
		"iss": m.server.URL,
		"sub": subject,
		"aud": testAudience,
		"azp": testConsole,
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
		claim: held,
	})
}

// apply posts a directory to the file authoring endpoint.
func (h *harness) apply(t *testing.T, token string, payload revision.Payload,
	headers map[string]string,
) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(api.ApplyRequest{Documents: payload.Documents})
	if err != nil {
		t.Fatalf("encode apply request: %v", err)
	}
	return h.do(http.MethodPost, api.SurfaceConsole, api.PolicyApplyPath, token, string(raw), headers)
}

// revisionCount is how many revisions this installation has ever opened. It is
// the check that a refusal happened before the pipeline rather than inside it.
func (h *harness) revisionCount() int {
	h.t.Helper()
	var n int
	if err := h.app.Store().Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM policy_revisions`).Scan(&n); err != nil {
		h.t.Fatalf("count revisions: %v", err)
	}
	return n
}

func (h *harness) originOf(t *testing.T, id string) store.Origin {
	t.Helper()
	rec, err := store.EffectivePolicy(context.Background(), h.app.Store().Pool(), id)
	if err != nil {
		t.Fatalf("read policy %s: %v", id, err)
	}
	return rec.Origin
}

// policyDocument renders one policy as the file it would be authored in.
func policyDocument(t *testing.T, name string, p *policy.Policy) revision.Document {
	t.Helper()
	raw, err := policy.Marshal(&policy.Set{Policies: []policy.Policy{*p}})
	if err != nil {
		t.Fatalf("encode %s: %v", name, err)
	}
	return revision.Document{Name: name, Content: raw}
}

func exportedNames(e revision.Export) []string {
	out := make([]string, len(e.Files))
	for i, f := range e.Files {
		out[i] = f.Name
	}
	return out
}
