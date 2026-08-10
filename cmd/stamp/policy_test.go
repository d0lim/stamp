package main

// policy_test.go drives the command against a stub API.
//
// What is being tested here is the command's contract with whatever runs it:
// which exit code each outcome produces, that the default does not block, and
// that a refusal a CI has to act on arrives as text naming the revision holding
// the gate. The governance behaviour behind the endpoints is the revision
// package's, and is tested there against a real database.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// stubAPI is the console API as this command sees it.
type stubAPI struct {
	applyStatus int
	applyBody   any
	// states is served one per read of a revision, so a test can drive a
	// revision from pending to resolved.
	states     []revision.State
	reads      int
	export     revision.Export
	lockBody   api.LockRequest
	lastApply  api.ApplyRequest
	lastBearer string
}

func (s *stubAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(api.PolicyApplyPattern, func(w http.ResponseWriter, r *http.Request) {
		s.lastBearer = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&s.lastApply); err != nil {
			t.Errorf("decode the apply body: %v", err)
		}
		status := s.applyStatus
		if status == 0 {
			status = http.StatusAccepted
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(s.applyBody)
	})
	mux.HandleFunc("GET /policies/revisions/{id}", func(w http.ResponseWriter, r *http.Request) {
		state := revision.StatePending
		if s.reads < len(s.states) {
			state = s.states[s.reads]
		} else if len(s.states) > 0 {
			state = s.states[len(s.states)-1]
		}
		s.reads++
		_ = json.NewEncoder(w).Encode(revision.Proposal{ID: r.PathValue("id"), State: state})
	})
	mux.HandleFunc(api.PolicyExportPattern, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(s.export)
	})
	mux.HandleFunc("POST /governance/lock", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&s.lockBody); err != nil {
			t.Errorf("decode the lock body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"mode": string(revision.ModeQuorum)})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// policyDir writes a directory holding one policy document.
func policyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"),
		[]byte("apiVersion: stamp/v1\nkind: Policy\nid: file.one\n"), 0o600); err != nil {
		t.Fatalf("write the policy: %v", err)
	}
	// A file the payload must ignore, because a directory is a working tree and
	// not only policies.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("notes\n"), 0o600); err != nil {
		t.Fatalf("write the readme: %v", err)
	}
	return dir
}

func TestApplyReturnsTheProposalAndDoesNotBlock(t *testing.T) {
	t.Parallel()
	stub := &stubAPI{applyBody: revision.FileApplyResult{
		Proposal: revision.Proposal{
			ID: "rev-1", State: revision.StatePending, Threshold: 2, Origin: store.OriginFile,
		},
	}}
	server := stub.server(t)
	var out strings.Builder

	err := runPolicy(context.Background(), []string{
		"apply", "--dir", policyDir(t), "--api", server.URL, "--token", "t",
	}, &out)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !strings.Contains(out.String(), "rev-1") {
		t.Errorf("the output does not name the proposal: %s", out.String())
	}
	if !strings.Contains(out.String(), "approvals required: 2") {
		t.Errorf("the output does not report what the revision needs: %s", out.String())
	}
	// Only the policy documents travel. The README is a file in the directory
	// and not a document of the desired state.
	if len(stub.lastApply.Documents) != 1 || stub.lastApply.Documents[0].Name != "a.yaml" {
		t.Errorf("the payload is %v, want just the policy document", stub.lastApply.Documents)
	}
	if stub.lastBearer != "Bearer t" {
		t.Errorf("the request carried %q, want the access token", stub.lastBearer)
	}
	if stub.reads != 0 {
		t.Errorf("the default apply polled %d times; it is meant to return and exit", stub.reads)
	}
}

func TestApplyNoChangeIsSuccessAndSaysSo(t *testing.T) {
	t.Parallel()
	stub := &stubAPI{applyStatus: http.StatusOK, applyBody: revision.FileApplyResult{NoChange: true}}
	server := stub.server(t)
	var out strings.Builder

	if err := runPolicy(context.Background(), []string{
		"apply", "--dir", policyDir(t), "--api", server.URL, "--token", "t",
	}, &out); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !strings.Contains(out.String(), "no change") {
		t.Errorf("the output does not report that there was nothing to do: %s", out.String())
	}
}

func TestApplyWaitReflectsTheOutcomeInTheExitCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		states  []revision.State
		timeout string
		want    int
	}{
		{"applied", []revision.State{revision.StatePending, revision.StateApplied}, "10s", 0},
		{"rejected", []revision.State{revision.StateRejected}, "10s", exitRejected},
		{"withdrawn", []revision.State{revision.StateWithdrawn}, "10s", exitReleased},
		{"superseded", []revision.State{revision.StateSuperseded}, "10s", exitReleased},
		{"still open", []revision.State{revision.StatePending}, "1ms", exitTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stub := &stubAPI{
				applyBody: revision.FileApplyResult{
					Proposal: revision.Proposal{ID: "rev-1", State: revision.StatePending},
				},
				states: tc.states,
			}
			server := stub.server(t)
			var out strings.Builder
			err := runPolicy(context.Background(), []string{
				"apply", "--dir", policyDir(t), "--api", server.URL, "--token", "t",
				"--wait", "--timeout", tc.timeout, "--poll", "1ms",
			}, &out)
			if tc.want == 0 {
				if err != nil {
					t.Fatalf("apply --wait: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("apply --wait succeeded, want exit %d", tc.want)
			}
			if got := exitCodeOf(err); got != tc.want {
				t.Errorf("exit code = %d, want %d (%v)", got, tc.want, err)
			}
		})
	}
}

// TestApplyReportsTheRevisionHoldingTheGate is the CI-facing half of R47.
func TestApplyReportsTheRevisionHoldingTheGate(t *testing.T) {
	t.Parallel()
	stub := &stubAPI{
		applyStatus: http.StatusConflict,
		applyBody: api.PendingRevisionResponse{
			Error:   "revision_pending",
			Message: "another revision is open",
			Pending: revision.PendingRevision{
				ID: "rev-open", Origin: store.OriginForm, Threshold: 3, Collected: 1,
			},
		},
	}
	server := stub.server(t)
	var out strings.Builder

	err := runPolicy(context.Background(), []string{
		"apply", "--dir", policyDir(t), "--api", server.URL, "--token", "t",
	}, &out)
	if err == nil {
		t.Fatal("the apply succeeded while another revision held the gate")
	}
	for _, want := range []string{"rev-open", "1 of 3", string(store.OriginForm)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not mention %q: %v", want, err)
		}
	}
	if got := exitCodeOf(err); got != exitFailure {
		t.Errorf("exit code = %d, want %d", got, exitFailure)
	}
}

func TestApplyRequiresATokenAndAnAPI(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	if err := runPolicy(context.Background(),
		[]string{"apply", "--dir", ".", "--api", "http://localhost"}, &out); err == nil {
		t.Error("an apply with no token was accepted")
	}
	if err := runPolicy(context.Background(),
		[]string{"apply", "--dir", ".", "--token", "t"}, &out); err == nil {
		t.Error("an apply with no API base URL was accepted")
	}
}

func TestExportWritesATreeThatReadsBack(t *testing.T) {
	t.Parallel()
	stub := &stubAPI{export: revision.Export{
		PolicyCount: 1,
		Files: []revision.ExportFile{
			{Name: revision.ExportSchemaFile, Content: "apiVersion: stamp/v1\nkind: Schema\n"},
			{Name: "policies/file.one.yaml", Content: "apiVersion: stamp/v1\nkind: Policy\nid: file.one\n"},
		},
	}}
	server := stub.server(t)
	dir := t.TempDir()
	var out strings.Builder

	if err := runPolicy(context.Background(), []string{
		"export", "--dir", dir, "--api", server.URL, "--token", "t",
	}, &out); err != nil {
		t.Fatalf("export: %v", err)
	}
	// The tree the export wrote is the payload the apply would send back: this
	// is the command-line end of the round trip.
	payload, err := revision.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the exported tree: %v", err)
	}
	if len(payload.Documents) != 2 {
		t.Fatalf("the exported tree holds %d documents, want 2", len(payload.Documents))
	}
	if !strings.Contains(out.String(), "proposes no revision") {
		t.Errorf("the output does not say what applying it does: %s", out.String())
	}
}

// TestExportRefusesAFileOutsideTheTargetDirectory is a check on the server's
// answer rather than on our own output: the names come from over the network.
func TestExportRefusesAFileOutsideTheTargetDirectory(t *testing.T) {
	t.Parallel()
	stub := &stubAPI{export: revision.Export{
		Files: []revision.ExportFile{{Name: "../escaped.yaml", Content: "x"}},
	}}
	server := stub.server(t)
	dir := t.TempDir()
	err := runPolicy(context.Background(), []string{
		"export", "--dir", dir, "--api", server.URL, "--token", "t",
	}, &strings.Builder{})
	if err == nil {
		t.Fatal("the export wrote a file the server named outside the target directory")
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dir), "escaped.yaml")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the escaped file exists: %v", statErr)
	}
}

func TestLockPrintsTheQuorumAndRequiresConfirmation(t *testing.T) {
	t.Parallel()
	stub := &stubAPI{}
	server := stub.server(t)

	var refused strings.Builder
	err := runPolicy(context.Background(), []string{
		"lock", "--threshold", "2", "--approvers", "ann,bob", "--api", server.URL, "--token", "t",
	}, &refused)
	if err == nil {
		t.Fatal("the lock ran without confirmation")
	}
	for _, want := range []string{"approvals required: 2", "ann, bob", "cannot be undone"} {
		if !strings.Contains(refused.String(), want) {
			t.Errorf("the prompt does not show %q: %s", want, refused.String())
		}
	}
	if stub.lockBody.Threshold != 0 {
		t.Error("an unconfirmed lock still called the API")
	}

	var out strings.Builder
	if err := runPolicy(context.Background(), []string{
		"lock", "--threshold", "2", "--approvers", "ann,bob",
		"--api", server.URL, "--token", "t", "--yes",
	}, &out); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if stub.lockBody.Threshold != 2 || len(stub.lockBody.Approvers) != 2 {
		t.Errorf("the lock request is %+v, want threshold 2 over two approvers", stub.lockBody)
	}
	if !strings.Contains(out.String(), string(revision.ModeQuorum)) {
		t.Errorf("the output does not report the new mode: %s", out.String())
	}
}

// TestLockRefusesAnUnreachableQuorumBeforeSendingIt keeps the operator from
// installing governance nobody can satisfy — the state whose only exit is the
// offline break-glass procedure.
func TestLockRefusesAnUnreachableQuorumBeforeSendingIt(t *testing.T) {
	t.Parallel()
	stub := &stubAPI{}
	server := stub.server(t)
	err := runPolicy(context.Background(), []string{
		"lock", "--threshold", "3", "--approvers", "ann,bob",
		"--api", server.URL, "--token", "t", "--yes",
	}, &strings.Builder{})
	if err == nil {
		t.Fatal("a threshold larger than the approver set was accepted")
	}
	if stub.lockBody.Threshold != 0 {
		t.Error("the unreachable quorum was sent anyway")
	}
}

func TestPolicyWithoutASubcommandExplainsItself(t *testing.T) {
	t.Parallel()
	err := runPolicy(context.Background(), nil, &strings.Builder{})
	if err == nil {
		t.Fatal("`stamp policy` with no subcommand succeeded")
	}
	for _, want := range []string{"apply", "export", "lock"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the usage text omits %q: %v", want, err)
		}
	}
}

// TestWaitStopsWhenTheContextIs keeps a cancelled CI step from leaving a
// process polling.
func TestWaitStopsWhenTheContextIs(t *testing.T) {
	t.Parallel()
	stub := &stubAPI{
		applyBody: revision.FileApplyResult{
			Proposal: revision.Proposal{ID: "rev-1", State: revision.StatePending},
		},
		states: []revision.State{revision.StatePending},
	}
	server := stub.server(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := runPolicy(ctx, []string{
		"apply", "--dir", policyDir(t), "--api", server.URL, "--token", "t",
		"--wait", "--timeout", "1h", "--poll", "5ms",
	}, &strings.Builder{})
	if err == nil {
		t.Fatal("the wait outlived its context")
	}
}
