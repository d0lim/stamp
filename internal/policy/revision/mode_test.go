package revision_test

// mode_test.go is R49: the operator closes one authoring path, and the refusal
// is the API's rather than the interface's.
//
// The second half of every case here is the part that matters more than the
// first. Whichever path is closed, the lock still works — an operator who
// enabled `file` mode at install time and then found the lock switched off with
// the console's authoring module would be stuck in solo-admin governance with
// no way out except the offline break-glass procedure.

import (
	"context"
	"errors"
	"testing"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

func TestFileModeClosesConsoleAuthoringAndLeavesTheLock(t *testing.T) {
	h := newHarness(t, harnessOptions{authoring: revision.AuthoringFile})
	ctx := context.Background()

	_, err := h.gov.Propose(ctx, revision.ProposeRequest{
		Proposer:       user("ann"),
		Delta:          revision.Single(nil, tenantPolicy("form.new", 1, "ann")),
		BootstrapToken: h.token,
	})
	if !errors.Is(err, revision.ErrAuthoringLocked) {
		t.Fatalf("a console submission in file mode = %v, want ErrAuthoringLocked", err)
	}

	// The file path still writes.
	if _, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload:        payload("schema.yaml", h.schemaDocument(), "a.yaml", h.document(tenantPolicy("file.one", 1, "ann"))),
	}); err != nil {
		t.Fatalf("apply in file mode: %v", err)
	}

	// And the lock is not an authoring action. It works in every mode, which is
	// what keeps an operator from being locked into solo-admin governance.
	if err := h.gov.Lock(ctx, revision.LockRequest{
		Actor: user("root"),
		Token: h.token,
		Quorum: policy.Quorum{
			Threshold: 2, Approvers: policy.ApproverSet{Members: []string{"ann", "bob", "cid"}},
		},
	}); err != nil {
		t.Fatalf("lock in file mode: %v", err)
	}
	if got := h.mode(); got != revision.ModeQuorum {
		t.Errorf("governance is %q, want %q", got, revision.ModeQuorum)
	}
}

func TestConsoleModeClosesTheApplyAndLeavesTheLock(t *testing.T) {
	h := newHarness(t, harnessOptions{authoring: revision.AuthoringConsole})
	ctx := context.Background()

	_, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload:        payload("schema.yaml", h.schemaDocument(), "a.yaml", h.document(tenantPolicy("file.one", 1, "ann"))),
	})
	if !errors.Is(err, revision.ErrAuthoringLocked) {
		t.Fatalf("an apply in console mode = %v, want ErrAuthoringLocked", err)
	}
	// The refusal is at the door: nothing was parsed and nothing was written.
	if _, alive := h.effective("file.one"); alive {
		t.Error("the refused apply wrote a policy")
	}

	if _, err := h.gov.Propose(ctx, revision.ProposeRequest{
		Proposer:       user("ann"),
		Delta:          revision.Single(nil, tenantPolicy("form.new", 1, "ann")),
		Origin:         store.OriginForm,
		BootstrapToken: h.token,
	}); err != nil {
		t.Fatalf("a console submission in console mode: %v", err)
	}

	if err := h.gov.Lock(ctx, revision.LockRequest{
		Actor:  user("root"),
		Token:  h.token,
		Quorum: policy.Quorum{Threshold: 1, Approvers: policy.ApproverSet{Members: []string{"ann"}}},
	}); err != nil {
		t.Fatalf("lock in console mode: %v", err)
	}
}

func TestBothModeIsTheDefaultAndAdmitsEitherPath(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()
	if got := h.gov.AuthoringMode(); got != revision.AuthoringBoth {
		t.Fatalf("the default authoring mode is %q, want %q", got, revision.AuthoringBoth)
	}

	if _, err := h.gov.Propose(ctx, revision.ProposeRequest{
		Proposer:       user("ann"),
		Delta:          revision.Single(nil, tenantPolicy("form.new", 1, "ann")),
		BootstrapToken: h.token,
	}); err != nil {
		t.Fatalf("console submission: %v", err)
	}
	if _, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload:        payload("schema.yaml", h.schemaDocument(), "a.yaml", h.document(tenantPolicy("file.one", 1, "ann"))),
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Each path owns what it authored, which is the whole of what `both` means.
	if got := h.originOf("form.new"); got != store.OriginForm {
		t.Errorf("the console policy is owned by %q", got)
	}
	if got := h.originOf("file.one"); got != store.OriginFile {
		t.Errorf("the file policy is owned by %q", got)
	}
}

func TestUnknownAuthoringModeIsRefusedAtConstruction(t *testing.T) {
	t.Parallel()
	if _, err := revision.ParseAuthoringMode("gitops"); err == nil {
		t.Fatal("an unknown authoring mode parsed without complaint")
	}
	if m, err := revision.ParseAuthoringMode(""); err != nil || m != revision.AuthoringBoth {
		t.Errorf("the empty mode is (%q, %v), want %q", m, err, revision.AuthoringBoth)
	}
}
