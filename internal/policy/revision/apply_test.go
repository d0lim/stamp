package revision_test

// apply_test.go is the file authoring path against a real store.
//
// The comparison rules themselves are pinned in plan_test.go, where they run
// without a database. What is here is everything that only means something once
// the state in force is real: that the delta reaches the governance pipeline as
// one proposal, that nothing is applied when one document fails, that the
// origin a policy is stored under follows the path that authored it, and that
// an export applies back as nothing at all.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// TestApplyBundlesAModifyAndADeleteIntoOneRevision is AE14: two changes, one
// diff, one quorum, both in force together.
func TestApplyBundlesAModifyAndADeleteIntoOneRevision(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()
	h.seed(store.OriginFile,
		tenantPolicy("file.one", 1, "ann"),
		tenantPolicy("file.two", 1, "ann"),
		tenantPolicy("file.three", 1, "ann"))
	h.lock(1, "ann")

	result, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer: user("ci"),
		Payload: payload(
			"schema.yaml", h.schemaDocument(),
			"one.yaml", h.document(tenantPolicy("file.one", 2, "ann", "bob")),
			"three.yaml", h.document(tenantPolicy("file.three", 1, "ann")),
		),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if result.NoChange {
		t.Fatal("the apply found no change")
	}
	if got := result.Proposal.Delta.Len(); got != 2 {
		t.Fatalf("the proposal carries %d changes, want 2: %v", got, result.Proposal.Delta.PolicyIDs())
	}
	if change, ok := result.Proposal.Delta.Change("file.one"); !ok || change.Kind != revision.ChangeModify {
		t.Errorf("file.one is %q, want a modify", change.Kind)
	}
	if change, ok := result.Proposal.Delta.Change("file.two"); !ok || change.Kind != revision.ChangeDelete {
		t.Errorf("file.two is %q, want a delete", change.Kind)
	}
	if !result.Proposal.Weakening {
		t.Error("a delta carrying a deletion is not classified as weakening")
	}
	if result.Proposal.Origin != store.OriginFile {
		t.Errorf("the proposal's origin is %q, want %q", result.Proposal.Origin, store.OriginFile)
	}

	if err := h.approve(result.Proposal, "ann"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	applied := h.reconcile()
	if len(applied) != 1 {
		t.Fatalf("reconcile applied %d revisions, want 1", len(applied))
	}
	// Both changes take effect, or neither does. There is no state in which the
	// modify landed and the delete is still waiting.
	if _, alive := h.effective("file.two"); alive {
		t.Error("the deleted policy is still in force")
	}
	updated, alive := h.effective("file.one")
	if !alive {
		t.Fatal("the modified policy is gone")
	}
	if quorum, ok := revision.GovernanceQuorum(updated); !ok || quorum.Threshold != 2 {
		t.Errorf("file.one's quorum is %v, want threshold 2", quorum)
	}
	h.verifyChain()
}

// TestApplyRefusesTheWholeSetWhenOneDocumentFails is AE15: no partial apply,
// and no proposal at all.
func TestApplyRefusesTheWholeSetWhenOneDocumentFails(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()

	broken := tenantPolicy("file.broken", 1, "ann")
	broken.Condition = policy.Compare{
		Op:    policy.OpGe,
		Left:  policy.Source("undeclared_source", policy.Field(policy.RoleSubject, "role")),
		Right: policy.Int(1),
	}
	_, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload: payload(
			"schema.yaml", h.schemaDocument(),
			"a.yaml", h.document(tenantPolicy("file.one", 1, "ann")),
			"b.yaml", h.document(tenantPolicy("file.two", 1, "ann")),
			"c.yaml", h.document(tenantPolicy("file.three", 1, "ann")),
			"d.yaml", h.document(tenantPolicy("file.four", 1, "ann")),
			"e.yaml", h.document(broken),
		),
	})
	if !errors.Is(err, revision.ErrInvalidPayload) {
		t.Fatalf("apply = %v, want ErrInvalidPayload", err)
	}
	if !strings.Contains(err.Error(), "undeclared_source") {
		t.Errorf("the refusal does not name the failure: %v", err)
	}
	if _, alive := h.effective("file.one"); alive {
		t.Error("a policy from the refused set is in force; there is no partial apply")
	}
	if _, ok, perr := h.gov.Pending(ctx); perr != nil || ok {
		t.Errorf("a refused apply left a pending revision (err %v)", perr)
	}
}

// TestApplyDoesNotProposeDeletingConsoleAuthoredPolicies is AE25 against the
// store: the default mode, one console policy, two file policies, a directory
// holding only the two.
func TestApplyDoesNotProposeDeletingConsoleAuthoredPolicies(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()
	h.seed(store.OriginForm, tenantPolicy("console.one", 1, "ann"))
	h.seed(store.OriginFile,
		tenantPolicy("file.one", 1, "ann"),
		tenantPolicy("file.two", 1, "ann"))

	result, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload: payload(
			"schema.yaml", h.schemaDocument(),
			"a.yaml", h.document(tenantPolicy("file.one", 1, "ann")),
			"b.yaml", h.document(tenantPolicy("file.two", 1, "ann")),
		),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !result.NoChange {
		t.Fatalf("the apply proposed %v; the delta should be empty", result.Proposal.Delta.PolicyIDs())
	}
	if _, alive := h.effective("console.one"); !alive {
		t.Error("the console-authored policy is gone")
	}
	if _, ok, perr := h.gov.Pending(ctx); perr != nil || ok {
		t.Errorf("an empty delta opened a revision anyway (err %v)", perr)
	}
}

// TestExportThenApplyIsANoOp is the plan's verification gate for this unit, and
// it is run through a real directory because that is the medium the round trip
// actually travels.
//
// The set deliberately mixes origins. A deployment that has only ever used the
// console is the case R48 names, and the export has to carry those policies —
// otherwise the file path starts from an empty directory and the first apply
// proposes deleting nothing while the console's policies stay invisible to it.
func TestExportThenApplyIsANoOp(t *testing.T) {
	h := newHarness(t, harnessOptions{capabilities: authorCapabilities("ann")})
	ctx := context.Background()
	h.seed(store.OriginForm, tenantPolicy("console.one", 1, "ann"), delayPolicy("console.two", 90*60))
	h.seed(store.OriginFile, tenantPolicy("file.one", 2, "ann", "bob"), externalPolicy("file.two", webhookPrimary))

	export, err := h.gov.Export(ctx, revision.ExportRequest{Caller: user("ann")})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if export.PolicyCount != 4 {
		t.Fatalf("the export carries %d policies, want 4", export.PolicyCount)
	}

	applied := writeTree(t, t.TempDir(), export)
	result, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload:        applied,
	})
	if err != nil {
		t.Fatalf("apply the export: %v", err)
	}
	if !result.NoChange {
		t.Fatalf("applying the export proposed %v, want no change", result.Proposal.Delta.PolicyIDs())
	}

	// And the second export is byte-identical to the first: the round trip does
	// not drift on the way back out either.
	again, err := h.gov.Export(ctx, revision.ExportRequest{Caller: user("ann")})
	if err != nil {
		t.Fatalf("second export: %v", err)
	}
	if len(again.Files) != len(export.Files) {
		t.Fatalf("the second export holds %d files, want %d", len(again.Files), len(export.Files))
	}
	for i := range again.Files {
		if again.Files[i] != export.Files[i] {
			t.Errorf("file %q differs between two exports", again.Files[i].Name)
		}
	}
}

// TestApplyRejectsAnOversizedPayloadBeforeParsing is R45's limit. The content
// is not YAML, so a refusal that named the syntax would mean the parser ran.
func TestApplyRejectsAnOversizedPayloadBeforeParsing(t *testing.T) {
	h := newHarness(t, harnessOptions{limits: revision.PayloadLimits{MaxDocumentBytes: 64, MaxDocuments: 3}})
	ctx := context.Background()

	_, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload:        payload("big.yaml", strings.Repeat("[", 65)),
	})
	if !errors.Is(err, revision.ErrPayloadTooLarge) {
		t.Fatalf("apply = %v, want ErrPayloadTooLarge", err)
	}

	_, err = h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload:        payload("a.yaml", "[", "b.yaml", "[", "c.yaml", "[", "d.yaml", "["),
	})
	if !errors.Is(err, revision.ErrPayloadTooLarge) {
		t.Fatalf("apply = %v, want ErrPayloadTooLarge on the document count", err)
	}
}

// TestApplyIsIndifferentToFileLayout is R10 in the comparison: identity is the
// identifier inside the document, so moving a policy between files is not a
// delete and a create.
func TestApplyIsIndifferentToFileLayout(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()
	h.seed(store.OriginFile, tenantPolicy("file.one", 1, "ann"), tenantPolicy("file.two", 1, "ann"))

	result, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		// One file instead of two, under different names, in a subdirectory.
		Payload: payload(
			"schema.yaml", h.schemaDocument(),
			"nested/everything.yaml",
			h.document(tenantPolicy("file.one", 1, "ann"))+"---\n"+h.document(tenantPolicy("file.two", 1, "ann")),
		),
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !result.NoChange {
		t.Fatalf("relaying the same policies through different files proposed %v",
			result.Proposal.Delta.PolicyIDs())
	}
}

// TestApplyMovesOriginOnlyOnADeclaration is AE26's file half: without the
// declaration the edit is a conflict, with it the policy changes hands and the
// handover is an entry in the proposal.
func TestApplyMovesOriginOnlyOnADeclaration(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()
	h.seed(store.OriginForm, tenantPolicy("console.one", 1, "ann"))

	edited := h.document(tenantPolicy("console.one", 2, "ann", "bob"))
	_, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload:        payload("schema.yaml", h.schemaDocument(), "a.yaml", edited),
	})
	if !errors.Is(err, revision.ErrOriginConflict) {
		t.Fatalf("apply = %v, want ErrOriginConflict", err)
	}
	if got := h.originOf("console.one"); got != store.OriginForm {
		t.Fatalf("the refused apply moved the origin to %q", got)
	}

	const adoption = "apiVersion: stamp/v1\nkind: Adoption\npolicies:\n  - console.one\n"
	result, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload: payload(
			"schema.yaml", h.schemaDocument(),
			"a.yaml", edited,
			"adopt.yaml", adoption,
		),
	})
	if err != nil {
		t.Fatalf("apply with the declaration: %v", err)
	}
	change, ok := result.Proposal.Delta.Change("console.one")
	if !ok || change.Kind != revision.ChangeTakeOwnership {
		t.Fatalf("the proposal carries %q, want a take-ownership entry", change.Kind)
	}
	if got := h.state(result.Proposal.ID); got != revision.StateApplied {
		t.Fatalf("the revision is %q, want applied before the lock", got)
	}
	if got := h.originOf("console.one"); got != store.OriginFile {
		t.Errorf("the policy is owned by %q, want %q", got, store.OriginFile)
	}

	// And now the file path owns it: a later apply that drops it is a deletion
	// rather than a conflict.
	dropped, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload:        payload("schema.yaml", h.schemaDocument()),
	})
	if err != nil {
		t.Fatalf("apply an empty directory: %v", err)
	}
	if change, ok := dropped.Proposal.Delta.Change("console.one"); !ok || change.Kind != revision.ChangeDelete {
		t.Errorf("dropping the adopted policy is %q, want a delete", change.Kind)
	}
}

// TestApplyStoresNewPoliciesAsFileAuthored closes the loop the scoping depends
// on. If an apply stored what it created as console-authored, the next apply
// would find it outside its own scope and could never delete it.
func TestApplyStoresNewPoliciesAsFileAuthored(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	ctx := context.Background()

	if _, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload:        payload("schema.yaml", h.schemaDocument(), "a.yaml", h.document(tenantPolicy("file.one", 1, "ann"))),
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := h.originOf("file.one"); got != store.OriginFile {
		t.Fatalf("the created policy is owned by %q, want %q", got, store.OriginFile)
	}

	result, err := h.gov.ApplyFiles(ctx, revision.FileApplyRequest{
		Proposer:       user("ci"),
		BootstrapToken: h.token,
		Payload:        payload("schema.yaml", h.schemaDocument()),
	})
	if err != nil {
		t.Fatalf("apply an empty directory: %v", err)
	}
	if change, ok := result.Proposal.Delta.Change("file.one"); !ok || change.Kind != revision.ChangeDelete {
		t.Errorf("the emptied directory proposed %q for its own policy, want a delete", change.Kind)
	}
	if result.Proposal.Delta.Touches(revision.GovernancePolicyID) {
		t.Error("an empty directory proposed a change to the governance policy")
	}
	if _, alive := h.effective(revision.GovernancePolicyID); !alive {
		t.Error("the governance policy is gone")
	}
}
