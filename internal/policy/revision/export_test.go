package revision_test

// export_test.go is R48's access half.
//
// The export is a read of the whole policy set in one response — every approver
// identity, every threshold, every external target — so it is treated as one:
// an authenticated caller, a capability, and a record either way.

import (
	"context"
	"errors"
	"testing"

	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

func TestExportRequiresAnAuthoringOrAuditCapability(t *testing.T) {
	h := newHarness(t, harnessOptions{capabilities: capabilities{
		"ann":     {revision.CapabilityAuthor},
		"auditor": {revision.CapabilityAudit},
		"nobody":  {"decisions.read"},
	}})
	ctx := context.Background()
	h.seed(store.OriginForm, tenantPolicy("console.one", 1, "ann"))

	if _, err := h.gov.Export(ctx, revision.ExportRequest{Caller: user("ann")}); err != nil {
		t.Errorf("an authoring caller was refused: %v", err)
	}
	if _, err := h.gov.Export(ctx, revision.ExportRequest{Caller: user("auditor")}); err != nil {
		t.Errorf("an audit caller was refused: %v", err)
	}

	_, err := h.gov.Export(ctx, revision.ExportRequest{Caller: user("nobody")})
	if !errors.Is(err, revision.ErrExportForbidden) {
		t.Fatalf("export = %v, want ErrExportForbidden", err)
	}
	// A refusal that left no trace would be indistinguishable from a request
	// nobody made, and the request being refused is exactly the reconnaissance
	// attempt somebody would want to see.
	refusals := h.auditPayloads(revision.AuditKindPolicyExportRefused)
	if len(refusals) != 1 {
		t.Fatalf("the refusal left %d audit records, want 1", len(refusals))
	}
	if refusals[0]["caller"] != user("nobody").CallerID() {
		t.Errorf("the refusal record names %v, want %q", refusals[0]["caller"], user("nobody").CallerID())
	}
	h.verifyChain()
}

func TestExportWithNoCapabilitySourceRefusesEveryone(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	_, err := h.gov.Export(context.Background(), revision.ExportRequest{Caller: user("ann")})
	if !errors.Is(err, revision.ErrExportForbidden) {
		t.Fatalf("export on an installation with no capability source = %v, want ErrExportForbidden", err)
	}
}

func TestExportRecordsTheCallerAndTheCount(t *testing.T) {
	h := newHarness(t, harnessOptions{capabilities: authorCapabilities("ann")})
	ctx := context.Background()
	h.seed(store.OriginForm, tenantPolicy("console.one", 1, "ann"))
	h.seed(store.OriginFile, tenantPolicy("file.one", 1, "ann"))

	export, err := h.gov.Export(ctx, revision.ExportRequest{Caller: user("ann")})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if export.PolicyCount != 2 {
		t.Errorf("the export carries %d policies, want 2", export.PolicyCount)
	}
	// The reserved governance policy is not in it: it is written against its own
	// schema and cannot be authored from a file, so exporting it would produce a
	// directory that does not apply.
	for _, f := range export.Files {
		if f.Name == "policies/"+revision.GovernancePolicyID+".yaml" {
			t.Error("the export carries the reserved governance policy")
		}
	}

	records := h.auditPayloads(revision.AuditKindPolicyExported)
	if len(records) != 1 {
		t.Fatalf("the export left %d audit records, want 1", len(records))
	}
	if records[0]["caller"] != user("ann").CallerID() {
		t.Errorf("the record names %v, want %q", records[0]["caller"], user("ann").CallerID())
	}
	if records[0]["policy_count"] != float64(2) {
		t.Errorf("the record counts %v policies, want 2", records[0]["policy_count"])
	}
}

func TestExportRefusesAnUnauthenticatedCaller(t *testing.T) {
	h := newHarness(t, harnessOptions{capabilities: authorCapabilities("ann")})
	if _, err := h.gov.Export(context.Background(), revision.ExportRequest{}); err == nil {
		t.Fatal("an export with no caller succeeded")
	}
}
