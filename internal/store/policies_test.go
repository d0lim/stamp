package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

func TestPolicyVersionsAccumulateAndOneStaysLive(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)

	first := seedPolicy(t, s, "wire-transfer")
	if first.Version != 1 {
		t.Fatalf("first version = %d, want 1", first.Version)
	}
	second := seedPolicy(t, s, "wire-transfer", policy.Delay{Duration: time.Hour})
	if second.Version != 2 {
		t.Fatalf("second version = %d, want 2", second.Version)
	}

	live, err := store.EffectivePolicy(ctx, s.Pool(), "wire-transfer")
	if err != nil {
		t.Fatalf("effective policy: %v", err)
	}
	if live.Version != 2 {
		t.Fatalf("live version = %d, want 2", live.Version)
	}
	if !live.RequiresDecision {
		t.Fatal("a policy carrying a challenge was not recorded as requiring a decision")
	}

	versions, err := store.PolicyVersions(ctx, s.Pool(), "wire-transfer")
	if err != nil {
		t.Fatalf("policy versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("stored %d versions, want 2", len(versions))
	}
	if versions[0].SupersededAt == nil {
		t.Fatal("the replaced version was not marked superseded")
	}

	// The stored document is the artifact that was validated, and it decodes
	// back into the policy it came from.
	back, err := live.Policy()
	if err != nil {
		t.Fatalf("decode stored policy: %v", err)
	}
	if back.ID != "wire-transfer" || len(back.Challenges) != 1 {
		t.Fatalf("decoded policy = %+v, want wire-transfer with one challenge", back)
	}
}

// The authoring origin decides which path owns a policy. A silent move is what
// makes the next file apply propose deleting everything the console authored.
func TestOriginTransferMustBeDeclared(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	rec := seedPolicy(t, s, "wire-transfer")
	if rec.Origin != store.OriginForm {
		t.Fatalf("origin = %q, want %q", rec.Origin, store.OriginForm)
	}

	p, err := rec.Policy()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	_, err = store.PutPolicy(ctx, s.Pool(), store.PolicyInput{
		Policy: p, SchemaVersion: rec.SchemaVersion, Origin: store.OriginFile, Author: "ci",
	})
	if !errors.Is(err, store.ErrOriginTransfer) {
		t.Fatalf("an undeclared origin move returned %v, want ErrOriginTransfer", err)
	}

	moved, err := store.PutPolicy(ctx, s.Pool(), store.PolicyInput{
		Policy: p, SchemaVersion: rec.SchemaVersion, Origin: store.OriginFile,
		Author: "ci", AssumeOwnership: true,
	})
	if err != nil {
		t.Fatalf("a declared handover was refused: %v", err)
	}
	if moved.Origin != store.OriginFile {
		t.Fatalf("origin after handover = %q, want %q", moved.Origin, store.OriginFile)
	}
}

func TestEffectivePoliciesFilterByOrigin(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	seedPolicy(t, s, "from-console")

	latest, err := store.LatestSchema(ctx, s.Pool())
	if err != nil {
		t.Fatalf("latest schema: %v", err)
	}
	filePolicy := &policy.Policy{
		ID: "from-file", Subject: "user", Resource: "account", Actions: []string{"transfer"},
		Condition: policy.Compare{Op: policy.OpEq, Left: policy.Field(policy.RoleSubject, "role"), Right: policy.String("ops")},
	}
	if _, err := store.PutPolicy(ctx, s.Pool(), store.PolicyInput{
		Policy: filePolicy, SchemaVersion: latest.Version, Origin: store.OriginFile, Author: "ci",
	}); err != nil {
		t.Fatalf("put file policy: %v", err)
	}

	all, err := store.EffectivePolicies(ctx, s.Pool())
	if err != nil {
		t.Fatalf("effective policies: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d effective policies, want 2", len(all))
	}
	fileOnly, err := store.EffectivePolicies(ctx, s.Pool(), store.OriginFile)
	if err != nil {
		t.Fatalf("effective file policies: %v", err)
	}
	if len(fileOnly) != 1 || fileOnly[0].ID != "from-file" {
		t.Fatalf("file-scoped set = %+v, want only from-file", fileOnly)
	}
}

func TestDeletedPolicyKeepsItsHistory(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	rec := seedPolicy(t, s, "wire-transfer")

	tomb, err := store.DeletePolicy(ctx, s.Pool(), "wire-transfer", "operator")
	if err != nil {
		t.Fatalf("delete policy: %v", err)
	}
	if !tomb.Deleted || tomb.Version != rec.Version+1 {
		t.Fatalf("tombstone = %+v, want a deleted version %d", tomb, rec.Version+1)
	}

	// The version a past decision points at still resolves.
	old, err := store.GetPolicy(ctx, s.Pool(), "wire-transfer", rec.Version)
	if err != nil {
		t.Fatalf("the deleted policy's history is gone: %v", err)
	}
	if old.Deleted {
		t.Fatal("deleting rewrote the historical version")
	}

	live, err := store.EffectivePolicies(ctx, s.Pool())
	if err != nil {
		t.Fatalf("effective policies: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("a deleted policy is still in the effective set: %+v", live)
	}
}

// The check path loads the whole live set, so this is the read it makes.
func TestLoadEffectiveSetRoundTripsThroughTheExchangeFormat(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	seedPolicy(t, s, "a-policy")
	seedPolicy(t, s, "b-policy", policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{"urn:acr:strong"}})

	set, schemaVersion, err := store.LoadEffectiveSet(ctx, s.Pool())
	if err != nil {
		t.Fatalf("load effective set: %v", err)
	}
	if schemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", schemaVersion)
	}
	if len(set.Policies) != 2 {
		t.Fatalf("loaded %d policies, want 2", len(set.Policies))
	}
	if len(set.Schema.Entities) != 2 {
		t.Fatalf("loaded %d entity types, want 2", len(set.Schema.Entities))
	}
	// The loaded set must pass the same validator that admitted it.
	if diags := policy.Validate(set); len(diags) != 0 {
		t.Fatalf("the stored set no longer validates: %v", diags)
	}
}

func TestUnknownPolicyIsNotFound(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	if _, err := store.EffectivePolicy(ctx, s.Pool(), "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
	if _, err := store.LatestSchema(ctx, s.Pool()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestPolicyOriginIsConstrainedBySchema(t *testing.T) {
	ctx := context.Background()
	s, _ := migratedStore(t)
	seedPolicy(t, s, "wire-transfer")

	_, err := s.Pool().Exec(ctx, `UPDATE policies SET origin = 'smuggled' WHERE id = 'wire-transfer'`)
	if err == nil {
		t.Fatal("the schema accepted an unknown authoring origin")
	}
}
