package revision_test

// filehelper_test.go holds what the file authoring tests need on top of the
// governance harness: a way to put a policy in the store owned by a named
// authoring path, and a way to build a payload the way a directory does.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/policy/revision"
	"github.com/d0lim/stamp/internal/store"
)

// payload builds a payload from alternating name and content arguments.
func payload(pairs ...string) revision.Payload {
	var out revision.Payload
	for i := 0; i+1 < len(pairs); i += 2 {
		out.Documents = append(out.Documents,
			revision.Document{Name: pairs[i], Content: []byte(pairs[i+1])})
	}
	return out
}

// document renders one policy as the exchange-format document a directory
// holds.
func (h *harness) document(p *policy.Policy) string {
	h.t.Helper()
	doc, err := revision.EncodePolicy(p)
	if err != nil {
		h.t.Fatalf("encode policy %s: %v", p.ID, err)
	}
	return doc
}

// schemaDocument renders the tenant schema as its document.
func (h *harness) schemaDocument() string {
	h.t.Helper()
	doc, err := revision.EncodeSchema(tenantSchema())
	if err != nil {
		h.t.Fatalf("encode schema: %v", err)
	}
	return doc
}

// seed puts a policy in the store owned by an authoring path, without going
// through a revision. Governance is not what these tests are establishing; the
// state in force is.
func (h *harness) seed(origin store.Origin, policies ...*policy.Policy) {
	h.t.Helper()
	ctx := context.Background()
	schema, err := store.LatestSchema(ctx, h.store.Pool())
	if err != nil {
		h.t.Fatalf("read latest schema: %v", err)
	}
	for _, p := range policies {
		if _, err := store.PutPolicy(ctx, h.store.Pool(), store.PolicyInput{
			Policy:        p,
			SchemaVersion: schema.Version,
			Origin:        origin,
			Author:        "seed",
		}); err != nil {
			h.t.Fatalf("seed policy %s: %v", p.ID, err)
		}
	}
}

// originOf reports which path owns a policy right now.
func (h *harness) originOf(id string) store.Origin {
	h.t.Helper()
	rec, err := store.EffectivePolicy(context.Background(), h.store.Pool(), id)
	if err != nil {
		h.t.Fatalf("read policy %s: %v", id, err)
	}
	return rec.Origin
}

// writeTree writes an export to a directory, the way the CLI does, and reads it
// back as a payload. The round trip through a real filesystem is the point:
// export → apply has to be a no-op through the medium it actually travels.
func writeTree(t *testing.T, dir string, export revision.Export) revision.Payload {
	t.Helper()
	for _, f := range export.Files {
		target := filepath.Join(dir, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			t.Fatalf("create %s: %v", filepath.Dir(target), err)
		}
		if err := os.WriteFile(target, []byte(f.Content), 0o600); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
	got, err := revision.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the exported tree: %v", err)
	}
	return got
}

// capabilities is a static capability source.
type capabilities map[string][]revision.Capability

func (c capabilities) CapabilitiesOf(_ context.Context, caller *identity.Subject) ([]revision.Capability, error) {
	if caller == nil {
		return nil, nil
	}
	return c[caller.ID], nil
}

// authorCapabilities entitles one identity to author policy.
func authorCapabilities(ids ...string) capabilities {
	out := capabilities{}
	for _, id := range ids {
		out[id] = []revision.Capability{revision.CapabilityAuthor}
	}
	return out
}
