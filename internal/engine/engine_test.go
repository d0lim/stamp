package engine

import (
	"context"
	"testing"
	"time"

	"github.com/d0lim/stamp/internal/policy"
)

// testSchema is the schema every fixture in this package is written against. It
// declares one attribute of each policy type so that a condition can exercise
// every AST node without a second schema.
func testSchema() policy.Schema {
	return policy.Schema{
		Entities: []policy.EntityType{
			{Name: "user", Attributes: []policy.Attribute{
				{Name: "admin", Type: policy.TypeBool},
				{Name: "dept", Type: policy.TypeString},
				{Name: "joined", Type: policy.TypeTimestamp},
				{Name: "level", Type: policy.TypeInt},
				{Name: "score", Type: policy.TypeDouble},
				{Name: "tags", Type: policy.ListOf(policy.TypeString)},
				{Name: "tenure", Type: policy.TypeDuration},
			}},
			{Name: "doc", Attributes: []policy.Attribute{
				{Name: "amount", Type: policy.TypeInt},
				{Name: "labels", Type: policy.ListOf(policy.TypeString)},
				{Name: "owner", Type: policy.TypeString},
			}},
			{Name: "env", Attributes: []policy.Attribute{
				{Name: "hour", Type: policy.TypeInt},
			}},
		},
		Actions: []policy.Action{{Name: "read"}, {Name: "write"}},
		Sources: []policy.SourceDecl{
			{
				Name:    "groups",
				Kind:    policy.SourceStatic,
				Params:  []policy.Param{{Name: "dept", Type: policy.TypeString}},
				Returns: policy.ListOf(policy.TypeString),
			},
			{
				Name:    "risk",
				Kind:    policy.SourceHTTP,
				Params:  []policy.Param{{Name: "owner", Type: policy.TypeString}},
				Returns: policy.TypeInt,
			},
		},
	}
}

// newTestSet validates a schema and policies together, so a broken fixture
// fails as a fixture rather than as a mysterious evaluation result.
//
// Normalize rewrites the condition tree in place, so a condition value must not
// be shared between two calls that could run at the same time. Table-driven
// tests that hold their conditions in a slice therefore run their cases
// sequentially.
func newTestSet(t *testing.T, policies ...policy.Policy) *policy.Set {
	t.Helper()
	set := &policy.Set{Schema: testSchema(), Policies: policies}
	set.Normalize()
	if diags := policy.Validate(set); len(diags) > 0 {
		t.Fatalf("fixture does not validate:\n%s", diags.Error())
	}
	return set
}

// newTestSnapshot builds a snapshot whose versions are derived from the policy
// identifiers, which is enough for tests that are not about versioning.
func newTestSnapshot(t *testing.T, policies ...policy.Policy) *Snapshot {
	t.Helper()
	set := newTestSet(t, policies...)
	versions := make([]PolicyVersion, len(set.Policies))
	for i := range set.Policies {
		versions[i] = PolicyVersion{Version: set.Policies[i].ID + "@1", Policy: set.Policies[i]}
	}
	snap, err := NewSnapshot("schema@1", set.Schema, versions)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	return snap
}

// ungated is a policy with no challenge: the check path may allow it.
func ungated(id string, condition policy.Node) policy.Policy {
	return policy.Policy{
		ID: id, Subject: "user", Resource: "doc", Context: "env",
		Actions: []string{"read"}, Condition: condition,
	}
}

// gated is the same policy carrying a challenge, which is what makes it
// unreachable by the check path.
func gated(id string, condition policy.Node, challenges ...policy.Challenge) policy.Policy {
	p := ungated(id, condition)
	if len(challenges) == 0 {
		challenges = []policy.Challenge{policy.MFA{Mode: policy.MFADelegated, ACRValues: []string{"urn:acr:mfa"}}}
	}
	p.Challenges = challenges
	return p
}

// resolverFunc adapts a function to SourceResolver.
type resolverFunc func(ctx context.Context, calls []SourceCall) (*Facts, error)

// ResolveSources implements SourceResolver.
func (f resolverFunc) ResolveSources(ctx context.Context, calls []SourceCall) (*Facts, error) {
	return f(ctx, calls)
}

// staticResolver answers every call from a table keyed by the call's rendered
// form, and counts how many batches it was asked for.
type staticResolver struct {
	values  map[string]any
	batches int
	calls   int
}

// ResolveSources implements SourceResolver.
func (r *staticResolver) ResolveSources(_ context.Context, calls []SourceCall) (*Facts, error) {
	r.batches++
	r.calls += len(calls)
	facts := NewFacts()
	for _, c := range calls {
		if v, ok := r.values[c.String()]; ok {
			facts.Set(c, v)
		}
	}
	return facts, nil
}

// baseInput is a well-formed request that matches the fixture policies.
func baseInput() Input {
	return Input{
		Action: "read",
		Subject: Entity{Type: "user", ID: "u1", Attributes: map[string]any{
			"admin":  false,
			"dept":   "eng",
			"joined": time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			"level":  int64(3),
			"score":  1.5,
			"tags":   []string{"a", "b"},
			"tenure": 48 * time.Hour,
		}},
		Resource: Entity{Type: "doc", ID: "d1", Attributes: map[string]any{
			"amount": int64(10),
			"labels": []string{"public"},
			"owner":  "u1",
		}},
		Context: Entity{Type: "env", ID: "e1", Attributes: map[string]any{
			"hour": int64(9),
		}},
	}
}
