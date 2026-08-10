package fact

import (
	"context"
	"testing"

	"github.com/d0lim/stamp/internal/policy"
)

// AE1, R13: the running example. A whitelisted account resolves immediately and
// without leaving the process; an unlisted one simply is not in the list.
func TestStaticListAnswersFromTheDeclaration(t *testing.T) {
	r, err := NewRegistry([]Declaration{staticWhitelist("acct-x", "acct-z")}, Config{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	v, err := r.Lookup(context.Background(), "account_whitelist")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if err := v.CheckType(policy.ListOf(policy.TypeString)); err != nil {
		t.Fatalf("returned value does not match the declared type: %v", err)
	}
	items := v.Data.([]any)
	if len(items) != 2 || items[0] != "acct-x" || items[1] != "acct-z" {
		t.Fatalf("value = %#v", v.Data)
	}
}

func TestStaticListPreservesAnEmptyList(t *testing.T) {
	r, err := NewRegistry([]Declaration{staticWhitelist()}, Config{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	v, err := r.Lookup(context.Background(), "account_whitelist")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	items, ok := v.Data.([]any)
	if !ok || len(items) != 0 {
		t.Fatalf("value = %#v, want an empty list rather than a nil one", v.Data)
	}
}

// The declaration is deployment configuration, and an evaluation must not be
// able to edit it through the value it was handed.
func TestStaticListIsNotReachableThroughItsResult(t *testing.T) {
	decl := staticWhitelist("acct-x")
	r, err := NewRegistry([]Declaration{decl}, Config{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	first, err := r.Lookup(context.Background(), "account_whitelist")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	first.Data.([]any)[0] = "acct-attacker"
	decl.Values[0] = "acct-also-attacker"

	second, err := r.Lookup(context.Background(), "account_whitelist")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if second.Data.([]any)[0] != "acct-x" {
		t.Fatalf("the declared list was edited from outside: %#v", second.Data)
	}
}

// A static source never leaves the process, so it never needs a cache entry —
// and it must not consume one, because the cache is a bounded resource shared
// with the sources that do.
func TestStaticListDoesNotOccupyTheCache(t *testing.T) {
	r, err := NewRegistry([]Declaration{staticWhitelist("acct-x")}, Config{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(r.Close)

	for i := 0; i < 3; i++ {
		if _, err := r.Lookup(context.Background(), "account_whitelist"); err != nil {
			t.Fatalf("Lookup: %v", err)
		}
	}
	if got := r.cache.len(); got != 0 {
		t.Fatalf("cache holds %d entries for a source that cannot go stale", got)
	}
}

func TestStaticListAcceptsEveryScalarElementType(t *testing.T) {
	tests := []struct {
		elem   policy.Type
		values []any
	}{
		{policy.TypeString, []any{"a"}},
		{policy.TypeInt, []any{int64(1)}},
		{policy.TypeDouble, []any{1.5}},
		{policy.TypeBool, []any{true}},
	}
	for _, tc := range tests {
		t.Run(string(tc.elem), func(t *testing.T) {
			decl := staticWhitelist(tc.values...)
			decl.Returns = policy.ListOf(tc.elem)
			r, err := NewRegistry([]Declaration{decl}, Config{})
			if err != nil {
				t.Fatalf("NewRegistry: %v", err)
			}
			t.Cleanup(r.Close)
			if _, err := r.Lookup(context.Background(), "account_whitelist"); err != nil {
				t.Fatalf("Lookup: %v", err)
			}
		})
	}
}
