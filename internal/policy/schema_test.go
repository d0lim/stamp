package policy

import (
	"reflect"
	"testing"
)

func TestTypeHelpers(t *testing.T) {
	cases := []struct {
		t       Type
		list    bool
		elem    Type
		valid   bool
		ordered bool
	}{
		{TypeString, false, "", true, true},
		{TypeBool, false, "", true, false},
		{TypeTimestamp, false, "", true, true},
		{TypeDuration, false, "", true, true},
		{ListOf(TypeInt), true, TypeInt, true, false},
		{ListOf(ListOf(TypeInt)), true, ListOf(TypeInt), false, false},
		{"text", false, "", false, false},
		{"list<text>", true, "text", false, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.t), func(t *testing.T) {
			if got := tc.t.IsList(); got != tc.list {
				t.Errorf("IsList: want %v, got %v", tc.list, got)
			}
			if got := tc.t.Elem(); got != tc.elem {
				t.Errorf("Elem: want %q, got %q", tc.elem, got)
			}
			if got := tc.t.Valid(); got != tc.valid {
				t.Errorf("Valid: want %v, got %v", tc.valid, got)
			}
			if got := tc.t.IsOrdered(); got != tc.ordered {
				t.Errorf("IsOrdered: want %v, got %v", tc.ordered, got)
			}
		})
	}
}

func TestNormalizeSortsAndFillsDefaults(t *testing.T) {
	set := &Set{
		Schema: Schema{
			Entities: []EntityType{
				{Name: "zeta", Attributes: []Attribute{{Name: "b", Type: TypeInt}, {Name: "a", Type: TypeInt}}},
				{Name: "alpha"},
			},
			Actions: []Action{{Name: "write"}, {Name: "read"}},
			Sources: []SourceDecl{
				{Name: "two", Kind: SourceStatic, Returns: TypeBool},
				{Name: "one", Kind: SourceStatic, Returns: TypeBool, OnError: OnErrorAllow,
					Params: []Param{{Name: "z", Type: TypeString}, {Name: "a", Type: TypeString}}},
			},
		},
		Policies: []Policy{
			{ID: "second", Actions: []string{"write", "read"}},
			{ID: "first"},
		},
	}
	set.Normalize()

	if set.Schema.Entities[0].Name != "alpha" || set.Schema.Entities[1].Name != "zeta" {
		t.Errorf("entities were not sorted: %v", set.Schema.Entities)
	}
	if set.Schema.Entities[1].Attributes[0].Name != "a" {
		t.Errorf("attributes were not sorted: %v", set.Schema.Entities[1].Attributes)
	}
	if set.Schema.Actions[0].Name != "read" {
		t.Errorf("actions were not sorted: %v", set.Schema.Actions)
	}
	if set.Schema.Sources[0].Name != "one" {
		t.Errorf("sources were not sorted: %v", set.Schema.Sources)
	}
	// Parameter order is the calling convention, so it must survive intact.
	if got := set.Schema.Sources[0].Params; got[0].Name != "z" || got[1].Name != "a" {
		t.Errorf("source parameters were reordered: %v", got)
	}
	// The omitted failure behaviour is filled in; the explicit one is left alone.
	if set.Schema.Sources[0].OnError != OnErrorAllow {
		t.Errorf("explicit on_error was overwritten: %q", set.Schema.Sources[0].OnError)
	}
	if set.Schema.Sources[1].OnError != DefaultOnError {
		t.Errorf("default on_error: want %q, got %q", DefaultOnError, set.Schema.Sources[1].OnError)
	}
	if set.Policies[0].ID != "first" {
		t.Errorf("policies were not sorted: %v", set.Policies)
	}
	if !reflect.DeepEqual(set.Policies[1].Actions, []string{"read", "write"}) {
		t.Errorf("policy actions were not sorted: %v", set.Policies[1].Actions)
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	once := sampleSet()
	twice := sampleSet()
	twice.Normalize()
	if !reflect.DeepEqual(once, twice) {
		t.Fatal("normalizing an already normalized set changed it")
	}
}

func TestSchemaLookups(t *testing.T) {
	set := sampleSet()
	entity, ok := set.Schema.Entity("transfer")
	if !ok {
		t.Fatal("transfer is declared but was not found")
	}
	if _, ok := entity.Attribute("amount"); !ok {
		t.Error("transfer.amount is declared but was not found")
	}
	if _, ok := entity.Attribute("nonexistent"); ok {
		t.Error("an undeclared attribute was found")
	}
	if _, ok := set.Schema.Source("daily_total"); !ok {
		t.Error("daily_total is declared but was not found")
	}
	if !set.Schema.HasAction("approve") {
		t.Error("approve is declared but was not found")
	}
	if _, ok := set.Policy("high-value-transfer"); !ok {
		t.Error("policy lookup by identifier failed")
	}
}

func TestPolicyEntityForUnboundContext(t *testing.T) {
	p := &Policy{Subject: "user", Resource: "doc"}
	if name, bound := p.EntityFor(RoleSubject); !bound || name != "user" {
		t.Errorf("subject: got %q %v", name, bound)
	}
	if _, bound := p.EntityFor(RoleContext); bound {
		t.Error("context should be unbound when the policy does not declare it")
	}
	if _, bound := p.EntityFor("nonsense"); bound {
		t.Error("an unknown role should never be bound")
	}
}

func TestNameSyntax(t *testing.T) {
	for _, name := range []string{"user", "daily_total", "a1"} {
		if !ValidIdent(name) {
			t.Errorf("%q should be a valid identifier", name)
		}
	}
	for _, name := range []string{"User", "1a", "with-dash", "with.dot", "", "with space"} {
		if ValidIdent(name) {
			t.Errorf("%q should not be a valid identifier", name)
		}
	}
	for _, name := range []string{"high-value-transfer", "read", "can.read", "v1"} {
		if !ValidName(name) {
			t.Errorf("%q should be a valid name", name)
		}
	}
	for _, name := range []string{"", "-leading", "Upper", "with space"} {
		if ValidName(name) {
			t.Errorf("%q should not be a valid name", name)
		}
	}
}
