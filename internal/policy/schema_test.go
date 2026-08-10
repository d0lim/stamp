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

// TestNormalizeCollapsesEquivalentSpellings pins the property that makes
// structural comparison of two policies meaningful: after normalization, a
// value that means one thing has one shape.
func TestNormalizeCollapsesEquivalentSpellings(t *testing.T) {
	set := &Set{Policies: []Policy{{
		ID: "x",
		Condition: All(
			Compare{
				Left:  SourceRef{Name: "kill_switch", Args: []Operand{}},
				Op:    OpEq,
				Right: Bool(true),
			},
			In(Field(RoleSubject, "id"), Literal{Type: ListOf(TypeString)}),
		),
		Challenges: []Challenge{
			Quorum{Threshold: 1, Approvers: ApproverSet{
				Source: &SourceRef{Name: "everyone", Args: []Operand{}},
			}},
		},
	}}}
	set.Normalize()

	logic := set.Policies[0].Condition.(Logic)
	if args := logic.Operands[0].(Compare).Left.(SourceRef).Args; args != nil {
		t.Errorf("an empty argument list should normalize to none, got %#v", args)
	}
	if data := logic.Operands[1].(Member).Collection.(Literal).Data; data == nil {
		t.Error("a list literal should always carry a slice, even an empty one")
	}
	if args := set.Policies[0].Challenges[0].(Quorum).Approvers.Source.Args; args != nil {
		t.Errorf("an approver source's empty argument list should normalize to none, got %#v", args)
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

// TestRequiresDecision pins the predicate U3 asks for. The invariant that a
// policy carrying challenges can never be allowed on the check path has to read
// "does this policy require a decision" from one place; if each caller derived
// it separately, one of them would eventually derive it differently.
func TestRequiresDecision(t *testing.T) {
	set := sampleSet()
	plain, ok := set.Policy("always-review-rejections")
	if !ok {
		t.Fatal("missing policy")
	}
	if plain.RequiresDecision() {
		t.Error("a policy with no challenges must not require a decision")
	}
	guarded, ok := set.Policy("high-value-transfer")
	if !ok {
		t.Fatal("missing policy")
	}
	if !guarded.RequiresDecision() {
		t.Error("a policy carrying challenges must require a decision")
	}
	// Every challenge kind on its own is enough.
	for _, c := range []Challenge{
		Quorum{}, MFA{}, Delay{}, External{},
	} {
		p := &Policy{Challenges: []Challenge{c}}
		if !p.RequiresDecision() {
			t.Errorf("a %s challenge must require a decision", c.ChallengeType())
		}
	}
}

// TestChallengeSetIsClosed pins the challenge inventory to the four kinds v1
// fixes. Adding a fifth is a change to the public challenge contract, not an
// implementation detail.
func TestChallengeSetIsClosed(t *testing.T) {
	kinds := ChallengeTypes()
	if len(kinds) != 4 {
		t.Fatalf("the challenge inventory changed: %v", kinds)
	}
	implementations := []Challenge{Quorum{}, MFA{}, Delay{}, External{}}
	for i, c := range implementations {
		if c.ChallengeType() != kinds[i] {
			t.Errorf("%T reports %q, expected %q", c, c.ChallengeType(), kinds[i])
		}
		if !c.ChallengeType().Valid() {
			t.Errorf("%q should be a valid challenge type", c.ChallengeType())
		}
	}
	if ChallengeType("webauthn").Valid() {
		t.Error("an invented challenge type should not be valid")
	}
}

func TestNormalizeSortsChallengesAndFillsMFAMode(t *testing.T) {
	p := Policy{ID: "x", Challenges: []Challenge{
		External{Target: "b"},
		MFA{},
		External{Target: "a"},
		Quorum{Threshold: 1},
	}}
	set := &Set{Policies: []Policy{p}}
	set.Normalize()

	got := set.Policies[0].Challenges
	want := []ChallengeType{ChallengeQuorum, ChallengeMFA, ChallengeExternal, ChallengeExternal}
	for i, kind := range want {
		if got[i].ChallengeType() != kind {
			t.Fatalf("challenge %d: want %q, got %q", i, kind, got[i].ChallengeType())
		}
	}
	// Sorting is stable, so two declarations of the same kind keep their order.
	if got[2].(External).Target != "b" || got[3].(External).Target != "a" {
		t.Errorf("same-kind challenges were reordered: %v", got)
	}
	if mode := got[1].(MFA).Mode; mode != DefaultMFAMode {
		t.Errorf("mfa mode default: want %q, got %q", DefaultMFAMode, mode)
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
