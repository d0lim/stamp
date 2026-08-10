package policy

import (
	"errors"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestUndeclaredSourceIsRejectedAtLoad(t *testing.T) {
	doc := `apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes: {id: string}
  - name: doc
    attributes: {level: int}
actions: [read]
---
apiVersion: stamp/v1
kind: Policy
id: reads-a-ghost
subject: user
resource: doc
actions: [read]
condition:
  left: {source: seen_recently, args: [{field: subject.id}]}
  op: eq
  right: true
`
	_, err := Load(strings.NewReader(doc))
	if err == nil {
		t.Fatal("a policy referencing an undeclared source must not load")
	}
	var diags Diagnostics
	if !errors.As(err, &diags) {
		t.Fatalf("expected structured diagnostics, got %T: %v", err, err)
	}
	if len(diags) != 1 {
		t.Fatalf("expected exactly one diagnostic, got %v", diags)
	}
	d := diags[0]
	if d.Pointer != "/policies/0/condition/left" {
		t.Errorf("pointer: want /policies/0/condition/left, got %q", d.Pointer)
	}
	if d.Code != CodeUnknownSource {
		t.Errorf("code: want %q, got %q", CodeUnknownSource, d.Code)
	}
	if !strings.Contains(d.Message, "seen_recently") {
		t.Errorf("message should name the source, got %q", d.Message)
	}
}

func TestTypeMismatchedPolicyIsRejectedAtLoad(t *testing.T) {
	const preamble = `apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes: {id: string, seniority: int}
  - name: doc
    attributes: {level: int, amount: double, tags: list<string>}
actions: [read]
sources:
  - name: daily_total
    kind: event
    params:
      - account_id: string
    returns: double
---
apiVersion: stamp/v1
kind: Policy
id: mismatched
subject: user
resource: doc
actions: [read]
condition:
`
	cases := map[string]struct {
		condition string
		pointer   string
		code      Code
	}{
		"int against string": {
			"  left: {field: resource.level}\n  op: eq\n  right: three\n",
			"/policies/0/condition/right", CodeTypeMismatch,
		},
		"int against double": {
			"  left: {field: resource.amount}\n  op: gt\n  right: 10\n",
			"/policies/0/condition/right", CodeTypeMismatch,
		},
		"ordering on bool": {
			"  left: {field: resource.level}\n  op: gt\n  right: {value: 1, type: int}\n",
			"", "",
		},
		"membership in a scalar": {
			"  left: {field: resource.level}\n  in: {field: resource.amount}\n",
			"/policies/0/condition/in", CodeTypeMismatch,
		},
		"membership element type": {
			"  left: {field: resource.level}\n  in: [a, b]\n",
			"/policies/0/condition/in", CodeTypeMismatch,
		},
		"undeclared attribute": {
			"  left: {field: resource.owner}\n  op: eq\n  right: alice\n",
			"/policies/0/condition/left", CodeUnknownAttribute,
		},
		"unbound role": {
			"  left: {field: context.ip}\n  op: eq\n  right: 10.0.0.1\n",
			"/policies/0/condition/left", CodeUnboundRole,
		},
		"source argument type": {
			"  left: {source: daily_total, args: [{field: subject.seniority}]}\n  op: gt\n  right: 1.0\n",
			"/policies/0/condition/left/args/0", CodeTypeMismatch,
		},
		"source arity": {
			"  left: {source: daily_total}\n  op: gt\n  right: 1.0\n",
			"/policies/0/condition/left", CodeArityMismatch,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(strings.NewReader(preamble + tc.condition))
			if tc.code == "" {
				if err != nil {
					t.Fatalf("expected this to load, got %v", err)
				}
				return
			}
			var diags Diagnostics
			if !errors.As(err, &diags) {
				t.Fatalf("expected diagnostics, got %v", err)
			}
			at := diags.At(tc.pointer)
			if len(at) == 0 {
				t.Fatalf("no diagnostic at %s; got %v", tc.pointer, diags)
			}
			if at[0].Code != tc.code {
				t.Fatalf("code at %s: want %q, got %q (%s)", tc.pointer, tc.code, at[0].Code, at[0].Message)
			}
			if at[0].Message == "" {
				t.Fatal("a diagnostic must carry a human-readable message")
			}
		})
	}
}

func TestOrderingOperatorNeedsAnOrderedType(t *testing.T) {
	set := sampleSet()
	set.Policies[1].Condition = Compare{
		Left: Field(RoleSubject, "on_leave"), Op: OpGt, Right: Bool(true),
	}
	diags := Validate(set)
	at := diags.At("/policies/1/condition/op")
	if len(at) == 0 || at[0].Code != CodeInvalidOperator {
		t.Fatalf("expected an invalid-operator diagnostic, got %v", diags)
	}
}

func TestSourceArgumentsMayNotBeSourceCalls(t *testing.T) {
	set := sampleSet()
	set.Policies[1].Condition = Compare{
		Left: Source("daily_total", Source("daily_total", String("x"))),
		Op:   OpGt, Right: Double(1),
	}
	diags := Validate(set)
	if !diags.Has(CodeInvalidOperand) {
		t.Fatalf("expected an invalid-operand diagnostic, got %v", diags)
	}
}

func TestSchemaDeclarationsAreChecked(t *testing.T) {
	set := &Set{
		Schema: Schema{
			Entities: []EntityType{
				{Name: "User", Attributes: []Attribute{{Name: "id", Type: "text"}}},
				{Name: "User"},
			},
			Sources: []SourceDecl{
				{Name: "x", Kind: "carrier_pigeon", Returns: TypeBool, OnError: "shrug"},
			},
		},
		Policies: []Policy{{ID: "Bad Id", Actions: []string{"nope"}}},
	}
	diags := Validate(set)
	for _, want := range []Code{
		CodeInvalidName, CodeDuplicate, CodeUnknownType,
		CodeInvalidValue, CodeUnknownAction, CodeMissingField,
	} {
		if !diags.Has(want) {
			t.Errorf("expected a %q diagnostic; got %v", want, diags)
		}
	}
}

func TestDuplicatePolicyIdentifiersAreRejected(t *testing.T) {
	set := sampleSet()
	set.Policies = append(set.Policies, set.Policies[0])
	if diags := Validate(set); !diags.Has(CodeDuplicate) {
		t.Fatalf("expected a duplicate diagnostic, got %v", diags)
	}
}

func TestCompiledConditionEvaluates(t *testing.T) {
	set := sampleSet()
	policy, ok := set.Policy("always-review-rejections")
	if !ok {
		t.Fatal("missing policy")
	}
	policy.Condition = All(
		Compare{Left: Field(RoleResource, "amount"), Op: OpGt, Right: Double(100)},
		NotIn(Field(RoleSubject, "department"), List(TypeString, "contractors")),
	)
	env, ast, err := Compile(&set.Schema, policy)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program: %v", err)
	}
	for _, tc := range []struct {
		amount     float64
		department string
		want       bool
	}{
		{500, "finance", true},
		{50, "finance", false},
		{500, "contractors", false},
	} {
		out, _, err := program.Eval(map[string]any{
			"resource.amount":    tc.amount,
			"subject.department": tc.department,
		})
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		if got := out.Value(); got != tc.want {
			t.Errorf("amount=%v department=%q: want %v, got %v", tc.amount, tc.department, tc.want, got)
		}
	}
}

func TestChallengeDeclarationsAreValidated(t *testing.T) {
	cases := map[string]struct {
		challenge Challenge
		pointer   string
		code      Code
	}{
		"quorum without a threshold": {
			Quorum{Approvers: ApproverSet{Members: []string{"a"}}},
			"/policies/1/challenges/0/threshold", CodeInvalidValue,
		},
		"quorum larger than its approver set": {
			Quorum{Threshold: 3, Approvers: ApproverSet{Members: []string{"a", "b"}}},
			"/policies/1/challenges/0/approvers", CodeInvalidValue,
		},
		"quorum with duplicate approvers": {
			Quorum{Threshold: 1, Approvers: ApproverSet{Members: []string{"a", "a"}}},
			"/policies/1/challenges/0/approvers/members/1", CodeDuplicate,
		},
		"approver set with no resolution": {
			Quorum{Threshold: 1},
			"/policies/1/challenges/0/approvers", CodeMissingField,
		},
		"approver set with two resolutions": {
			Quorum{Threshold: 1, Approvers: ApproverSet{Members: []string{"a"}, Claim: "groups"}},
			"/policies/1/challenges/0/approvers", CodeInvalidValue,
		},
		"approvers from an undeclared source": {
			Quorum{Threshold: 1, Approvers: ApproverSet{
				Source: &SourceRef{Name: "nobody", Args: []Operand{String("x")}},
			}},
			"/policies/1/challenges/0/approvers", CodeUnknownSource,
		},
		"approvers from a source with the wrong arity": {
			Quorum{Threshold: 1, Approvers: ApproverSet{Source: &SourceRef{Name: "approver_ids"}}},
			"/policies/1/challenges/0/approvers", CodeArityMismatch,
		},
		"approvers from a source of the wrong type": {
			Quorum{Threshold: 1, Approvers: ApproverSet{
				Source: &SourceRef{Name: "daily_total", Args: []Operand{String("x")}},
			}},
			"/policies/1/challenges/0/approvers", CodeTypeMismatch,
		},
		"approvers from a source of the wrong kind": {
			Quorum{Threshold: 1, Approvers: ApproverSet{
				Source: &SourceRef{Name: "team_names", Args: []Operand{String("x")}},
			}},
			"/policies/1/challenges/0/approvers", CodeInvalidValue,
		},
		"mfa in the unimplemented direct mode": {
			MFA{Mode: MFADirect},
			"/policies/1/challenges/0/mode", CodeUnsupported,
		},
		"mfa in an invented mode": {
			MFA{Mode: "telepathy"},
			"/policies/1/challenges/0/mode", CodeInvalidValue,
		},
		"mfa with a blank acr value": {
			MFA{Mode: MFADelegated, ACRValues: []string{"  "}},
			"/policies/1/challenges/0/acr_values/0", CodeInvalidValue,
		},
		"delay with no duration": {
			Delay{},
			"/policies/1/challenges/0/duration", CodeInvalidValue,
		},
		"delay running backwards": {
			Delay{Duration: -time.Minute},
			"/policies/1/challenges/0/duration", CodeInvalidValue,
		},
		"delay with an unresolvable canceller": {
			Delay{Duration: time.Minute, CancellableBy: &ApproverSet{}},
			"/policies/1/challenges/0/cancellable_by", CodeMissingField,
		},
		"external without a target": {
			External{},
			"/policies/1/challenges/0/target", CodeMissingField,
		},
		"external with a malformed target": {
			External{Target: "Fraud Review"},
			"/policies/1/challenges/0/target", CodeInvalidName,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			set := sampleSet()
			// A source that returns approver-shaped data but is not a group
			// lookup, so the kind check has something to catch.
			set.Schema.Sources = append(set.Schema.Sources, SourceDecl{
				Name: "team_names", Kind: SourceHTTP,
				Params:  []Param{{Name: "team", Type: TypeString}},
				Returns: ListOf(TypeString), OnError: OnErrorDeny,
			})
			set.Normalize()
			set.Policies[1].Challenges = []Challenge{tc.challenge}

			diags := Validate(set)
			at := diags.At(tc.pointer)
			if len(at) == 0 {
				t.Fatalf("no diagnostic at %s; got %v", tc.pointer, diags)
			}
			if at[0].Code != tc.code {
				t.Fatalf("code at %s: want %q, got %q (%s)", tc.pointer, tc.code, at[0].Code, at[0].Message)
			}
			if at[0].Message == "" {
				t.Fatal("a diagnostic must carry a human-readable message")
			}
		})
	}
}

func TestUnknownChallengeTypeIsRejectedAtLoad(t *testing.T) {
	doc := `apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes: {id: string}
  - name: doc
    attributes: {level: int}
actions: [read]
---
apiVersion: stamp/v1
kind: Policy
id: exotic
subject: user
resource: doc
actions: [read]
challenges:
  - type: webauthn
    threshold: 2
`
	_, err := Load(strings.NewReader(doc))
	var diags Diagnostics
	if !errors.As(err, &diags) {
		t.Fatalf("expected diagnostics, got %v", err)
	}
	at := diags.At("/policies/0/challenges/0/type")
	if len(at) == 0 || at[0].Code != CodeUnknownChallenge {
		t.Fatalf("expected an unknown-challenge diagnostic, got %v", diags)
	}
	if !strings.Contains(at[0].Message, "quorum") {
		t.Errorf("the message should list the kinds that are allowed, got %q", at[0].Message)
	}
}

func TestChallengeKeysAreScopedToTheirType(t *testing.T) {
	doc := `apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes: {id: string}
  - name: doc
    attributes: {level: int}
actions: [read]
---
apiVersion: stamp/v1
kind: Policy
id: confused
subject: user
resource: doc
actions: [read]
challenges:
  - type: delay
    duration: 5m
    threshold: 2
`
	_, err := Load(strings.NewReader(doc))
	var diags Diagnostics
	if !errors.As(err, &diags) {
		t.Fatalf("expected diagnostics, got %v", err)
	}
	at := diags.At("/policies/0/challenges/0/threshold")
	if len(at) == 0 || at[0].Code != CodeUnknownKey {
		t.Fatalf("a quorum key on a delay should be an unknown key, got %v", diags)
	}
}

func TestChallengeCarryingPolicyStillCompiles(t *testing.T) {
	// Challenges are declarations, not condition nodes: they never reach the
	// compiler and never change what a condition means.
	set := sampleSet()
	guarded, _ := set.Policy("high-value-transfer")
	_, withChallenges, err := Compile(&set.Schema, guarded)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	guarded.Challenges = nil
	_, withoutChallenges, err := Compile(&set.Schema, guarded)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if withChallenges.OutputType() != withoutChallenges.OutputType() {
		t.Error("challenges changed the compiled condition")
	}
}

// ---------------------------------------------------------------------------
// properties
// ---------------------------------------------------------------------------

// TestStaticValidationImpliesCELCompiles is the invariant the unit exists to
// hold: anything the static checks accept, cel-go compiles. If it ever fails,
// a policy could clear the form's preflight and then be rejected at save time.
//
// The generator is deliberately sloppy — it invents roles, attributes, sources,
// argument counts, and operand types at random — so most cases are rejected.
// The ones that get through are the sample the property is asserted over.
func TestStaticValidationImpliesCELCompiles(t *testing.T) {
	set := sampleSet()
	limits := DefaultLimits()
	rng := rand.New(rand.NewPCG(0x5741, 0x4d50))

	accepted := 0
	const iterations = 4000
	for i := 0; i < iterations; i++ {
		g := &generator{rng: rng, schema: &set.Schema, sloppy: true}
		policy := Policy{
			ID:        "generated",
			Subject:   "user",
			Resource:  "transfer",
			Actions:   []string{"approve"},
			Condition: g.condition(3),
		}
		candidate := &Set{Schema: set.Schema, Policies: []Policy{policy}}
		if diags := validateStatic(candidate, limits); len(diags) > 0 {
			continue
		}
		accepted++
		if _, _, err := Compile(&candidate.Schema, &candidate.Policies[0]); err != nil {
			t.Fatalf("static validation accepted a condition cel-go rejects: %v\ncondition: %#v",
				err, policy.Condition)
		}
	}
	if accepted < iterations/20 {
		t.Fatalf("only %d of %d generated conditions were accepted; the property is close to vacuous",
			accepted, iterations)
	}
	t.Logf("%d of %d generated conditions passed static validation and all compiled", accepted, iterations)
}

// TestValidSetsRoundTrip is the export/import property: a set that validates
// survives serialization and deserialization with its meaning intact, and its
// canonical form is stable under a second pass.
func TestValidSetsRoundTrip(t *testing.T) {
	base := sampleSet()
	rng := rand.New(rand.NewPCG(0x524f, 0x554e))

	for i := 0; i < 300; i++ {
		g := &generator{rng: rng, schema: &base.Schema}
		set := &Set{Schema: base.Schema, Policies: []Policy{{
			ID:         "generated",
			Subject:    "user",
			Resource:   "transfer",
			Actions:    []string{"approve"},
			Condition:  g.condition(3),
			Challenges: g.challenges(),
		}}}
		set.Normalize()
		if diags := Validate(set); len(diags) > 0 {
			t.Fatalf("the well-typed generator produced an invalid set: %v\ncondition: %#v",
				diags, set.Policies[0].Condition)
		}
		data, err := Marshal(set)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		got, err := Load(strings.NewReader(string(data)))
		if err != nil {
			t.Fatalf("load:\n%s\n%v", data, err)
		}
		// Compared structurally rather than by re-serializing, so that anything
		// the encoder silently drops shows up here instead of cancelling out on
		// both sides.
		if !reflect.DeepEqual(set, got) {
			t.Fatalf("round trip changed the set\n%s\nwant %#v\ngot  %#v", data, set, got)
		}
		again, err := Marshal(got)
		if err != nil {
			t.Fatalf("re-marshal: %v", err)
		}
		if string(again) != string(data) {
			t.Fatalf("canonical form is not stable\nfirst:\n%s\nsecond:\n%s", data, again)
		}
	}
}

// generator builds condition ASTs. With sloppy set it invents names and mixes
// types freely; otherwise it only produces well-typed conditions against the
// schema it is given.
type generator struct {
	rng    *rand.Rand
	schema *Schema
	sloppy bool
}

// challenges produces a well-formed challenge list so that the round-trip
// property covers declarations as well as conditions.
func (g *generator) challenges() []Challenge {
	n := g.rng.IntN(5)
	if n == 0 {
		return nil
	}
	out := make([]Challenge, 0, n)
	for i := 0; i < n; i++ {
		switch g.rng.IntN(4) {
		case 0:
			members := []string{"alice", "bob", "carol", "dave"}[:1+g.rng.IntN(4)]
			approvers := ApproverSet{Members: members}
			threshold := 1 + g.rng.IntN(len(members))
			if g.rng.IntN(3) == 0 {
				approvers = ApproverSet{Claim: "groups"}
				threshold = 1 + g.rng.IntN(3)
			} else if g.rng.IntN(3) == 0 {
				approvers = ApproverSet{Source: &SourceRef{
					Name: "approver_ids",
					Args: []Operand{g.operandOfType(TypeString)},
				}}
				threshold = 1 + g.rng.IntN(3)
			}
			out = append(out, Quorum{Threshold: threshold, Approvers: approvers})
		case 1:
			acr := []string{"urn:a", "urn:b", "urn:c"}[:g.rng.IntN(4)]
			if len(acr) == 0 {
				acr = nil
			}
			out = append(out, MFA{Mode: MFADelegated, ACRValues: acr})
		case 2:
			c := Delay{Duration: time.Duration(1+g.rng.Int64N(86_400)) * time.Second}
			if g.rng.IntN(2) == 0 {
				c.CancellableBy = &ApproverSet{Members: []string{"security-lead"}}
			}
			out = append(out, c)
		default:
			targets := []string{"fraud-review", "risk.desk", "compliance_bot"}
			out = append(out, External{Target: targets[g.rng.IntN(len(targets))]})
		}
	}
	return out
}

func (g *generator) condition(depth int) Node {
	if depth <= 0 || g.rng.IntN(3) == 0 {
		return g.leaf()
	}
	switch g.rng.IntN(3) {
	case 0:
		return Not(g.condition(depth - 1))
	case 1:
		return All(g.nodes(depth)...)
	default:
		return Any(g.nodes(depth)...)
	}
}

func (g *generator) nodes(depth int) []Node {
	n := 1 + g.rng.IntN(3)
	out := make([]Node, n)
	for i := range out {
		out[i] = g.condition(depth - 1)
	}
	return out
}

func (g *generator) leaf() Node {
	// A wholly random leaf almost never type-checks, and a tree of them never
	// does, so the sloppy generator mixes well-typed leaves in. Otherwise the
	// property would be asserted over an empty sample.
	if g.sloppy && g.rng.IntN(4) == 0 {
		return g.sloppyLeaf()
	}
	left, leftType := g.typedReference()
	if !leftType.IsList() && g.rng.IntN(3) == 0 {
		return Member{
			Left:       left,
			Collection: g.collectionOf(leftType),
			Negate:     g.rng.IntN(2) == 0,
		}
	}
	return Compare{Left: left, Op: g.operatorFor(leftType), Right: g.operandOfType(leftType)}
}

func (g *generator) sloppyLeaf() Node {
	left, _ := g.reference()
	if g.rng.IntN(3) == 0 {
		return Member{Left: left, Collection: g.operand(), Negate: g.rng.IntN(2) == 0}
	}
	ops := CompareOps()
	return Compare{Left: left, Op: ops[g.rng.IntN(len(ops))], Right: g.operand()}
}

// typedReference returns a reference and the type it resolves to.
func (g *generator) typedReference() (Reference, Type) {
	if g.rng.IntN(3) == 0 && len(g.schema.Sources) > 0 {
		src := &g.schema.Sources[g.rng.IntN(len(g.schema.Sources))]
		args := make([]Operand, len(src.Params))
		for i, p := range src.Params {
			args[i] = g.operandOfType(p.Type)
		}
		return SourceRef{Name: src.Name, Args: args}, src.Returns
	}
	role := RoleSubject
	entity := "user"
	if g.rng.IntN(2) == 0 {
		role, entity = RoleResource, "transfer"
	}
	e, _ := g.schema.Entity(entity)
	attr := e.Attributes[g.rng.IntN(len(e.Attributes))]
	return Field(role, attr.Name), attr.Type
}

// reference returns a possibly nonsensical reference.
func (g *generator) reference() (Reference, Type) {
	if g.rng.IntN(4) == 0 {
		names := []string{"daily_total", "approver_ids", "kill_switch", "nonexistent"}
		name := names[g.rng.IntN(len(names))]
		args := make([]Operand, g.rng.IntN(3))
		for i := range args {
			args[i] = g.operand()
		}
		if len(args) == 0 {
			return SourceRef{Name: name}, ""
		}
		return SourceRef{Name: name, Args: args}, ""
	}
	roles := Roles()
	attrs := []string{"id", "department", "seniority", "on_leave", "amount", "currency",
		"created_at", "age", "tags", "invented"}
	return Field(roles[g.rng.IntN(len(roles))], attrs[g.rng.IntN(len(attrs))]), ""
}

func (g *generator) operand() Operand {
	if g.rng.IntN(2) == 0 {
		ref, _ := g.reference()
		return ref
	}
	types := append(ScalarTypes(), ListOf(TypeString), ListOf(TypeInt))
	return g.literal(types[g.rng.IntN(len(types))])
}

func (g *generator) operandOfType(t Type) Operand {
	if g.rng.IntN(3) == 0 {
		if ref, ok := g.referenceOfType(t); ok {
			return ref
		}
	}
	return g.literal(t)
}

func (g *generator) referenceOfType(t Type) (Reference, bool) {
	type candidate struct {
		ref Reference
	}
	var candidates []candidate
	for _, role := range []Role{RoleSubject, RoleResource} {
		entity := "user"
		if role == RoleResource {
			entity = "transfer"
		}
		e, ok := g.schema.Entity(entity)
		if !ok {
			continue
		}
		for _, a := range e.Attributes {
			if a.Type == t {
				candidates = append(candidates, candidate{Field(role, a.Name)})
			}
		}
	}
	if len(candidates) == 0 {
		return nil, false
	}
	return candidates[g.rng.IntN(len(candidates))].ref, true
}

func (g *generator) collectionOf(elem Type) Operand {
	for i := range g.schema.Sources {
		src := &g.schema.Sources[i]
		if src.Returns == ListOf(elem) && g.rng.IntN(3) == 0 {
			args := make([]Operand, len(src.Params))
			for j, p := range src.Params {
				args[j] = g.operandOfType(p.Type)
			}
			return SourceRef{Name: src.Name, Args: args}
		}
	}
	return g.literal(ListOf(elem))
}

func (g *generator) operatorFor(t Type) CompareOp {
	if t.IsOrdered() {
		ops := CompareOps()
		return ops[g.rng.IntN(len(ops))]
	}
	if g.rng.IntN(2) == 0 {
		return OpEq
	}
	return OpNe
}

func (g *generator) literal(t Type) Literal {
	if t.IsList() {
		n := g.rng.IntN(4)
		items := make([]any, n)
		for i := range items {
			items[i] = g.literal(t.Elem()).Data
		}
		return Literal{Type: t, Data: items}
	}
	switch t {
	case TypeBool:
		return Bool(g.rng.IntN(2) == 0)
	case TypeInt:
		return Int(g.rng.Int64N(2001) - 1000)
	case TypeDouble:
		if g.rng.IntN(3) == 0 {
			return Double(float64(g.rng.Int64N(2001) - 1000))
		}
		return Double(g.rng.Float64() * 1e6)
	case TypeString:
		pool := []string{"", "finance", "10", "true", "yes", "null", "~", "a: b", "  padded  ",
			"멀티바이트", "line\nbreak", "#hash"}
		return String(pool[g.rng.IntN(len(pool))])
	case TypeTimestamp:
		return Timestamp(time.Unix(g.rng.Int64N(2_000_000_000), g.rng.Int64N(1_000_000_000)).UTC())
	case TypeDuration:
		d := time.Duration(g.rng.Int64N(1_000_000_000_000))
		if g.rng.IntN(4) == 0 {
			d = -d
		}
		return Duration(d)
	default:
		return String("unreachable")
	}
}
