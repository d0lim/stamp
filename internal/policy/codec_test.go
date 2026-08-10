package policy

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// sampleSet is a valid policy set exercising every AST node kind and every
// operand kind.
func sampleSet() *Set {
	s := &Set{
		Schema: Schema{
			Entities: []EntityType{
				{Name: "user", Attributes: []Attribute{
					{Name: "id", Type: TypeString},
					{Name: "department", Type: TypeString},
					{Name: "seniority", Type: TypeInt},
					{Name: "on_leave", Type: TypeBool},
				}},
				{Name: "transfer", Attributes: []Attribute{
					{Name: "amount", Type: TypeDouble},
					{Name: "currency", Type: TypeString},
					{Name: "created_at", Type: TypeTimestamp},
					{Name: "age", Type: TypeDuration},
					{Name: "tags", Type: ListOf(TypeString)},
				}},
			},
			Actions: []Action{
				{Name: "approve", Description: "release the transfer"},
				{Name: "reject"},
			},
			Sources: []SourceDecl{
				{Name: "daily_total", Kind: SourceEvent,
					Params: []Param{{Name: "account_id", Type: TypeString}}, Returns: TypeDouble},
				{Name: "approver_ids", Kind: SourceIdPGroup,
					Params: []Param{{Name: "team", Type: TypeString}}, Returns: ListOf(TypeString)},
				{Name: "kill_switch", Kind: SourceStatic, Returns: TypeBool, OnError: OnErrorAllow},
			},
		},
		Policies: []Policy{{
			ID:          "high-value-transfer",
			Description: "large transfers need a second pair of eyes",
			Subject:     "user",
			Resource:    "transfer",
			Actions:     []string{"approve"},
			Condition: All(
				Compare{Left: Field(RoleResource, "amount"), Op: OpGt, Right: Double(10000)},
				NotIn(Field(RoleSubject, "department"), List(TypeString, "contractors", "interns")),
				Compare{
					Left:  Source("daily_total", Field(RoleSubject, "id")),
					Op:    OpLe,
					Right: Double(100000),
				},
				In(Field(RoleSubject, "id"), Source("approver_ids", String("finance"))),
				Not(Compare{Left: Field(RoleSubject, "on_leave"), Op: OpEq, Right: Bool(true)}),
				Any(
					Compare{Left: Field(RoleResource, "created_at"), Op: OpGe,
						Right: Timestamp(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))},
					Compare{Left: Field(RoleResource, "age"), Op: OpLt, Right: Duration(2 * time.Hour)},
					Compare{Left: Field(RoleSubject, "seniority"), Op: OpNe, Right: Int(3)},
					In(Field(RoleResource, "currency"), Literal{
						Type: ListOf(TypeString),
						Data: []any{},
					}),
				),
			),
			Challenges: []Challenge{
				Quorum{Threshold: 2, Approvers: ApproverSet{
					Source: &SourceRef{Name: "approver_ids", Args: []Operand{String("finance")}},
				}},
				MFA{Mode: MFADelegated, ACRValues: []string{"urn:mace:incommon:iap:silver"}},
				Delay{Duration: 30 * time.Minute, CancellableBy: &ApproverSet{
					Members: []string{"security-lead"},
				}},
				External{Target: "fraud-review"},
			},
		}, {
			ID:       "always-review-rejections",
			Subject:  "user",
			Resource: "transfer",
			Actions:  []string{"reject"},
		}},
	}
	s.Normalize()
	return s
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	want := sampleSet()
	data, err := Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	t.Logf("canonical form:\n%s", data)

	got, err := Load(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round trip changed the set\nwant %#v\ngot  %#v", want, got)
	}

	// Re-encoding the decoded set reproduces the same bytes, which is what
	// makes export followed by apply a no-op rather than a fresh revision.
	again, err := Marshal(got)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(data, again) {
		t.Fatalf("canonical form is not stable\nfirst:\n%s\nsecond:\n%s", data, again)
	}
}

// handWritten is a minimal policy file as a person would type it: comments,
// defaults left out, keys in whatever order made sense while writing.
const handWritten = `
# The declarations this policy is written against.
apiVersion: stamp/v1
kind: Schema
entities:
  - name: transfer
    attributes:
      amount: double       # money moved
      currency: string
  - name: user
    attributes:
      department: string
actions:
  - approve                # no description needed
sources:
  - name: daily_total
    kind: event
    params:
      - account_id: string
    returns: double
    # on_error is omitted: deny is the default and the safe one
---
# One policy. Its identity is the id below, not this file's name.
apiVersion: stamp/v1
kind: Policy
id: high-value-transfer
subject: user
resource: transfer
actions: [approve]
condition:
  all:
    - left: {field: resource.amount}
      op: gt
      right: 10000.0
    - left: {field: user.department}
      not_in: [contractors]
challenges:
  # two of these three have to sign off
  - type: quorum
    threshold: 2
    approvers: {members: [alice, bob, carol]}
  # mode is omitted: delegated is the only one v1 implements
  - type: mfa
`

func TestHandWrittenFileLoads(t *testing.T) {
	// The hand-written sample above deliberately says user.department where it
	// means subject.department, so it must be rejected first.
	if _, err := Load(strings.NewReader(handWritten)); err == nil {
		t.Fatal("expected the unbound role in the sample to be rejected")
	}

	fixed := strings.ReplaceAll(handWritten, "user.department", "subject.department")
	set, err := Load(strings.NewReader(fixed))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(set.Policies) != 1 || set.Policies[0].ID != "high-value-transfer" {
		t.Fatalf("unexpected policies: %#v", set.Policies)
	}
	// The omitted default is filled in by normalization.
	src, ok := set.Schema.Source("daily_total")
	if !ok {
		t.Fatal("daily_total was not declared")
	}
	if src.OnError != OnErrorDeny {
		t.Fatalf("on_error default: want %q, got %q", OnErrorDeny, src.OnError)
	}

	// Re-serializing after normalization is semantically equivalent: the
	// comments and the original key order are gone, but reloading yields the
	// same set.
	data, err := Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(data, []byte("on_error")) {
		t.Fatalf("normalization should omit the default on_error:\n%s", data)
	}
	if bytes.Contains(data, []byte("mode:")) {
		t.Fatalf("normalization should omit the default mfa mode:\n%s", data)
	}
	// The hand-written file said nothing about a decision; the challenges it
	// declares are what make one necessary.
	if !set.Policies[0].RequiresDecision() {
		t.Error("a policy declaring challenges must require a decision")
	}
	again, err := Load(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reflect.DeepEqual(set, again) {
		t.Fatalf("re-serialization is not semantically equivalent\nwant %#v\ngot  %#v", set, again)
	}
}

func TestRenamingAFilePreservesThePolicyIdentifier(t *testing.T) {
	content := strings.ReplaceAll(handWritten, "user.department", "subject.department")

	before, err := LoadFS(fstest.MapFS{
		"policies/transfers.yaml": {Data: []byte(content)},
	})
	if err != nil {
		t.Fatalf("load before rename: %v", err)
	}
	after, err := LoadFS(fstest.MapFS{
		"somewhere/else/renamed-and-moved.yml": {Data: []byte(content)},
	})
	if err != nil {
		t.Fatalf("load after rename: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("moving and renaming the file changed the policy set")
	}
	if before.Policies[0].ID != "high-value-transfer" {
		t.Fatalf("identifier came from somewhere other than the document: %q", before.Policies[0].ID)
	}
}

func TestLoadFSMergesFilesIntoOneSet(t *testing.T) {
	schemaDoc := `apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes: {id: string}
  - name: doc
    attributes: {level: int}
actions: [read]
`
	policyDoc := `apiVersion: stamp/v1
kind: Policy
id: read-low-level
subject: user
resource: doc
actions: [read]
condition:
  left: {field: resource.level}
  op: lt
  right: 3
`
	set, err := LoadFS(fstest.MapFS{
		"schema.yaml": {Data: []byte(schemaDoc)},
		"policy.yaml": {Data: []byte(policyDoc)},
		"README.md":   {Data: []byte("not a policy")},
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(set.Schema.Entities) != 2 || len(set.Policies) != 1 {
		t.Fatalf("unexpected merged set: %#v", set)
	}
}

func TestEmptyConditionParses(t *testing.T) {
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
id: no-condition
subject: user
resource: doc
actions: [read]
`
	set, err := Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.Policies[0].Condition != nil {
		t.Fatalf("expected a nil condition, got %#v", set.Policies[0].Condition)
	}
	// An absent condition still compiles, so callers never special-case it.
	if _, _, err := Compile(&set.Schema, &set.Policies[0]); err != nil {
		t.Fatalf("compile: %v", err)
	}
	data, err := Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(data, []byte("\ncondition:")) {
		t.Fatalf("an absent condition should not be written back:\n%s", data)
	}
}

func TestDeeplyNestedLogicRoundTrips(t *testing.T) {
	const depth = 30 // one under the default limit of 32, counting the leaf
	leaf := Node(Compare{Left: Field(RoleResource, "level"), Op: OpLt, Right: Int(3)})
	condition := leaf
	for i := 0; i < depth-1; i++ {
		if i%2 == 0 {
			condition = All(condition)
		} else {
			condition = Any(condition)
		}
	}
	set := &Set{
		Schema: Schema{
			Entities: []EntityType{
				{Name: "doc", Attributes: []Attribute{{Name: "level", Type: TypeInt}}},
				{Name: "user", Attributes: []Attribute{{Name: "id", Type: TypeString}}},
			},
			Actions: []Action{{Name: "read"}},
		},
		Policies: []Policy{{
			ID: "nested", Subject: "user", Resource: "doc",
			Actions: []string{"read"}, Condition: condition,
		}},
	}
	set.Normalize()
	if got := Depth(condition); got != depth {
		t.Fatalf("depth helper: want %d, got %d", depth, got)
	}
	if diags := Validate(set); len(diags) > 0 {
		t.Fatalf("validate: %v", diags)
	}
	data, err := Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := Load(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !reflect.DeepEqual(set, got) {
		t.Fatal("deep nesting did not survive the round trip")
	}

	// One level past the limit is rejected rather than handed to cel-go.
	set.Policies[0].Condition = All(All(All(condition)))
	diags := Validate(set)
	if !diags.Has(CodeLimitExceeded) {
		t.Fatalf("expected the depth limit to reject this, got %v", diags)
	}
}

func TestWideConjunctionStaysWithinCELNestingLimits(t *testing.T) {
	// A conjunction wide enough that a left-nested compile would blow past
	// cel-go's own nesting ceiling. Folding into a balanced tree keeps it flat.
	const width = 400
	operands := make([]Node, width)
	for i := range operands {
		operands[i] = Compare{Left: Field(RoleResource, "level"), Op: OpLt, Right: Int(int64(i))}
	}
	set := &Set{
		Schema: Schema{
			Entities: []EntityType{
				{Name: "doc", Attributes: []Attribute{{Name: "level", Type: TypeInt}}},
				{Name: "user", Attributes: []Attribute{{Name: "id", Type: TypeString}}},
			},
			Actions: []Action{{Name: "read"}},
		},
		Policies: []Policy{{
			ID: "wide", Subject: "user", Resource: "doc",
			Actions: []string{"read"}, Condition: All(operands...),
		}},
	}
	set.Normalize()
	limits := DefaultLimits()
	limits.MaxConditionNodes = 4096
	if diags := ValidateWithLimits(set, limits); len(diags) > 0 {
		t.Fatalf("validate: %v", diags)
	}
}

// TestCanonicalFormStaysReadable guards the property the format exists for. The
// round trip would survive an explicit "!!float 10000" tag just as well, but a
// person reading the diff would not, so the encoder keeps the decimal point and
// never falls back to YAML tags.
func TestCanonicalFormStaysReadable(t *testing.T) {
	data, err := Marshal(sampleSet())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(data, []byte("!!")) {
		t.Errorf("canonical form leaked a YAML tag:\n%s", data)
	}
	if !bytes.Contains(data, []byte("right: 10000.0")) {
		t.Errorf("an integral double should keep its decimal point:\n%s", data)
	}
	if bytes.Contains(data, []byte("%YAML")) {
		t.Errorf("canonical form leaked a directive:\n%s", data)
	}
}

func TestOversizedPayloadIsRejectedBeforeParsing(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxDocumentBytes = 32
	_, err := DecodeWithLimits(strings.NewReader(handWritten), limits)
	var diags Diagnostics
	if !errors.As(err, &diags) || !diags.Has(CodeLimitExceeded) {
		t.Fatalf("expected a limit diagnostic, got %v", err)
	}
}

func TestUnknownKeysAndVersionsAreRejected(t *testing.T) {
	cases := map[string]struct {
		doc  string
		code Code
	}{
		"unknown api version": {"apiVersion: stamp/v2\nkind: Policy\nid: x\n", CodeUnknownAPIVersion},
		"unknown kind":        {"apiVersion: stamp/v1\nkind: Rule\nid: x\n", CodeUnknownKind},
		"unknown key":         {"apiVersion: stamp/v1\nkind: Policy\nid: x\nsubjects: user\n", CodeUnknownKey},
		"not a mapping":       {"apiVersion: stamp/v1\n- a\n", CodeInvalidYAML},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(tc.doc))
			var diags Diagnostics
			if !errors.As(err, &diags) {
				t.Fatalf("expected diagnostics, got %v", err)
			}
			if !diags.Has(tc.code) {
				t.Fatalf("want code %q, got %v", tc.code, diags)
			}
		})
	}
}

func TestLiteralOnTheLeftIsRejected(t *testing.T) {
	doc := `apiVersion: stamp/v1
kind: Policy
id: x
subject: user
resource: doc
actions: [read]
condition:
  left: 10
  op: gt
  right: {field: resource.level}
`
	_, err := Decode(strings.NewReader(doc))
	var diags Diagnostics
	if !errors.As(err, &diags) || !diags.Has(CodeInvalidOperand) {
		t.Fatalf("expected an invalid-operand diagnostic, got %v", err)
	}
}

func TestExplicitlyTypedLiterals(t *testing.T) {
	doc := `apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes: {id: string}
  - name: doc
    attributes:
      age: duration
      amount: double
actions: [read]
---
apiVersion: stamp/v1
kind: Policy
id: typed
subject: user
resource: doc
actions: [read]
condition:
  all:
    - left: {field: resource.age}
      op: lt
      right: {value: 1h30m, type: duration}
    - left: {field: resource.amount}
      op: gt
      right: {value: 10000, type: double}
`
	set, err := Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	logic, ok := set.Policies[0].Condition.(Logic)
	if !ok {
		t.Fatalf("expected a logic node, got %T", set.Policies[0].Condition)
	}
	first, ok := logic.Operands[0].(Compare)
	if !ok {
		t.Fatalf("expected a comparison, got %T", logic.Operands[0])
	}
	if got := first.Right; !reflect.DeepEqual(got, Duration(90*time.Minute)) {
		t.Fatalf("duration literal: got %#v", got)
	}
	second, _ := logic.Operands[1].(Compare)
	if got := second.Right; !reflect.DeepEqual(got, Double(10000)) {
		t.Fatalf("explicitly typed double: got %#v", got)
	}
}
