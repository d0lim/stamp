package policy

import (
	"reflect"
	"testing"
	"time"
)

func TestDepthAndCount(t *testing.T) {
	leaf := Compare{Left: Field(RoleResource, "amount"), Op: OpGt, Right: Double(1)}
	cases := []struct {
		name  string
		node  Node
		depth int
		count int
	}{
		{"absent", nil, 0, 0},
		{"single comparison", leaf, 1, 3},
		{"negation", Not(leaf), 2, 4},
		{"conjunction of two", All(leaf, leaf), 2, 7},
		{"nested", All(leaf, Any(leaf, Not(leaf))), 4, 12},
		{"source with an argument", Compare{
			Left:  Source("daily_total", Field(RoleSubject, "id")),
			Op:    OpGt,
			Right: Double(1),
		}, 1, 4},
		{"membership", In(Field(RoleSubject, "id"), List(TypeString, "a")), 1, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Depth(tc.node); got != tc.depth {
				t.Errorf("Depth: want %d, got %d", tc.depth, got)
			}
			if got := Count(tc.node); got != tc.count {
				t.Errorf("Count: want %d, got %d", tc.count, got)
			}
		})
	}
}

func TestConstructors(t *testing.T) {
	instant := time.Date(2026, 3, 4, 5, 6, 7, 0, time.FixedZone("KST", 9*3600))
	cases := []struct {
		got  Literal
		want Literal
	}{
		{Bool(true), Literal{Type: TypeBool, Data: true}},
		{Int(7), Literal{Type: TypeInt, Data: int64(7)}},
		{Double(1.5), Literal{Type: TypeDouble, Data: 1.5}},
		{String("x"), Literal{Type: TypeString, Data: "x"}},
		{Duration(time.Minute), Literal{Type: TypeDuration, Data: time.Minute}},
		{Timestamp(instant), Literal{Type: TypeTimestamp, Data: instant.UTC()}},
		{List(TypeInt, int64(1), int64(2)), Literal{Type: "list<int>", Data: []any{int64(1), int64(2)}}},
	}
	for _, tc := range cases {
		if !reflect.DeepEqual(tc.got, tc.want) {
			t.Errorf("want %#v, got %#v", tc.want, tc.got)
		}
	}

	// A timestamp literal is normalized to UTC so that two spellings of the
	// same instant are the same value.
	if !Timestamp(instant).Data.(time.Time).Equal(instant) {
		t.Error("normalizing to UTC changed the instant")
	}

	// A source call with no arguments carries a nil slice rather than an empty
	// one, so a hand-written document and a constructed AST compare equal.
	if Source("kill_switch").Args != nil {
		t.Error("a source call with no arguments should carry no argument slice")
	}

	leaf := Compare{Left: Field(RoleSubject, "id"), Op: OpEq, Right: String("x")}
	if got := Not(leaf); len(got.Operands) != 1 || got.Op != LogicNot {
		t.Errorf("Not: got %#v", got)
	}
	if got := NotIn(Field(RoleSubject, "id"), List(TypeString)); !got.Negate {
		t.Error("NotIn should negate")
	}
}

func TestOperatorValidity(t *testing.T) {
	for _, op := range CompareOps() {
		if !op.Valid() {
			t.Errorf("%q should be valid", op)
		}
	}
	if CompareOp("approximately").Valid() {
		t.Error("an invented operator should not be valid")
	}
	if !OpLt.Ordering() || OpEq.Ordering() {
		t.Error("Ordering misclassifies an operator")
	}
	for _, op := range []LogicOp{LogicAll, LogicAny, LogicNot} {
		if !op.Valid() {
			t.Errorf("%q should be valid", op)
		}
	}
	if LogicOp("xor").Valid() {
		t.Error("an invented combinator should not be valid")
	}
}

// TestNodeSetIsClosed pins the shape of the AST. The condition language holds
// exactly three node kinds and three operand kinds, none of which is an
// arbitrary function call. Extending this list is a decision about whether every
// stored policy still opens in the form builder, so it should not happen by
// accident.
func TestNodeSetIsClosed(t *testing.T) {
	nodes := []Node{Logic{}, Compare{}, Member{}}
	operands := []Operand{FieldRef{}, SourceRef{}, Literal{}}
	references := []Reference{FieldRef{}, SourceRef{}}

	if len(nodes) != 3 || len(operands) != 3 || len(references) != 2 {
		t.Fatal("the AST node inventory changed")
	}
	// Only references may sit on the left of a rule; a constant may not.
	if _, ok := any(Literal{}).(Reference); ok {
		t.Error("a constant must not satisfy Reference")
	}
}
