package policy

import "time"

// Node is one node of a policy condition.
//
// The set of implementations is closed and deliberately small: Logic, Compare,
// and Member. Every one of them corresponds to a row or a group a form builder
// can draw. There is no node for calling an arbitrary function, and adding one
// would silently retire the guarantee that any stored policy can be reopened in
// the form builder.
type Node interface {
	node()
}

// LogicOp names a logical combinator.
type LogicOp string

// The logical combinators. Not takes exactly one operand; All and Any take one
// or more.
const (
	LogicAll LogicOp = "all"
	LogicAny LogicOp = "any"
	LogicNot LogicOp = "not"
)

// Valid reports whether op is one of the declared combinators.
func (op LogicOp) Valid() bool {
	return op == LogicAll || op == LogicAny || op == LogicNot
}

// Logic combines child conditions with a logical combinator.
type Logic struct {
	Op       LogicOp
	Operands []Node
}

func (Logic) node() {}

// CompareOp names a comparison operator.
type CompareOp string

// The comparison operators. Eq and Ne apply to any two operands of the same
// type; the ordering operators additionally require an ordered type.
const (
	OpEq CompareOp = "eq"
	OpNe CompareOp = "ne"
	OpLt CompareOp = "lt"
	OpLe CompareOp = "le"
	OpGt CompareOp = "gt"
	OpGe CompareOp = "ge"
)

// CompareOps returns every comparison operator, in declaration order.
func CompareOps() []CompareOp {
	return []CompareOp{OpEq, OpNe, OpLt, OpLe, OpGt, OpGe}
}

// Valid reports whether op is one of the declared comparison operators.
func (op CompareOp) Valid() bool {
	for _, o := range CompareOps() {
		if op == o {
			return true
		}
	}
	return false
}

// Ordering reports whether op requires an ordered operand type.
func (op CompareOp) Ordering() bool { return op != OpEq && op != OpNe }

// Compare relates a reference to another operand.
//
// The left side is always a Reference — a declared field or a declared fact
// source. That asymmetry is not an accident of the format: it is how a form row
// reads, with an attribute picker on the left and a value box on the right, and
// comparing two constants is never useful.
type Compare struct {
	Left  Reference
	Op    CompareOp
	Right Operand
}

func (Compare) node() {}

// Member tests whether a reference's value appears in a collection. Negate
// turns the test into "not in".
type Member struct {
	Left       Reference
	Collection Operand
	Negate     bool
}

func (Member) node() {}

// Operand produces a value inside a condition.
type Operand interface {
	operand()
}

// Reference is an operand that reads a declared value rather than carrying one.
// Both implementations name something the schema declares, which is why a
// condition can never reach outside the schema.
type Reference interface {
	Operand
	reference()
}

// FieldRef reads one declared attribute of one bound entity role.
type FieldRef struct {
	Role      Role
	Attribute string
}

func (FieldRef) operand()   {}
func (FieldRef) reference() {}

// SourceRef calls a declared fact source with positional arguments.
//
// This is the only call-shaped node in the AST, and it is not an escape hatch:
// the callee must be declared in the schema, the argument count and types are
// checked against that declaration, and arguments may not themselves be source
// calls.
type SourceRef struct {
	Name string
	Args []Operand
}

func (SourceRef) operand()   {}
func (SourceRef) reference() {}

// Literal carries a constant value of a declared type. Data holds a Go value
// matching Type: bool, int64, float64, string, time.Time, time.Duration, or a
// []any of one of those for a list type.
type Literal struct {
	Type Type
	Data any
}

func (Literal) operand() {}

// Field returns a reference to one attribute of a bound entity role.
func Field(role Role, attribute string) FieldRef {
	return FieldRef{Role: role, Attribute: attribute}
}

// Source returns a call to a declared fact source.
func Source(name string, args ...Operand) SourceRef {
	if len(args) == 0 {
		return SourceRef{Name: name}
	}
	return SourceRef{Name: name, Args: args}
}

// Bool returns a boolean literal.
func Bool(v bool) Literal { return Literal{Type: TypeBool, Data: v} }

// Int returns an integer literal.
func Int(v int64) Literal { return Literal{Type: TypeInt, Data: v} }

// Double returns a double literal.
func Double(v float64) Literal { return Literal{Type: TypeDouble, Data: v} }

// String returns a string literal.
func String(v string) Literal { return Literal{Type: TypeString, Data: v} }

// Timestamp returns a timestamp literal. The value is normalized to UTC so that
// two literals denoting the same instant compare equal.
func Timestamp(v time.Time) Literal { return Literal{Type: TypeTimestamp, Data: v.UTC()} }

// Duration returns a duration literal.
func Duration(v time.Duration) Literal { return Literal{Type: TypeDuration, Data: v} }

// List returns a homogeneous list literal of the given element type.
func List(elem Type, values ...any) Literal {
	data := make([]any, 0, len(values))
	data = append(data, values...)
	return Literal{Type: ListOf(elem), Data: data}
}

// All returns a conjunction of the given conditions.
func All(operands ...Node) Logic { return Logic{Op: LogicAll, Operands: operands} }

// Any returns a disjunction of the given conditions.
func Any(operands ...Node) Logic { return Logic{Op: LogicAny, Operands: operands} }

// Not returns the negation of a condition.
func Not(operand Node) Logic { return Logic{Op: LogicNot, Operands: []Node{operand}} }

// In returns a membership test.
func In(left Reference, collection Operand) Member {
	return Member{Left: left, Collection: collection}
}

// NotIn returns a negated membership test.
func NotIn(left Reference, collection Operand) Member {
	return Member{Left: left, Collection: collection, Negate: true}
}

// Depth returns the nesting depth of a condition. A nil condition has depth 0
// and a single comparison has depth 1.
func Depth(n Node) int {
	switch v := n.(type) {
	case nil:
		return 0
	case Logic:
		deepest := 0
		for _, op := range v.Operands {
			if d := Depth(op); d > deepest {
				deepest = d
			}
		}
		return deepest + 1
	default:
		return 1
	}
}

// Count returns the number of condition nodes in a condition, counting operands
// as well as the nodes that hold them. It is the measure an apply payload limit
// is expressed in.
func Count(n Node) int {
	switch v := n.(type) {
	case nil:
		return 0
	case Logic:
		total := 1
		for _, op := range v.Operands {
			total += Count(op)
		}
		return total
	case Compare:
		return 1 + countOperand(v.Left) + countOperand(v.Right)
	case Member:
		return 1 + countOperand(v.Left) + countOperand(v.Collection)
	default:
		return 1
	}
}

func countOperand(o Operand) int {
	if s, ok := o.(SourceRef); ok {
		total := 1
		for _, a := range s.Args {
			total += countOperand(a)
		}
		return total
	}
	return 1
}
