package engine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter"
)

// factsVar is the activation slot the resolved fact table travels in.
//
// It is deliberately not a declared CEL variable. The checker only knows the
// names the schema declares, so no condition can ever name this slot; only the
// engine's own fact-call interpretable reads it.
const factsVar = "stamp.facts"

// sourcePrefix is the namespace every fact source function is bound under. It
// is derived from the policy package's own naming function rather than spelled
// out again here, so the two cannot drift.
var sourcePrefix = policy.CELSourceFunction("")

// ErrUndeclaredAttribute reports evaluation input carrying an attribute the
// schema does not declare for that entity type.
var ErrUndeclaredAttribute = errors.New("undeclared attribute")

// ErrUnresolvedFact reports a condition reaching a fact source call that the
// resolver did not answer before evaluation began.
var ErrUnresolvedFact = errors.New("unresolved fact source call")

// SourceCall is one invocation of a declared fact source, with its arguments
// already reduced to values.
//
// Every argument is computable from the request alone — the AST forbids a
// source call from taking another source call as an argument — so the whole set
// of calls a condition needs is known before any condition is evaluated. That is
// what lets fact resolution happen in one batch, under the caller's context and
// deadline, instead of as I/O smuggled into the middle of a CEL evaluation.
type SourceCall struct {
	// Name is the declared source name, without the CEL namespace prefix.
	Name string
	// Args are the positional argument values, in declaration order.
	Args []any
}

// String renders a call in a stable, human-readable form.
func (c SourceCall) String() string {
	parts := make([]string, len(c.Args))
	for i, a := range c.Args {
		parts[i] = canonical(a)
	}
	return c.Name + "(" + strings.Join(parts, ", ") + ")"
}

// key returns the canonical lookup key for a call. Two calls with equal names
// and equal argument values produce the same key, which is what lets one
// resolution serve every site that asks for it.
func (c SourceCall) key() string {
	var b strings.Builder
	b.WriteString(c.Name)
	for _, a := range c.Args {
		b.WriteByte(0x1f)
		b.WriteString(canonical(a))
	}
	return b.String()
}

// canonical renders a value in a form that is unique per (type, value) pair, so
// that a string 1 and an int 1 never collide in a cache key.
func canonical(v any) string {
	switch x := v.(type) {
	case bool:
		return "b:" + strconv.FormatBool(x)
	case int64:
		return "i:" + strconv.FormatInt(x, 10)
	case float64:
		return "d:" + strconv.FormatFloat(x, 'g', -1, 64)
	case string:
		return "s:" + strconv.Quote(x)
	case time.Time:
		return "t:" + x.UTC().Format(time.RFC3339Nano)
	case time.Duration:
		return "u:" + strconv.FormatInt(int64(x), 10)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = canonical(e)
		}
		return "l:[" + strings.Join(parts, ",") + "]"
	default:
		return fmt.Sprintf("?:%T:%v", v, v)
	}
}

// Facts is the fact table resolved for one evaluation.
//
// It is filled once, before any condition runs, and read-only from then on. The
// nil table is usable and answers every lookup with "not resolved", so a policy
// set with no fact sources needs no resolver at all.
type Facts struct {
	values map[string]any
}

// NewFacts returns an empty fact table.
func NewFacts() *Facts { return &Facts{values: make(map[string]any)} }

// Set records the value a call resolved to.
func (f *Facts) Set(call SourceCall, value any) {
	if f.values == nil {
		f.values = make(map[string]any)
	}
	f.values[call.key()] = value
}

// Value returns the value recorded for a call.
func (f *Facts) Value(call SourceCall) (any, bool) {
	if f == nil || f.values == nil {
		return nil, false
	}
	v, ok := f.values[call.key()]
	return v, ok
}

// Len returns the number of resolved calls.
func (f *Facts) Len() int {
	if f == nil {
		return 0
	}
	return len(f.values)
}

// SourceResolver answers the fact source calls a condition needs, ahead of
// evaluation.
//
// The fact plane implements this; the engine only states the contract. Calls
// arrive in one batch under the caller's context so the implementation owns
// timeouts, caching, egress control, and its declared on-error behaviour — all
// of which are impossible to express from inside a CEL function binding, which
// sees neither a context nor a deadline.
//
// A resolver that returns an error fails the evaluation closed. A resolver that
// returns a table missing one of the requested calls also fails closed, at the
// moment the condition reaches that call.
type SourceResolver interface {
	ResolveSources(ctx context.Context, calls []SourceCall) (*Facts, error)
}

// Program is the compiled, reusable evaluation artifact for one policy version.
//
// A Program is immutable and safe for concurrent use. All per-request state —
// attribute values and the resolved fact table — travels in the activation, so
// one compilation serves every request against that policy version.
type Program struct {
	policy  *policy.Policy
	program cel.Program
	sites   []policy.SourceRef
}

// Policy returns the policy this program was compiled from.
func (p *Program) Policy() *policy.Policy { return p.policy }

// compileProgram turns a validated policy into a cel-go program.
//
// The condition is handed to the policy package, which builds a cel-go AST node
// by node and type-checks it. No CEL source text is assembled anywhere on this
// path. Static validation already guarantees that a validated policy compiles,
// so an error here means the caller skipped validation.
func compileProgram(s *policy.Schema, p *policy.Policy) (*Program, error) {
	env, ast, err := policy.Compile(s, p)
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", p.ID, err)
	}
	returns := make(map[string]policy.Type, len(s.Sources))
	for i := range s.Sources {
		returns[s.Sources[i].Name] = s.Sources[i].Returns
	}
	prg, err := env.Program(ast, cel.CustomDecoratorV2(factDecorator(returns)))
	if err != nil {
		return nil, fmt.Errorf("policy %q: building cel program: %w", p.ID, err)
	}
	return &Program{policy: p, program: prg, sites: collectSources(p.Condition)}, nil
}

// SourceCalls returns every fact source call the condition can reach, with
// arguments resolved against the request. Duplicate calls collapse, so a source
// referenced twice with the same arguments is resolved once.
func (p *Program) SourceCalls(b *Binding) ([]SourceCall, error) {
	if len(p.sites) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(p.sites))
	calls := make([]SourceCall, 0, len(p.sites))
	for _, site := range p.sites {
		args := make([]any, len(site.Args))
		for i, operand := range site.Args {
			v, err := b.operandValue(operand)
			if err != nil {
				return nil, fmt.Errorf("policy %q: fact source %q argument %d: %w", p.policy.ID, site.Name, i, err)
			}
			args[i] = v
		}
		call := SourceCall{Name: site.Name, Args: args}
		if _, dup := seen[call.key()]; dup {
			continue
		}
		seen[call.key()] = struct{}{}
		calls = append(calls, call)
	}
	return calls, nil
}

// Evaluate runs the condition and reports whether it holds.
//
// A policy with no condition compiles to the constant true, so the answer is
// always a plain boolean and the caller never special-cases the empty case. Any
// failure — an unresolved fact, a missing attribute, a cancelled context — is
// returned as an error rather than as a false, because "the condition did not
// hold" and "we could not tell" must not collapse into the same value on a path
// whose whole job is deciding access.
func (p *Program) Evaluate(ctx context.Context, b *Binding, facts *Facts) (bool, error) {
	out, _, err := p.program.ContextEval(ctx, b.activation(facts))
	if err != nil {
		return false, fmt.Errorf("policy %q: %w", p.policy.ID, err)
	}
	v, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("policy %q: condition produced %s, not a bool", p.policy.ID, out.Type().TypeName())
	}
	return v, nil
}

// collectSources walks a condition and returns every fact source call site, in
// a deterministic order.
func collectSources(n policy.Node) []policy.SourceRef {
	var out []policy.SourceRef
	var walkOperand func(policy.Operand)
	walkOperand = func(o policy.Operand) {
		if s, ok := o.(policy.SourceRef); ok {
			out = append(out, s)
			for _, a := range s.Args {
				walkOperand(a)
			}
		}
	}
	var walk func(policy.Node)
	walk = func(node policy.Node) {
		switch v := node.(type) {
		case policy.Logic:
			for _, child := range v.Operands {
				walk(child)
			}
		case policy.Compare:
			walkOperand(v.Left)
			walkOperand(v.Right)
		case policy.Member:
			walkOperand(v.Left)
			walkOperand(v.Collection)
		}
	}
	walk(n)
	return out
}

// Binding is one request's attribute values, already checked against the schema
// and keyed the way the compiled programs expect.
//
// It is built once per request and shared by every policy the request matches,
// which is what makes the undeclared-attribute error a property of the request
// rather than of whichever policy happened to be evaluated first.
type Binding struct {
	vars map[string]any
}

// activation returns the map handed to cel-go, with the fact table attached.
func (b *Binding) activation(facts *Facts) map[string]any {
	act := make(map[string]any, len(b.vars)+1)
	for k, v := range b.vars {
		act[k] = v
	}
	act[factsVar] = facts
	return act
}

// operandValue resolves a fact source argument against the request. Only
// literals and field references can appear here — validation rejects a source
// call nested inside another source call's arguments — so this never needs to
// evaluate anything.
func (b *Binding) operandValue(o policy.Operand) (any, error) {
	switch v := o.(type) {
	case policy.Literal:
		return coerce(v.Type, v.Data)
	case policy.FieldRef:
		key := string(v.Role) + "." + v.Attribute
		value, ok := b.vars[key]
		if !ok {
			return nil, fmt.Errorf("request carries no value for %s", key)
		}
		return value, nil
	default:
		return nil, fmt.Errorf("unsupported argument %T", o)
	}
}

// bind checks a request's attributes against the schema and reduces them to the
// activation the compiled programs read.
//
// Undeclared attributes are an error, not a silent drop: cel-go ignores
// activation keys it does not know, so a typo in an attribute name would
// otherwise change a decision with no diagnostic anywhere. Missing attributes
// are not an error here — they surface as an evaluation failure only for the
// policies that actually read them.
func bind(s *policy.Schema, in Input) (*Binding, error) {
	vars := make(map[string]any, 8)
	for _, role := range policy.Roles() {
		entity := in.entity(role)
		if entity.Type == "" {
			continue
		}
		declared, ok := s.Entity(entity.Type)
		if !ok {
			return nil, fmt.Errorf("%s: entity type %q is not declared", role, entity.Type)
		}
		undeclared := make([]string, 0)
		for name, raw := range entity.Attributes {
			attr, ok := declared.Attribute(name)
			if !ok {
				undeclared = append(undeclared, name)
				continue
			}
			value, err := coerce(attr.Type, raw)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", role, name, err)
			}
			vars[string(role)+"."+name] = value
		}
		if len(undeclared) > 0 {
			sort.Strings(undeclared)
			return nil, fmt.Errorf("%w: entity type %q does not declare %s",
				ErrUndeclaredAttribute, entity.Type, strings.Join(undeclared, ", "))
		}
	}
	return &Binding{vars: vars}, nil
}

// coerce converts a Go value to the representation the declared type uses.
//
// The widening it allows is between Go spellings of one policy type — an int
// and an int64 are both a policy int. It never crosses between policy types: a
// float is not an int and an int is not a double, because the policy type system
// has no implicit numeric conversion and introducing one here would make the
// evaluator disagree with the validator.
func coerce(t policy.Type, v any) (any, error) {
	if t.IsList() {
		return coerceList(t, v)
	}
	switch t {
	case policy.TypeBool:
		if b, ok := v.(bool); ok {
			return b, nil
		}
	case policy.TypeInt:
		switch n := v.(type) {
		case int:
			return int64(n), nil
		case int8:
			return int64(n), nil
		case int16:
			return int64(n), nil
		case int32:
			return int64(n), nil
		case int64:
			return n, nil
		}
	case policy.TypeDouble:
		switch n := v.(type) {
		case float32:
			return float64(n), nil
		case float64:
			return n, nil
		}
	case policy.TypeString:
		if s, ok := v.(string); ok {
			return s, nil
		}
	case policy.TypeTimestamp:
		if ts, ok := v.(time.Time); ok {
			return ts.UTC(), nil
		}
	case policy.TypeDuration:
		if d, ok := v.(time.Duration); ok {
			return d, nil
		}
	default:
		return nil, fmt.Errorf("unknown type %q", t)
	}
	return nil, fmt.Errorf("expected %s, got %T", t, v)
}

// coerceList converts any Go slice or array to a []any of coerced elements.
func coerceList(t policy.Type, v any) (any, error) {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() || (rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array) {
		return nil, fmt.Errorf("expected %s, got %T", t, v)
	}
	out := make([]any, rv.Len())
	for i := range out {
		elem, err := coerce(t.Elem(), rv.Index(i).Interface())
		if err != nil {
			return nil, fmt.Errorf("element %d: %w", i, err)
		}
		out[i] = elem
	}
	return out, nil
}

// factDecorator replaces every planned call to a declared fact source with a
// lookup into the fact table carried by the activation.
//
// This is the whole of the engine's coupling to cel-go's interpreter. Binding
// the sources as ordinary CEL functions instead would force the resolver to run
// inside evaluation, where there is no context and no deadline, and would make
// the program per-request rather than per-policy-version — the compile cache
// measures that difference in orders of magnitude.
func factDecorator(returns map[string]policy.Type) interpreter.InterpretableDecoratorV2 {
	return func(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
		call, ok := i.(interpreter.InterpretableCall)
		if !ok {
			return i, nil
		}
		name, found := strings.CutPrefix(call.Function(), sourcePrefix)
		if !found {
			return i, nil
		}
		declared, ok := returns[name]
		if !ok {
			return nil, fmt.Errorf("condition calls undeclared fact source %q", name)
		}
		return &factCall{id: call.ID(), name: name, returns: declared, args: call.Args()}, nil
	}
}

// factCall is the interpretable a fact source call plans to.
type factCall struct {
	id      int64
	name    string
	returns policy.Type
	args    []interpreter.InterpretableV2
}

// ID reports the expression node this interpretable came from.
func (c *factCall) ID() int64 { return c.id }

// Exec evaluates the call within an execution frame.
func (c *factCall) Exec(f *interpreter.ExecutionFrame) ref.Val {
	vals := make([]ref.Val, len(c.args))
	for i, arg := range c.args {
		vals[i] = arg.Exec(f)
	}
	return c.lookup(f, vals)
}

// Eval evaluates the call against an activation.
func (c *factCall) Eval(a interpreter.Activation) ref.Val {
	vals := make([]ref.Val, len(c.args))
	for i, arg := range c.args {
		vals[i] = arg.Eval(a)
	}
	return c.lookup(a, vals)
}

func (c *factCall) lookup(a interpreter.Activation, vals []ref.Val) ref.Val {
	args := make([]any, len(vals))
	for i, v := range vals {
		if types.IsUnknownOrError(v) {
			return v
		}
		native, err := nativeOf(v)
		if err != nil {
			return types.WrapErr(fmt.Errorf("fact source %q argument %d: %w", c.name, i, err))
		}
		args[i] = native
	}
	call := SourceCall{Name: c.name, Args: args}
	raw, ok := a.ResolveName(factsVar)
	if !ok {
		return types.WrapErr(fmt.Errorf("%w: %s", ErrUnresolvedFact, call))
	}
	facts, _ := raw.(*Facts)
	value, ok := facts.Value(call)
	if !ok {
		return types.WrapErr(fmt.Errorf("%w: %s", ErrUnresolvedFact, call))
	}
	coerced, err := coerce(c.returns, value)
	if err != nil {
		return types.WrapErr(fmt.Errorf("fact source %q returned a value that is not %s: %w", c.name, c.returns, err))
	}
	return types.DefaultTypeAdapter.NativeToValue(coerced)
}

// nativeOf converts a CEL value back to the Go value the policy type system
// uses. The switch is closed over exactly the types the schema can declare.
func nativeOf(v ref.Val) (any, error) {
	switch t := v.(type) {
	case types.Bool:
		return bool(t), nil
	case types.Int:
		return int64(t), nil
	case types.Double:
		return float64(t), nil
	case types.String:
		return string(t), nil
	case types.Duration:
		return t.Duration, nil
	case types.Timestamp:
		return t.UTC(), nil
	}
	lister, ok := v.(traits.Lister)
	if !ok {
		return nil, fmt.Errorf("unsupported value of CEL type %s", v.Type().TypeName())
	}
	size, ok := lister.Size().(types.Int)
	if !ok {
		return nil, fmt.Errorf("list of CEL type %s has no size", v.Type().TypeName())
	}
	out := make([]any, 0, int(size))
	for i := types.Int(0); i < size; i++ {
		elem, err := nativeOf(lister.Get(i))
		if err != nil {
			return nil, err
		}
		out = append(out, elem)
	}
	return out, nil
}
