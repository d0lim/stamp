package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	celtypes "github.com/google/cel-go/common/types"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// Code identifies a class of validation failure. Codes are stable: a form maps
// them to its own wording, and a CLI matches on them, so neither is parsing
// English.
type Code string

// The validation failure codes.
const (
	CodeInvalidYAML       Code = "invalid_yaml"
	CodeInvalidDocument   Code = "invalid_document"
	CodeUnknownAPIVersion Code = "unknown_api_version"
	CodeUnknownKind       Code = "unknown_kind"
	CodeUnknownKey        Code = "unknown_key"
	CodeMissingField      Code = "missing_field"
	CodeInvalidName       Code = "invalid_name"
	CodeInvalidValue      Code = "invalid_value"
	CodeUnknownType       Code = "unknown_type"
	CodeDuplicate         Code = "duplicate"
	CodeUnknownEntity     Code = "unknown_entity"
	CodeUnknownAction     Code = "unknown_action"
	CodeUnknownAttribute  Code = "unknown_attribute"
	CodeUnboundRole       Code = "unbound_role"
	CodeUnknownSource     Code = "unknown_source"
	CodeTypeMismatch      Code = "type_mismatch"
	CodeArityMismatch     Code = "arity_mismatch"
	CodeInvalidOperand    Code = "invalid_operand"
	CodeInvalidOperator   Code = "invalid_operator"
	CodeLimitExceeded     Code = "limit_exceeded"
	CodeCELCompile        Code = "cel_compile"
)

// Diagnostic is one structured validation failure.
//
// The three parts are the whole contract. Pointer is an RFC 6901 JSON Pointer
// into the policy set as the format encodes it, which is what lets a form put
// the message next to the field that caused it. Code is machine-readable and
// stable. Message is for a person.
type Diagnostic struct {
	Pointer string `json:"pointer"`
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

// Error renders a diagnostic as one line.
func (d Diagnostic) Error() string {
	return fmt.Sprintf("%s: %s: %s", d.Pointer, d.Code, d.Message)
}

// Diagnostics is an ordered collection of validation failures. The zero-length
// value means the input is valid.
type Diagnostics []Diagnostic

// Error renders every diagnostic, one per line.
func (ds Diagnostics) Error() string {
	parts := make([]string, len(ds))
	for i, d := range ds {
		parts[i] = d.Error()
	}
	return strings.Join(parts, "\n")
}

// Has reports whether any diagnostic carries the given code.
func (ds Diagnostics) Has(code Code) bool {
	for _, d := range ds {
		if d.Code == code {
			return true
		}
	}
	return false
}

// At returns the diagnostics recorded at exactly the given pointer.
func (ds Diagnostics) At(pointer string) Diagnostics {
	var out Diagnostics
	for _, d := range ds {
		if d.Pointer == pointer {
			out = append(out, d)
		}
	}
	return out
}

// Limits bound the size of an accepted policy set. An apply payload that
// exceeds the byte limit is rejected before it is parsed; the structural limits
// are checked during validation.
type Limits struct {
	MaxDocumentBytes  int
	MaxPolicies       int
	MaxConditionNodes int
	MaxConditionDepth int
}

// DefaultLimits returns the limits applied when a caller does not supply its
// own.
//
// MaxConditionDepth is set far below cel-go's own nesting ceiling. Conjunctions
// compile to balanced trees rather than left-nested chains, so a wide All never
// turns operand count into CEL nesting depth.
func DefaultLimits() Limits {
	return Limits{
		MaxDocumentBytes:  1 << 20,
		MaxPolicies:       1000,
		MaxConditionNodes: 512,
		MaxConditionDepth: 32,
	}
}

// Validate checks a policy set and returns every failure it finds. A nil result
// means the set is safe to store.
//
// The final step compiles each condition through cel-go, so a set that
// validates is a set that compiles. Without that step a policy could clear the
// form's preflight and then fail at the moment it is saved.
func Validate(s *Set) Diagnostics {
	return ValidateWithLimits(s, DefaultLimits())
}

// ValidateWithLimits is Validate with caller-supplied size limits.
func ValidateWithLimits(s *Set, limits Limits) Diagnostics {
	diags := validateStatic(s, limits)
	if len(diags) > 0 {
		// The compile step assumes a well-typed AST. Running it on a set that
		// already failed static checks would report cel-go's wording for
		// mistakes we have better messages for.
		return diags
	}
	for i := range s.Policies {
		if _, _, err := Compile(&s.Schema, &s.Policies[i]); err != nil {
			diags = append(diags, Diagnostic{
				Pointer: jptr("policies", i, "condition"),
				Code:    CodeCELCompile,
				Message: fmt.Sprintf("policy %q passed static validation but cel-go rejected it: %v", s.Policies[i].ID, err),
			})
		}
	}
	return diags
}

// validateStatic runs every check that does not involve cel-go. It is separated
// from the compile step so that the property test can assert the invariant that
// matters: anything this accepts, cel-go compiles.
func validateStatic(s *Set, limits Limits) Diagnostics {
	v := &validator{limits: limits}
	v.schema(&s.Schema)
	if limits.MaxPolicies > 0 && len(s.Policies) > limits.MaxPolicies {
		v.add("policies", CodeLimitExceeded,
			fmt.Sprintf("policy set holds %d policies, limit is %d", len(s.Policies), limits.MaxPolicies))
	}
	seen := map[string]int{}
	for i := range s.Policies {
		p := &s.Policies[i]
		if first, dup := seen[p.ID]; dup && p.ID != "" {
			v.add(jptr("policies", i, "id"), CodeDuplicate,
				fmt.Sprintf("policy id %q is already used at /policies/%d", p.ID, first))
			continue
		}
		seen[p.ID] = i
		v.policy(&s.Schema, p, jptr("policies", i))
	}
	return v.diags
}

type validator struct {
	limits Limits
	diags  Diagnostics
}

func (v *validator) add(pointer string, code Code, message string) {
	v.diags = append(v.diags, Diagnostic{Pointer: pointer, Code: code, Message: message})
}

func (v *validator) schema(s *Schema) {
	entities := map[string]int{}
	for i := range s.Entities {
		e := &s.Entities[i]
		ptr := jptr("schema", "entities", i)
		if !ValidIdent(e.Name) {
			v.add(jptr("schema", "entities", i, "name"), CodeInvalidName,
				fmt.Sprintf("entity name %q must match [a-z][a-z0-9_]*", e.Name))
		}
		if first, dup := entities[e.Name]; dup {
			v.add(jptr("schema", "entities", i, "name"), CodeDuplicate,
				fmt.Sprintf("entity %q is already declared at /schema/entities/%d", e.Name, first))
		}
		entities[e.Name] = i
		attrs := map[string]int{}
		for j, a := range e.Attributes {
			aptr := jptr(ptr, "attributes", a.Name)
			if !ValidIdent(a.Name) {
				v.add(aptr, CodeInvalidName,
					fmt.Sprintf("attribute name %q must match [a-z][a-z0-9_]*", a.Name))
			}
			if first, dup := attrs[a.Name]; dup {
				v.add(aptr, CodeDuplicate,
					fmt.Sprintf("attribute %q is declared twice on entity %q (first at index %d)", a.Name, e.Name, first))
			}
			attrs[a.Name] = j
			if !a.Type.Valid() {
				v.add(aptr, CodeUnknownType, fmt.Sprintf("unknown type %q", a.Type))
			}
		}
	}

	actions := map[string]int{}
	for i, a := range s.Actions {
		if !ValidName(a.Name) {
			v.add(jptr("schema", "actions", i, "name"), CodeInvalidName,
				fmt.Sprintf("action name %q must match [a-z0-9][a-z0-9._-]*", a.Name))
		}
		if first, dup := actions[a.Name]; dup {
			v.add(jptr("schema", "actions", i, "name"), CodeDuplicate,
				fmt.Sprintf("action %q is already declared at /schema/actions/%d", a.Name, first))
		}
		actions[a.Name] = i
	}

	sources := map[string]int{}
	for i := range s.Sources {
		src := &s.Sources[i]
		ptr := jptr("schema", "sources", i)
		if !ValidIdent(src.Name) {
			v.add(jptr(ptr, "name"), CodeInvalidName,
				fmt.Sprintf("source name %q must match [a-z][a-z0-9_]*", src.Name))
		}
		if first, dup := sources[src.Name]; dup {
			v.add(jptr(ptr, "name"), CodeDuplicate,
				fmt.Sprintf("source %q is already declared at /schema/sources/%d", src.Name, first))
		}
		sources[src.Name] = i
		if !src.Kind.Valid() {
			v.add(jptr(ptr, "kind"), CodeInvalidValue, fmt.Sprintf("unknown source kind %q", src.Kind))
		}
		if src.OnError != "" && !src.OnError.Valid() {
			v.add(jptr(ptr, "on_error"), CodeInvalidValue,
				fmt.Sprintf("on_error must be deny or allow, got %q", src.OnError))
		}
		if !src.Returns.Valid() {
			v.add(jptr(ptr, "returns"), CodeUnknownType, fmt.Sprintf("unknown type %q", src.Returns))
		}
		params := map[string]int{}
		for j, p := range src.Params {
			pptr := jptr(ptr, "params", j)
			if !ValidIdent(p.Name) {
				v.add(pptr, CodeInvalidName,
					fmt.Sprintf("parameter name %q must match [a-z][a-z0-9_]*", p.Name))
			}
			if first, dup := params[p.Name]; dup {
				v.add(pptr, CodeDuplicate,
					fmt.Sprintf("parameter %q is declared twice on source %q (first at index %d)", p.Name, src.Name, first))
			}
			params[p.Name] = j
			if !p.Type.Valid() {
				v.add(pptr, CodeUnknownType, fmt.Sprintf("unknown type %q", p.Type))
			}
		}
	}
}

func (v *validator) policy(s *Schema, p *Policy, ptr string) {
	if p.ID == "" {
		v.add(jptr(ptr, "id"), CodeMissingField, "policy has no id; identity comes from this field, never from the filename")
	} else if !ValidName(p.ID) {
		v.add(jptr(ptr, "id"), CodeInvalidName,
			fmt.Sprintf("policy id %q must match [a-z0-9][a-z0-9._-]*", p.ID))
	}

	for _, r := range []Role{RoleSubject, RoleResource} {
		name, bound := p.EntityFor(r)
		if !bound {
			v.add(jptr(ptr, string(r)), CodeMissingField, fmt.Sprintf("policy must bind a %s entity type", r))
			continue
		}
		if _, ok := s.Entity(name); !ok {
			v.add(jptr(ptr, string(r)), CodeUnknownEntity, fmt.Sprintf("entity type %q is not declared", name))
		}
	}
	if p.Context != "" {
		if _, ok := s.Entity(p.Context); !ok {
			v.add(jptr(ptr, "context"), CodeUnknownEntity, fmt.Sprintf("entity type %q is not declared", p.Context))
		}
	}

	if len(p.Actions) == 0 {
		v.add(jptr(ptr, "actions"), CodeMissingField, "policy must govern at least one action")
	}
	seen := map[string]bool{}
	for i, a := range p.Actions {
		aptr := jptr(ptr, "actions", i)
		if seen[a] {
			v.add(aptr, CodeDuplicate, fmt.Sprintf("action %q is listed twice", a))
		}
		seen[a] = true
		if !s.HasAction(a) {
			v.add(aptr, CodeUnknownAction, fmt.Sprintf("action %q is not declared", a))
		}
	}

	if p.Condition == nil {
		return
	}
	cptr := jptr(ptr, "condition")
	if d := Depth(p.Condition); v.limits.MaxConditionDepth > 0 && d > v.limits.MaxConditionDepth {
		v.add(cptr, CodeLimitExceeded,
			fmt.Sprintf("condition nests %d levels deep, limit is %d", d, v.limits.MaxConditionDepth))
		return
	}
	if n := Count(p.Condition); v.limits.MaxConditionNodes > 0 && n > v.limits.MaxConditionNodes {
		v.add(cptr, CodeLimitExceeded,
			fmt.Sprintf("condition holds %d nodes, limit is %d", n, v.limits.MaxConditionNodes))
		return
	}
	v.condition(s, p, p.Condition, cptr)
}

func (v *validator) condition(s *Schema, p *Policy, n Node, ptr string) {
	switch node := n.(type) {
	case Logic:
		if !node.Op.Valid() {
			v.add(ptr, CodeInvalidOperator, fmt.Sprintf("unknown logical operator %q", node.Op))
			return
		}
		if len(node.Operands) == 0 {
			v.add(jptr(ptr, string(node.Op)), CodeMissingField,
				fmt.Sprintf("%q needs at least one operand", node.Op))
			return
		}
		if node.Op == LogicNot {
			if len(node.Operands) != 1 {
				v.add(jptr(ptr, "not"), CodeArityMismatch,
					fmt.Sprintf("\"not\" takes exactly one operand, got %d", len(node.Operands)))
				return
			}
			v.condition(s, p, node.Operands[0], jptr(ptr, "not"))
			return
		}
		for i, operand := range node.Operands {
			v.condition(s, p, operand, jptr(ptr, string(node.Op), i))
		}
	case Compare:
		if !node.Op.Valid() {
			v.add(jptr(ptr, "op"), CodeInvalidOperator, fmt.Sprintf("unknown comparison operator %q", node.Op))
			return
		}
		left, leftOK := v.operandType(s, p, node.Left, jptr(ptr, "left"), false)
		right, rightOK := v.operandType(s, p, node.Right, jptr(ptr, "right"), false)
		if !leftOK || !rightOK {
			return
		}
		if left != right {
			v.add(jptr(ptr, "right"), CodeTypeMismatch, mismatchMessage(left, right))
			return
		}
		if node.Op.Ordering() && !left.IsOrdered() {
			v.add(jptr(ptr, "op"), CodeInvalidOperator,
				fmt.Sprintf("operator %q needs an ordered type, but both sides are %s", node.Op, left))
		}
	case Member:
		left, leftOK := v.operandType(s, p, node.Left, jptr(ptr, "left"), false)
		key := "in"
		if node.Negate {
			key = "not_in"
		}
		coll, collOK := v.operandType(s, p, node.Collection, jptr(ptr, key), false)
		if !leftOK || !collOK {
			return
		}
		if !coll.IsList() {
			v.add(jptr(ptr, key), CodeTypeMismatch,
				fmt.Sprintf("membership needs a list on the right, got %s", coll))
			return
		}
		if coll.Elem() != left {
			v.add(jptr(ptr, key), CodeTypeMismatch,
				fmt.Sprintf("cannot look for a %s in a %s", left, coll))
		}
	case nil:
		v.add(ptr, CodeInvalidDocument, "condition node is empty")
	default:
		v.add(ptr, CodeInvalidDocument, fmt.Sprintf("unsupported condition node %T", n))
	}
}

// operandType resolves an operand's type against the schema, reporting the
// first reason it cannot. nested marks operands that appear as source-call
// arguments, where a further source call is not allowed.
func (v *validator) operandType(s *Schema, p *Policy, o Operand, ptr string, nested bool) (Type, bool) {
	switch operand := o.(type) {
	case FieldRef:
		if !operand.Role.Valid() {
			v.add(ptr, CodeInvalidValue, fmt.Sprintf("unknown entity role %q", operand.Role))
			return "", false
		}
		entityName, bound := p.EntityFor(operand.Role)
		if !bound {
			v.add(ptr, CodeUnboundRole,
				fmt.Sprintf("policy binds no %s entity, so %s.%s cannot be read", operand.Role, operand.Role, operand.Attribute))
			return "", false
		}
		entity, ok := s.Entity(entityName)
		if !ok {
			v.add(ptr, CodeUnknownEntity, fmt.Sprintf("entity type %q is not declared", entityName))
			return "", false
		}
		attr, ok := entity.Attribute(operand.Attribute)
		if !ok {
			v.add(ptr, CodeUnknownAttribute,
				fmt.Sprintf("entity %q declares no attribute %q", entityName, operand.Attribute))
			return "", false
		}
		if !attr.Type.Valid() {
			v.add(ptr, CodeUnknownType, fmt.Sprintf("attribute %q has unknown type %q", operand.Attribute, attr.Type))
			return "", false
		}
		return attr.Type, true
	case SourceRef:
		if nested {
			v.add(ptr, CodeInvalidOperand, "a fact source argument may not itself be a fact source call")
			return "", false
		}
		decl, ok := s.Source(operand.Name)
		if !ok {
			v.add(ptr, CodeUnknownSource, fmt.Sprintf("fact source %q is not declared", operand.Name))
			return "", false
		}
		if len(operand.Args) != len(decl.Params) {
			v.add(ptr, CodeArityMismatch,
				fmt.Sprintf("fact source %q takes %d argument(s), got %d", decl.Name, len(decl.Params), len(operand.Args)))
			return "", false
		}
		ok = true
		for i, arg := range operand.Args {
			argType, argOK := v.operandType(s, p, arg, jptr(ptr, "args", i), true)
			if !argOK {
				ok = false
				continue
			}
			if argType != decl.Params[i].Type {
				v.add(jptr(ptr, "args", i), CodeTypeMismatch,
					fmt.Sprintf("parameter %q of fact source %q is %s, got %s",
						decl.Params[i].Name, decl.Name, decl.Params[i].Type, argType))
				ok = false
			}
		}
		if !ok {
			return "", false
		}
		if !decl.Returns.Valid() {
			v.add(ptr, CodeUnknownType, fmt.Sprintf("fact source %q returns unknown type %q", decl.Name, decl.Returns))
			return "", false
		}
		return decl.Returns, true
	case Literal:
		if !operand.Type.Valid() {
			v.add(ptr, CodeUnknownType, fmt.Sprintf("unknown type %q", operand.Type))
			return "", false
		}
		if err := checkLiteralData(operand); err != nil {
			v.add(ptr, CodeInvalidValue, err.Error())
			return "", false
		}
		return operand.Type, true
	case nil:
		v.add(ptr, CodeMissingField, "operand is missing")
		return "", false
	default:
		v.add(ptr, CodeInvalidOperand, fmt.Sprintf("unsupported operand %T", o))
		return "", false
	}
}

func mismatchMessage(left, right Type) string {
	msg := fmt.Sprintf("cannot compare %s with %s", left, right)
	if (left == TypeDouble && right == TypeInt) || (left == TypeInt && right == TypeDouble) {
		msg += "; there are no implicit numeric conversions, so write the literal as " +
			"10.0 for a double or use {value: 10, type: double}"
	}
	return msg
}

// checkLiteralData verifies that a literal's Go value matches its declared
// type. A hand-written document cannot produce a mismatch, but a caller
// building the AST in Go can.
func checkLiteralData(l Literal) error {
	if l.Type.IsList() {
		items, ok := l.Data.([]any)
		if !ok {
			return fmt.Errorf("literal of type %s must hold []any, got %T", l.Type, l.Data)
		}
		elem := l.Type.Elem()
		for i, item := range items {
			if err := checkScalarData(elem, item); err != nil {
				return fmt.Errorf("element %d: %w", i, err)
			}
		}
		return nil
	}
	return checkScalarData(l.Type, l.Data)
}

func checkScalarData(t Type, data any) error {
	var ok bool
	switch t {
	case TypeBool:
		_, ok = data.(bool)
	case TypeInt:
		_, ok = data.(int64)
	case TypeDouble:
		_, ok = data.(float64)
	case TypeString:
		_, ok = data.(string)
	case TypeTimestamp:
		_, ok = data.(time.Time)
	case TypeDuration:
		_, ok = data.(time.Duration)
	default:
		return fmt.Errorf("unknown type %q", t)
	}
	if !ok {
		return fmt.Errorf("literal of type %s cannot hold a %T", t, data)
	}
	return nil
}

// jptr builds an RFC 6901 JSON Pointer. Segments are strings, ints, or an
// already-built pointer used as a prefix.
func jptr(segments ...any) string {
	var b strings.Builder
	for _, seg := range segments {
		switch s := seg.(type) {
		case string:
			if strings.HasPrefix(s, "/") {
				b.WriteString(s)
				continue
			}
			b.WriteByte('/')
			b.WriteString(escapePointerToken(s))
		case int:
			b.WriteByte('/')
			b.WriteString(strconv.Itoa(s))
		default:
			b.WriteByte('/')
			b.WriteString(escapePointerToken(fmt.Sprint(seg)))
		}
	}
	return b.String()
}

func escapePointerToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// CELEnv builds the cel-go environment a policy's condition is checked and
// evaluated in.
//
// Every attribute of every bound entity role becomes a qualified variable
// (subject.amount), and every declared fact source becomes a namespaced
// function with a fixed overload. Nothing else is in scope, which is the second
// half of the guarantee the AST makes: a condition cannot name anything the
// schema did not declare, and the checker enforces it independently of our own
// walk.
func CELEnv(s *Schema, p *Policy) (*cel.Env, error) {
	opts := make([]cel.EnvOption, 0, 16)
	for _, role := range Roles() {
		entityName, bound := p.EntityFor(role)
		if !bound {
			continue
		}
		entity, ok := s.Entity(entityName)
		if !ok {
			return nil, fmt.Errorf("entity type %q is not declared", entityName)
		}
		for _, attr := range entity.Attributes {
			t, err := celType(attr.Type)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", role, attr.Name, err)
			}
			opts = append(opts, cel.Variable(string(role)+"."+attr.Name, t))
		}
	}
	for i := range s.Sources {
		src := &s.Sources[i]
		params := make([]*cel.Type, len(src.Params))
		for j, param := range src.Params {
			t, err := celType(param.Type)
			if err != nil {
				return nil, fmt.Errorf("source %s parameter %s: %w", src.Name, param.Name, err)
			}
			params[j] = t
		}
		ret, err := celType(src.Returns)
		if err != nil {
			return nil, fmt.Errorf("source %s return: %w", src.Name, err)
		}
		opts = append(opts, cel.Function(CELSourceFunction(src.Name),
			cel.Overload(celSourceOverload(src.Name), params, ret)))
	}
	return cel.NewEnv(opts...)
}

// CELSourceFunction returns the cel-go function name a declared fact source is
// bound to. It is namespaced so a source can never shadow a CEL builtin.
func CELSourceFunction(name string) string { return "stamp.source." + name }

func celSourceOverload(name string) string { return "stamp_source_" + name }

func celType(t Type) (*cel.Type, error) {
	if t.IsList() {
		elem, err := celType(t.Elem())
		if err != nil {
			return nil, err
		}
		return cel.ListType(elem), nil
	}
	switch t {
	case TypeBool:
		return cel.BoolType, nil
	case TypeInt:
		return cel.IntType, nil
	case TypeDouble:
		return cel.DoubleType, nil
	case TypeString:
		return cel.StringType, nil
	case TypeTimestamp:
		return cel.TimestampType, nil
	case TypeDuration:
		return cel.DurationType, nil
	default:
		return nil, fmt.Errorf("unknown type %q", t)
	}
}

// Compile turns a policy condition into a type-checked cel-go AST and returns
// the environment it was checked in.
//
// The AST is built node by node through cel-go's expression factory. No CEL
// source text is ever assembled: a string round trip would be both an injection
// surface and a lossy one, and the structured AST is the canonical form.
//
// A policy with no condition compiles to the constant true, so every validated
// policy yields a program and the caller never has to special-case the empty
// case.
func Compile(s *Schema, p *Policy) (*cel.Env, *cel.Ast, error) {
	env, err := CELEnv(s, p)
	if err != nil {
		return nil, nil, err
	}
	b := &celBuilder{fac: celast.NewExprFactory()}
	var expr celast.Expr
	if p.Condition == nil {
		expr = b.fac.NewLiteral(b.next(), celtypes.True)
	} else {
		expr, err = b.node(p.Condition)
		if err != nil {
			return nil, nil, err
		}
	}
	protoExpr, err := celast.ExprToProto(expr)
	if err != nil {
		return nil, nil, fmt.Errorf("converting condition to cel expression: %w", err)
	}
	sourceInfo, err := celast.SourceInfoToProto(celast.NewSourceInfo(nil))
	if err != nil {
		return nil, nil, fmt.Errorf("building cel source info: %w", err)
	}
	parsed := cel.ParsedExprToAst(&exprpb.ParsedExpr{Expr: protoExpr, SourceInfo: sourceInfo})
	checked, issues := env.Check(parsed)
	if issues != nil && issues.Err() != nil {
		return nil, nil, issues.Err()
	}
	if checked.OutputType() != cel.BoolType {
		return nil, nil, fmt.Errorf("condition must evaluate to bool, got %v", checked.OutputType())
	}
	return env, checked, nil
}

type celBuilder struct {
	fac celast.ExprFactory
	id  int64
}

func (b *celBuilder) next() int64 {
	b.id++
	return b.id
}

func (b *celBuilder) node(n Node) (celast.Expr, error) {
	switch node := n.(type) {
	case Logic:
		return b.logic(node)
	case Compare:
		left, err := b.operand(node.Left)
		if err != nil {
			return nil, err
		}
		right, err := b.operand(node.Right)
		if err != nil {
			return nil, err
		}
		fn, err := celCompareFunction(node.Op)
		if err != nil {
			return nil, err
		}
		return b.fac.NewCall(b.next(), fn, left, right), nil
	case Member:
		left, err := b.operand(node.Left)
		if err != nil {
			return nil, err
		}
		collection, err := b.operand(node.Collection)
		if err != nil {
			return nil, err
		}
		in := b.fac.NewCall(b.next(), "@in", left, collection)
		if node.Negate {
			return b.fac.NewCall(b.next(), "!_", in), nil
		}
		return in, nil
	default:
		return nil, fmt.Errorf("unsupported condition node %T", n)
	}
}

func (b *celBuilder) logic(node Logic) (celast.Expr, error) {
	if len(node.Operands) == 0 {
		return nil, fmt.Errorf("%q has no operands", node.Op)
	}
	operands := make([]celast.Expr, len(node.Operands))
	for i, child := range node.Operands {
		expr, err := b.node(child)
		if err != nil {
			return nil, err
		}
		operands[i] = expr
	}
	switch node.Op {
	case LogicNot:
		if len(operands) != 1 {
			return nil, fmt.Errorf("\"not\" takes exactly one operand, got %d", len(operands))
		}
		return b.fac.NewCall(b.next(), "!_", operands[0]), nil
	case LogicAll:
		return b.fold(operands, "_&&_"), nil
	case LogicAny:
		return b.fold(operands, "_||_"), nil
	default:
		return nil, fmt.Errorf("unknown logical operator %q", node.Op)
	}
}

// fold combines operands into a balanced binary tree rather than the
// left-nested chain CEL's own parser produces. Short-circuit order is
// unchanged, but a conjunction of many operands stays shallow, so a wide
// condition cannot push cel-go past its nesting ceiling.
func (b *celBuilder) fold(operands []celast.Expr, fn string) celast.Expr {
	if len(operands) == 1 {
		return operands[0]
	}
	mid := len(operands) / 2
	return b.fac.NewCall(b.next(), fn, b.fold(operands[:mid], fn), b.fold(operands[mid:], fn))
}

func (b *celBuilder) operand(o Operand) (celast.Expr, error) {
	switch operand := o.(type) {
	case FieldRef:
		return b.fac.NewSelect(b.next(),
			b.fac.NewIdent(b.next(), string(operand.Role)), operand.Attribute), nil
	case SourceRef:
		args := make([]celast.Expr, len(operand.Args))
		for i, arg := range operand.Args {
			expr, err := b.operand(arg)
			if err != nil {
				return nil, err
			}
			args[i] = expr
		}
		return b.fac.NewCall(b.next(), CELSourceFunction(operand.Name), args...), nil
	case Literal:
		return b.literal(operand)
	default:
		return nil, fmt.Errorf("unsupported operand %T", o)
	}
}

func (b *celBuilder) literal(l Literal) (celast.Expr, error) {
	if l.Type.IsList() {
		items, ok := l.Data.([]any)
		if !ok {
			return nil, fmt.Errorf("literal of type %s must hold []any, got %T", l.Type, l.Data)
		}
		elems := make([]celast.Expr, len(items))
		for i, item := range items {
			expr, err := b.literal(Literal{Type: l.Type.Elem(), Data: item})
			if err != nil {
				return nil, err
			}
			elems[i] = expr
		}
		return b.fac.NewList(b.next(), elems, nil), nil
	}
	switch l.Type {
	case TypeBool:
		v, ok := l.Data.(bool)
		if !ok {
			return nil, literalDataError(l)
		}
		return b.fac.NewLiteral(b.next(), celtypes.Bool(v)), nil
	case TypeInt:
		v, ok := l.Data.(int64)
		if !ok {
			return nil, literalDataError(l)
		}
		return b.fac.NewLiteral(b.next(), celtypes.Int(v)), nil
	case TypeDouble:
		v, ok := l.Data.(float64)
		if !ok {
			return nil, literalDataError(l)
		}
		return b.fac.NewLiteral(b.next(), celtypes.Double(v)), nil
	case TypeString:
		v, ok := l.Data.(string)
		if !ok {
			return nil, literalDataError(l)
		}
		return b.fac.NewLiteral(b.next(), celtypes.String(v)), nil
	case TypeTimestamp:
		v, ok := l.Data.(time.Time)
		if !ok {
			return nil, literalDataError(l)
		}
		// The CEL wire format has no timestamp constant, so an instant is
		// carried as a call to the standard timestamp() conversion over a
		// string constant. That is still an AST node, not assembled source.
		return b.fac.NewCall(b.next(), "timestamp",
			b.fac.NewLiteral(b.next(), celtypes.String(v.UTC().Format(time.RFC3339Nano)))), nil
	case TypeDuration:
		v, ok := l.Data.(time.Duration)
		if !ok {
			return nil, literalDataError(l)
		}
		return b.fac.NewCall(b.next(), "duration",
			b.fac.NewLiteral(b.next(), celtypes.String(v.String()))), nil
	default:
		return nil, fmt.Errorf("unknown type %q", l.Type)
	}
}

func literalDataError(l Literal) error {
	return fmt.Errorf("literal of type %s cannot hold a %T", l.Type, l.Data)
}

func celCompareFunction(op CompareOp) (string, error) {
	switch op {
	case OpEq:
		return "_==_", nil
	case OpNe:
		return "_!=_", nil
	case OpLt:
		return "_<_", nil
	case OpLe:
		return "_<=_", nil
	case OpGt:
		return "_>_", nil
	case OpGe:
		return "_>=_", nil
	default:
		return "", fmt.Errorf("unknown comparison operator %q", op)
	}
}
