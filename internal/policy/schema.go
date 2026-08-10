// Package policy defines STAMP's typed policy schema, the structured condition
// AST that policies are written in, the human-writable exchange format, and the
// static validator that guards the door into the engine.
//
// Three properties hold the package together.
//
// The condition AST carries only nodes a form builder can render — comparison,
// set membership, logical combination, and reference to a declared fact source.
// There is deliberately no arbitrary function-call node: the absence of an
// escape hatch is what makes "every policy can be drawn as a form" a structural
// guarantee rather than a convention.
//
// The exchange format is designed for a person writing YAML by hand and reading
// it back in a diff, not for the convenience of the serializer. It is not a dump
// of the AST node tree. A policy's identity comes from the `id` field inside its
// document and never from the file it happens to live in, so moving or renaming
// a file is not mistaken for a delete plus a create.
//
// Validation rejects type mismatches, undeclared sources, and undeclared fields
// before a policy is ever stored, and finishes by compiling the condition
// through cel-go so that "passed validation" implies "compiles". Failures come
// back as structured diagnostics — a JSON Pointer into the document, a stable
// error code, and a human-readable message — so a form can map an error back to
// the field that caused it.
package policy

import (
	"regexp"
	"sort"
	"strings"
)

// Type names a value type in the policy type system.
//
// The type system is a proper subset of CEL's: six scalar types plus
// homogeneous lists of them. There are no implicit numeric conversions — an int
// never compares against a double — and timestamp and duration keep CEL's own
// semantics rather than being smuggled through as strings.
type Type string

// The scalar types. A list type is written list<elem> and built with ListOf.
const (
	TypeBool      Type = "bool"
	TypeInt       Type = "int"
	TypeDouble    Type = "double"
	TypeString    Type = "string"
	TypeTimestamp Type = "timestamp"
	TypeDuration  Type = "duration"
)

// ScalarTypes returns every scalar type, in declaration order.
func ScalarTypes() []Type {
	return []Type{TypeBool, TypeInt, TypeDouble, TypeString, TypeTimestamp, TypeDuration}
}

// ListOf returns the list type whose elements have type elem.
func ListOf(elem Type) Type { return Type("list<" + string(elem) + ">") }

// IsList reports whether t is a list type.
func (t Type) IsList() bool {
	return strings.HasPrefix(string(t), "list<") && strings.HasSuffix(string(t), ">")
}

// Elem returns the element type of a list type, or the empty Type if t is not a
// list.
func (t Type) Elem() Type {
	if !t.IsList() {
		return ""
	}
	return Type(strings.TrimSuffix(strings.TrimPrefix(string(t), "list<"), ">"))
}

// IsScalar reports whether t is one of the scalar types.
func (t Type) IsScalar() bool {
	for _, s := range ScalarTypes() {
		if t == s {
			return true
		}
	}
	return false
}

// Valid reports whether t is a scalar type or a list of scalars.
func (t Type) Valid() bool {
	if t.IsList() {
		return t.Elem().IsScalar()
	}
	return t.IsScalar()
}

// IsOrdered reports whether values of type t may be compared with lt, le, gt,
// and ge. Booleans and lists are equality-only.
func (t Type) IsOrdered() bool {
	switch t {
	case TypeInt, TypeDouble, TypeString, TypeTimestamp, TypeDuration:
		return true
	default:
		return false
	}
}

// Role names the position an entity occupies in an access request. The three
// roles mirror AuthZEN's request shape and are the only prefixes a field
// reference may use.
type Role string

// The entity roles a policy may bind.
const (
	RoleSubject  Role = "subject"
	RoleResource Role = "resource"
	RoleContext  Role = "context"
)

// Roles returns every role, in declaration order.
func Roles() []Role { return []Role{RoleSubject, RoleResource, RoleContext} }

// Valid reports whether r is one of the declared roles.
func (r Role) Valid() bool {
	for _, k := range Roles() {
		if r == k {
			return true
		}
	}
	return false
}

// SourceKind names the fact source implementation a declaration selects. U2
// records the kind as part of the signature; the implementations and their
// per-kind transport configuration belong to the fact-plane unit.
type SourceKind string

// The fact source kinds.
const (
	SourceStatic   SourceKind = "static"
	SourceHTTP     SourceKind = "http"
	SourceEvent    SourceKind = "event"
	SourceIdPGroup SourceKind = "idp_group"
)

// SourceKinds returns every source kind, in declaration order.
func SourceKinds() []SourceKind {
	return []SourceKind{SourceStatic, SourceHTTP, SourceEvent, SourceIdPGroup}
}

// Valid reports whether k is one of the declared source kinds.
func (k SourceKind) Valid() bool {
	for _, s := range SourceKinds() {
		if k == s {
			return true
		}
	}
	return false
}

// OnError says how evaluation behaves when a fact source fails.
type OnError string

// The fact source failure behaviours. Fail-open is only meaningful when the
// operator has also enabled it at deployment level; the declaration alone never
// grants it.
const (
	OnErrorDeny  OnError = "deny"
	OnErrorAllow OnError = "allow"
)

// DefaultOnError is the failure behaviour a declaration gets when it says
// nothing. Normalization writes it in on load and omits it again on export, so
// a hand-written document never has to spell out the safe default.
const DefaultOnError = OnErrorDeny

// Valid reports whether e is one of the declared failure behaviours.
func (e OnError) Valid() bool { return e == OnErrorDeny || e == OnErrorAllow }

// Attribute declares one typed attribute of an entity type.
type Attribute struct {
	Name string
	Type Type
}

// EntityType declares an entity and the attributes a condition may read from
// it.
type EntityType struct {
	Name       string
	Attributes []Attribute
}

// Attribute looks up a declared attribute by name.
func (e *EntityType) Attribute(name string) (Attribute, bool) {
	for _, a := range e.Attributes {
		if a.Name == name {
			return a, true
		}
	}
	return Attribute{}, false
}

// Action declares an operation a policy can govern.
type Action struct {
	Name        string
	Description string
}

// Param declares one positional parameter of a fact source. Parameter order is
// part of the signature, so params are never reordered by normalization.
type Param struct {
	Name string
	Type Type
}

// SourceDecl declares a fact source signature: what it is called, which
// implementation kind serves it, what arguments it takes, what it returns, and
// what happens when it fails.
type SourceDecl struct {
	Name    string
	Kind    SourceKind
	Params  []Param
	Returns Type
	OnError OnError
}

// Schema holds the entity, action, and source declarations a policy set is
// written against.
type Schema struct {
	Entities []EntityType
	Actions  []Action
	Sources  []SourceDecl
}

// Entity looks up a declared entity type by name.
func (s *Schema) Entity(name string) (*EntityType, bool) {
	for i := range s.Entities {
		if s.Entities[i].Name == name {
			return &s.Entities[i], true
		}
	}
	return nil, false
}

// Source looks up a declared fact source by name.
func (s *Schema) Source(name string) (*SourceDecl, bool) {
	for i := range s.Sources {
		if s.Sources[i].Name == name {
			return &s.Sources[i], true
		}
	}
	return nil, false
}

// HasAction reports whether an action of that name is declared.
func (s *Schema) HasAction(name string) bool {
	for _, a := range s.Actions {
		if a.Name == name {
			return true
		}
	}
	return false
}

// Policy is one governed rule: which entity types and actions it applies to,
// and the condition under which it applies.
//
// ID is the policy's identity and comes from the document, never from a
// filename. Context is optional; a policy that does not bind it cannot
// reference context fields.
type Policy struct {
	ID          string
	Description string
	Subject     string
	Resource    string
	Context     string
	Actions     []string
	Condition   Node
}

// EntityFor returns the entity type name bound to a role, and whether the
// policy binds that role at all.
func (p *Policy) EntityFor(r Role) (string, bool) {
	switch r {
	case RoleSubject:
		return p.Subject, p.Subject != ""
	case RoleResource:
		return p.Resource, p.Resource != ""
	case RoleContext:
		return p.Context, p.Context != ""
	default:
		return "", false
	}
}

// Set is a schema together with the policies written against it. It is the unit
// the file format exchanges and the unit the validator checks — a desired-state
// comparison is computed over policy identifiers, so how the documents were
// distributed across files never enters into it.
type Set struct {
	Schema   Schema
	Policies []Policy
}

// Policy looks up a policy by identifier.
func (s *Set) Policy(id string) (*Policy, bool) {
	for i := range s.Policies {
		if s.Policies[i].ID == id {
			return &s.Policies[i], true
		}
	}
	return nil, false
}

// Normalize puts a set into canonical form: declarations and policies sorted by
// name, attributes and actions sorted within their declaration, and omitted
// defaults filled in.
//
// This is what makes export followed by apply a no-op. Encoding is a
// deterministic function of the normalized set and decoding inverts it, so a
// hand-written document that omits defaults and a machine-written one that
// spells them out normalize to the same value and re-serialize identically.
//
// Source parameters keep their declared order because that order is the
// calling convention.
func (s *Set) Normalize() {
	for i := range s.Schema.Entities {
		e := &s.Schema.Entities[i]
		sort.Slice(e.Attributes, func(a, b int) bool { return e.Attributes[a].Name < e.Attributes[b].Name })
	}
	sort.Slice(s.Schema.Entities, func(a, b int) bool { return s.Schema.Entities[a].Name < s.Schema.Entities[b].Name })
	sort.Slice(s.Schema.Actions, func(a, b int) bool { return s.Schema.Actions[a].Name < s.Schema.Actions[b].Name })
	for i := range s.Schema.Sources {
		if s.Schema.Sources[i].OnError == "" {
			s.Schema.Sources[i].OnError = DefaultOnError
		}
	}
	sort.Slice(s.Schema.Sources, func(a, b int) bool { return s.Schema.Sources[a].Name < s.Schema.Sources[b].Name })
	for i := range s.Policies {
		sort.Strings(s.Policies[i].Actions)
	}
	sort.Slice(s.Policies, func(a, b int) bool { return s.Policies[a].ID < s.Policies[b].ID })
}

// identPattern is the syntax shared by entity, attribute, and source names.
// These become CEL identifiers during compilation, so they are held to CEL's
// identifier rules rather than to YAML's laxer key syntax.
var identPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// namePattern is the looser syntax for names that never become CEL
// identifiers: policy identifiers and action names.
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// ValidIdent reports whether name may be used as an entity, attribute, or
// source name.
func ValidIdent(name string) bool { return identPattern.MatchString(name) }

// ValidName reports whether name may be used as a policy identifier or an
// action name.
func ValidName(name string) bool { return namePattern.MatchString(name) }
