package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// APIVersion is the version tag every document in the exchange format carries.
// It versions the policy schema contract, which is published under semver from
// the first release.
const APIVersion = "stamp/v1"

// The document kinds. A file is a YAML stream, and each document in it declares
// its own kind, so a schema and the policies written against it can live in one
// hand-written file or in as many files as a repository prefers.
const (
	KindSchema = "Schema"
	KindPolicy = "Policy"
)

// A Policy document holds exactly one policy. A file may hold as many documents
// as it likes.
//
// One policy per document rather than per file, because identity has to come
// from the `id` field for renames to be renames — and once identity is in the
// document, file granularity carries no meaning that a desired-state comparison
// could use. Splitting one policy per file is then a repository's convention
// rather than the format's rule, and schema declarations get somewhere natural
// to live alongside a small policy set.

// Decode reads a policy set from a YAML document stream.
//
// No filename is involved, and there is no parameter for one. A policy's
// identity is the `id` field inside its document, so moving or renaming a file
// changes nothing the engine can observe — which is what keeps a rename from
// being applied as a delete plus a create.
//
// The returned set is normalized. Decode reports malformed structure but does
// not validate against the schema; use Load for the full door check.
func Decode(r io.Reader) (*Set, error) {
	return DecodeWithLimits(r, DefaultLimits())
}

// DecodeWithLimits is Decode with caller-supplied size limits. The byte limit is
// enforced before parsing, so an oversized payload never reaches the parser.
func DecodeWithLimits(r io.Reader, limits Limits) (*Set, error) {
	data, err := readCapped(r, limits.MaxDocumentBytes)
	if err != nil {
		return nil, Diagnostics{{Pointer: "", Code: CodeLimitExceeded, Message: err.Error()}}
	}
	d := &decoder{}
	d.stream(data)
	if len(d.diags) > 0 {
		return nil, d.diags
	}
	d.set.Normalize()
	return &d.set, nil
}

// Load reads a policy set from a YAML stream and validates it. A set that Load
// returns is a set that has passed every static check and compiles under
// cel-go.
func Load(r io.Reader) (*Set, error) {
	return LoadWithLimits(r, DefaultLimits())
}

// LoadWithLimits is Load with caller-supplied size limits.
func LoadWithLimits(r io.Reader, limits Limits) (*Set, error) {
	set, err := DecodeWithLimits(r, limits)
	if err != nil {
		return nil, err
	}
	if diags := ValidateWithLimits(set, limits); len(diags) > 0 {
		return nil, diags
	}
	return set, nil
}

// LoadFS reads every .yaml and .yml file in a filesystem as one policy set and
// validates the result. It is the directory-as-desired-state entry point: the
// directory names the set, and nothing about which file a document came from
// survives into the set.
func LoadFS(fsys fs.FS) (*Set, error) {
	return LoadFSWithLimits(fsys, DefaultLimits())
}

// LoadFSWithLimits is LoadFS with caller-supplied size limits. The byte limit
// applies to each file separately.
func LoadFSWithLimits(fsys fs.FS, limits Limits) (*Set, error) {
	names, err := policyFileNames(fsys)
	if err != nil {
		return nil, err
	}
	merged := &Set{}
	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}
		set, err := DecodeWithLimits(bytes.NewReader(data), limits)
		if err != nil {
			var diags Diagnostics
			if errors.As(err, &diags) {
				for i := range diags {
					diags[i].Message = name + ": " + diags[i].Message
				}
				return nil, diags
			}
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		merged.Schema.Entities = append(merged.Schema.Entities, set.Schema.Entities...)
		merged.Schema.Actions = append(merged.Schema.Actions, set.Schema.Actions...)
		merged.Schema.Sources = append(merged.Schema.Sources, set.Schema.Sources...)
		merged.Policies = append(merged.Policies, set.Policies...)
	}
	merged.Normalize()
	if diags := ValidateWithLimits(merged, limits); len(diags) > 0 {
		return nil, diags
	}
	return merged, nil
}

func policyFileNames(fsys fs.FS) ([]string, error) {
	var names []string
	err := fs.WalkDir(fsys, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		switch strings.ToLower(path.Ext(name)) {
		case ".yaml", ".yml":
			names = append(names, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func readCapped(r io.Reader, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		return io.ReadAll(r)
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("document exceeds the %d byte limit", maxBytes)
	}
	return data, nil
}

// Encode writes a policy set as a YAML document stream in canonical form: the
// schema document first, then one document per policy ordered by identifier,
// with a fixed key order and every default omitted.
//
// Encoding is a deterministic function of a normalized set, and Decode inverts
// it. That is the whole mechanism behind "export, then apply, and nothing
// changes": the engine's set and the file's set normalize to the same value, so
// the desired-state comparison finds no delta.
func Encode(w io.Writer, s *Set) error {
	normalized := *s
	normalized.Normalize()

	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if !schemaEmpty(&normalized.Schema) {
		if err := enc.Encode(schemaDocumentNode(&normalized.Schema)); err != nil {
			return closeAfter(enc, err)
		}
	}
	for i := range normalized.Policies {
		if err := enc.Encode(policyDocumentNode(&normalized.Policies[i])); err != nil {
			return closeAfter(enc, err)
		}
	}
	return enc.Close()
}

func closeAfter(enc *yaml.Encoder, err error) error {
	_ = enc.Close()
	return err
}

// Marshal renders a policy set as canonical YAML.
func Marshal(s *Set) ([]byte, error) {
	var buf bytes.Buffer
	if err := Encode(&buf, s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func schemaEmpty(s *Schema) bool {
	return len(s.Entities) == 0 && len(s.Actions) == 0 && len(s.Sources) == 0
}

// ---------------------------------------------------------------------------
// encoding
// ---------------------------------------------------------------------------

func scalar(tag, value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
}

func str(value string) *yaml.Node { return scalar("!!str", value) }

type mapBuilder struct {
	node *yaml.Node
}

func newMapping(style yaml.Style) *mapBuilder {
	return &mapBuilder{node: &yaml.Node{Kind: yaml.MappingNode, Style: style}}
}

func (m *mapBuilder) put(key string, value *yaml.Node) *mapBuilder {
	m.node.Content = append(m.node.Content, str(key), value)
	return m
}

func (m *mapBuilder) putString(key, value string) *mapBuilder {
	return m.put(key, str(value))
}

// putStringIf writes the key only when the value differs from the default,
// which is how "omit what the reader can already assume" is implemented.
func (m *mapBuilder) putStringIf(key, value, omitWhen string) {
	if value == omitWhen {
		return
	}
	m.putString(key, value)
}

func sequence(style yaml.Style, items ...*yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.SequenceNode, Style: style, Content: items}
}

func envelope(kind string) *mapBuilder {
	return newMapping(0).putString("apiVersion", APIVersion).putString("kind", kind)
}

func schemaDocumentNode(s *Schema) *yaml.Node {
	m := envelope(KindSchema)
	if len(s.Entities) > 0 {
		items := make([]*yaml.Node, len(s.Entities))
		for i := range s.Entities {
			e := &s.Entities[i]
			em := newMapping(0).putString("name", e.Name)
			if len(e.Attributes) > 0 {
				attrs := newMapping(0)
				for _, a := range e.Attributes {
					attrs.putString(a.Name, string(a.Type))
				}
				em.put("attributes", attrs.node)
			}
			items[i] = em.node
		}
		m.put("entities", sequence(0, items...))
	}
	if len(s.Actions) > 0 {
		items := make([]*yaml.Node, len(s.Actions))
		for i, a := range s.Actions {
			if a.Description == "" {
				items[i] = str(a.Name)
				continue
			}
			items[i] = newMapping(0).putString("name", a.Name).putString("description", a.Description).node
		}
		m.put("actions", sequence(0, items...))
	}
	if len(s.Sources) > 0 {
		items := make([]*yaml.Node, len(s.Sources))
		for i := range s.Sources {
			src := &s.Sources[i]
			sm := newMapping(0).putString("name", src.Name).putString("kind", string(src.Kind))
			if len(src.Params) > 0 {
				params := make([]*yaml.Node, len(src.Params))
				for j, p := range src.Params {
					params[j] = newMapping(yaml.FlowStyle).putString(p.Name, string(p.Type)).node
				}
				sm.put("params", sequence(0, params...))
			}
			sm.putString("returns", string(src.Returns))
			sm.putStringIf("on_error", string(src.OnError), string(DefaultOnError))
			items[i] = sm.node
		}
		m.put("sources", sequence(0, items...))
	}
	return documentOf(m.node)
}

func policyDocumentNode(p *Policy) *yaml.Node {
	m := envelope(KindPolicy).putString("id", p.ID)
	m.putStringIf("description", p.Description, "")
	m.putString("subject", p.Subject)
	m.putString("resource", p.Resource)
	m.putStringIf("context", p.Context, "")
	m.put("actions", stringSequenceNode(p.Actions))
	if p.Condition != nil {
		m.put("condition", conditionNode(p.Condition))
	}
	if len(p.Challenges) > 0 {
		items := make([]*yaml.Node, len(p.Challenges))
		for i, c := range p.Challenges {
			items[i] = challengeNode(c)
		}
		m.put("challenges", sequence(0, items...))
	}
	return documentOf(m.node)
}

func stringSequenceNode(values []string) *yaml.Node {
	items := make([]*yaml.Node, len(values))
	for i, v := range values {
		items[i] = str(v)
	}
	return sequence(yaml.FlowStyle, items...)
}

func challengeNode(c Challenge) *yaml.Node {
	if c == nil {
		return newMapping(0).node
	}
	m := newMapping(0).putString("type", string(c.ChallengeType()))
	switch v := c.(type) {
	case Quorum:
		m.put("threshold", scalar("!!int", strconv.Itoa(v.Threshold)))
		m.put("approvers", approverSetNode(v.Approvers))
	case MFA:
		m.putStringIf("mode", string(v.Mode), string(DefaultMFAMode))
		if len(v.ACRValues) > 0 {
			m.put("acr_values", stringSequenceNode(v.ACRValues))
		}
	case Delay:
		m.putString("duration", v.Duration.String())
		if v.CancellableBy != nil {
			m.put("cancellable_by", approverSetNode(*v.CancellableBy))
		}
	case External:
		m.putString("target", v.Target)
	}
	return m.node
}

// approverSetNode writes the one resolution the set carries. The source form is
// rendered by the operand encoder, so an approver lookup and a condition's fact
// source call are spelled identically.
func approverSetNode(a ApproverSet) *yaml.Node {
	switch {
	case a.Source != nil:
		return operandNode(*a.Source)
	case a.Claim != "":
		return newMapping(yaml.FlowStyle).putString("claim", a.Claim).node
	default:
		return newMapping(yaml.FlowStyle).put("members", stringSequenceNode(a.Members)).node
	}
}

func documentOf(root *yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}
}

func conditionNode(n Node) *yaml.Node {
	switch node := n.(type) {
	case Logic:
		if node.Op == LogicNot {
			if len(node.Operands) != 1 {
				return newMapping(0).put("not", sequence(0)).node
			}
			return newMapping(0).put("not", conditionNode(node.Operands[0])).node
		}
		items := make([]*yaml.Node, len(node.Operands))
		for i, child := range node.Operands {
			items[i] = conditionNode(child)
		}
		return newMapping(0).put(string(node.Op), sequence(0, items...)).node
	case Compare:
		return newMapping(0).
			put("left", operandNode(node.Left)).
			putString("op", string(node.Op)).
			put("right", operandNode(node.Right)).node
	case Member:
		key := "in"
		if node.Negate {
			key = "not_in"
		}
		return newMapping(0).
			put("left", operandNode(node.Left)).
			put(key, operandNode(node.Collection)).node
	default:
		return newMapping(0).node
	}
}

// operandNode renders an operand under one rule: a mapping names something the
// schema declares, and a bare scalar or sequence is a constant.
func operandNode(o Operand) *yaml.Node {
	switch operand := o.(type) {
	case FieldRef:
		return newMapping(yaml.FlowStyle).
			putString("field", string(operand.Role)+"."+operand.Attribute).node
	case SourceRef:
		m := newMapping(yaml.FlowStyle).putString("source", operand.Name)
		if len(operand.Args) > 0 {
			args := make([]*yaml.Node, len(operand.Args))
			for i, arg := range operand.Args {
				args[i] = operandNode(arg)
			}
			m.put("args", sequence(yaml.FlowStyle, args...))
		}
		return m.node
	case Literal:
		return literalNode(operand)
	default:
		return newMapping(yaml.FlowStyle).node
	}
}

// literalNode renders a constant in the shortest form that reads back as the
// same type. Types YAML can resolve on its own are written bare; timestamp,
// duration, and the empty list carry an explicit type because a bare scalar
// would come back as something else.
func literalNode(l Literal) *yaml.Node {
	if l.Type.IsList() {
		items, ok := l.Data.([]any)
		if !ok {
			return newMapping(yaml.FlowStyle).node
		}
		elem := l.Type.Elem()
		nodes := make([]*yaml.Node, len(items))
		for i, item := range items {
			nodes[i] = scalarLiteralNode(elem, item)
		}
		if len(items) > 0 && inferableType(elem) {
			return sequence(yaml.FlowStyle, nodes...)
		}
		return newMapping(yaml.FlowStyle).
			put("value", sequence(yaml.FlowStyle, nodes...)).
			putString("type", string(l.Type)).node
	}
	if inferableType(l.Type) {
		return scalarLiteralNode(l.Type, l.Data)
	}
	return newMapping(yaml.FlowStyle).
		put("value", scalarLiteralNode(l.Type, l.Data)).
		putString("type", string(l.Type)).node
}

// inferableType reports whether a bare YAML scalar of this type reads back as
// the same type without an explicit annotation.
func inferableType(t Type) bool {
	switch t {
	case TypeBool, TypeInt, TypeDouble, TypeString:
		return true
	default:
		return false
	}
}

func scalarLiteralNode(t Type, data any) *yaml.Node {
	switch t {
	case TypeBool:
		v, _ := data.(bool)
		return scalar("!!bool", strconv.FormatBool(v))
	case TypeInt:
		v, _ := data.(int64)
		return scalar("!!int", strconv.FormatInt(v, 10))
	case TypeDouble:
		v, _ := data.(float64)
		return scalar("!!float", formatDouble(v))
	case TypeString:
		v, _ := data.(string)
		return str(v)
	case TypeTimestamp:
		v, _ := data.(time.Time)
		return str(v.UTC().Format(time.RFC3339Nano))
	case TypeDuration:
		v, _ := data.(time.Duration)
		return str(v.String())
	default:
		return str(fmt.Sprint(data))
	}
}

// formatDouble keeps a decimal point on integral values so that YAML resolves
// the scalar back to a float rather than an int. Without it a double literal of
// 10000 would return from a round trip as an int and stop comparing against the
// attribute it was written for.
func formatDouble(v float64) string {
	s := strconv.FormatFloat(v, 'g', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return s
}

// ---------------------------------------------------------------------------
// decoding
// ---------------------------------------------------------------------------

type decoder struct {
	set   Set
	diags Diagnostics
}

func (d *decoder) add(pointer string, code Code, node *yaml.Node, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if node != nil && node.Line > 0 {
		message = fmt.Sprintf("line %d: %s", node.Line, message)
	}
	d.diags = append(d.diags, Diagnostic{Pointer: pointer, Code: code, Message: message})
}

func (d *decoder) stream(data []byte) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			d.add("", CodeInvalidYAML, nil, "%v", err)
			return
		}
		if len(doc.Content) == 0 {
			continue
		}
		d.document(doc.Content[0])
	}
}

func (d *decoder) document(root *yaml.Node) {
	if root.Kind != yaml.MappingNode {
		d.add("", CodeInvalidDocument, root, "a document must be a mapping with apiVersion and kind")
		return
	}
	apiVersion, kind := "", ""
	for i := 0; i+1 < len(root.Content); i += 2 {
		switch root.Content[i].Value {
		case "apiVersion":
			apiVersion = root.Content[i+1].Value
		case "kind":
			kind = root.Content[i+1].Value
		}
	}
	if apiVersion != APIVersion {
		d.add("", CodeUnknownAPIVersion, root, "apiVersion must be %q, got %q", APIVersion, apiVersion)
		return
	}
	switch kind {
	case KindSchema:
		d.schemaDocument(root)
	case KindPolicy:
		d.policyDocument(root)
	default:
		d.add("", CodeUnknownKind, root, "kind must be %q or %q, got %q", KindSchema, KindPolicy, kind)
	}
}

// walk iterates a mapping's entries in document order, dispatching known keys
// and reporting the rest. Reporting unknown keys rather than skipping them is
// what turns a typo in a hand-written file into a pointer a form can highlight.
func (d *decoder) walk(node *yaml.Node, ptr string, handlers map[string]func(*yaml.Node)) {
	if node.Kind != yaml.MappingNode {
		d.add(ptr, CodeInvalidDocument, node, "expected a mapping")
		return
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		handler, ok := handlers[key]
		if !ok {
			d.add(jptr(ptr, key), CodeUnknownKey, node.Content[i], "unknown key %q", key)
			continue
		}
		handler(node.Content[i+1])
	}
}

func (d *decoder) scalarString(node *yaml.Node, ptr string) string {
	if node.Kind != yaml.ScalarNode {
		d.add(ptr, CodeInvalidValue, node, "expected a scalar")
		return ""
	}
	return node.Value
}

func (d *decoder) schemaDocument(root *yaml.Node) {
	d.walk(root, "/schema", map[string]func(*yaml.Node){
		"apiVersion": func(*yaml.Node) {},
		"kind":       func(*yaml.Node) {},
		"entities":   d.entities,
		"actions":    d.actions,
		"sources":    d.sources,
	})
}

func (d *decoder) entities(node *yaml.Node) {
	if node.Kind != yaml.SequenceNode {
		d.add("/schema/entities", CodeInvalidValue, node, "entities must be a sequence")
		return
	}
	for _, item := range node.Content {
		ptr := jptr("schema", "entities", len(d.set.Schema.Entities))
		entity := EntityType{}
		d.walk(item, ptr, map[string]func(*yaml.Node){
			"name": func(n *yaml.Node) { entity.Name = d.scalarString(n, jptr(ptr, "name")) },
			"attributes": func(n *yaml.Node) {
				entity.Attributes = d.attributes(n, jptr(ptr, "attributes"))
			},
		})
		d.set.Schema.Entities = append(d.set.Schema.Entities, entity)
	}
}

func (d *decoder) attributes(node *yaml.Node, ptr string) []Attribute {
	if node.Kind != yaml.MappingNode {
		d.add(ptr, CodeInvalidValue, node, "attributes must be a mapping of name to type")
		return nil
	}
	attrs := make([]Attribute, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		name := node.Content[i].Value
		attrs = append(attrs, Attribute{
			Name: name,
			Type: Type(d.scalarString(node.Content[i+1], jptr(ptr, name))),
		})
	}
	return attrs
}

func (d *decoder) actions(node *yaml.Node) {
	if node.Kind != yaml.SequenceNode {
		d.add("/schema/actions", CodeInvalidValue, node, "actions must be a sequence")
		return
	}
	for _, item := range node.Content {
		ptr := jptr("schema", "actions", len(d.set.Schema.Actions))
		action := Action{}
		switch item.Kind {
		case yaml.ScalarNode:
			action.Name = item.Value
		default:
			d.walk(item, ptr, map[string]func(*yaml.Node){
				"name":        func(n *yaml.Node) { action.Name = d.scalarString(n, jptr(ptr, "name")) },
				"description": func(n *yaml.Node) { action.Description = d.scalarString(n, jptr(ptr, "description")) },
			})
		}
		d.set.Schema.Actions = append(d.set.Schema.Actions, action)
	}
}

func (d *decoder) sources(node *yaml.Node) {
	if node.Kind != yaml.SequenceNode {
		d.add("/schema/sources", CodeInvalidValue, node, "sources must be a sequence")
		return
	}
	for _, item := range node.Content {
		ptr := jptr("schema", "sources", len(d.set.Schema.Sources))
		src := SourceDecl{OnError: DefaultOnError}
		d.walk(item, ptr, map[string]func(*yaml.Node){
			"name":    func(n *yaml.Node) { src.Name = d.scalarString(n, jptr(ptr, "name")) },
			"kind":    func(n *yaml.Node) { src.Kind = SourceKind(d.scalarString(n, jptr(ptr, "kind"))) },
			"returns": func(n *yaml.Node) { src.Returns = Type(d.scalarString(n, jptr(ptr, "returns"))) },
			"on_error": func(n *yaml.Node) {
				src.OnError = OnError(d.scalarString(n, jptr(ptr, "on_error")))
			},
			"params": func(n *yaml.Node) { src.Params = d.params(n, jptr(ptr, "params")) },
		})
		d.set.Schema.Sources = append(d.set.Schema.Sources, src)
	}
}

func (d *decoder) params(node *yaml.Node, ptr string) []Param {
	if node.Kind != yaml.SequenceNode {
		d.add(ptr, CodeInvalidValue, node, "params must be a sequence of single-key mappings")
		return nil
	}
	params := make([]Param, 0, len(node.Content))
	for i, item := range node.Content {
		if item.Kind != yaml.MappingNode || len(item.Content) != 2 {
			d.add(jptr(ptr, i), CodeInvalidValue, item, "each parameter is one mapping of name to type")
			continue
		}
		params = append(params, Param{
			Name: item.Content[0].Value,
			Type: Type(d.scalarString(item.Content[1], jptr(ptr, i))),
		})
	}
	return params
}

func (d *decoder) policyDocument(root *yaml.Node) {
	ptr := jptr("policies", len(d.set.Policies))
	p := Policy{}
	d.walk(root, ptr, map[string]func(*yaml.Node){
		"apiVersion":  func(*yaml.Node) {},
		"kind":        func(*yaml.Node) {},
		"id":          func(n *yaml.Node) { p.ID = d.scalarString(n, jptr(ptr, "id")) },
		"description": func(n *yaml.Node) { p.Description = d.scalarString(n, jptr(ptr, "description")) },
		"subject":     func(n *yaml.Node) { p.Subject = d.scalarString(n, jptr(ptr, "subject")) },
		"resource":    func(n *yaml.Node) { p.Resource = d.scalarString(n, jptr(ptr, "resource")) },
		"context":     func(n *yaml.Node) { p.Context = d.scalarString(n, jptr(ptr, "context")) },
		"actions":     func(n *yaml.Node) { p.Actions = d.stringSequence(n, jptr(ptr, "actions")) },
		"condition":   func(n *yaml.Node) { p.Condition = d.condition(n, jptr(ptr, "condition")) },
		"challenges":  func(n *yaml.Node) { p.Challenges = d.challenges(n, jptr(ptr, "challenges")) },
	})
	d.set.Policies = append(d.set.Policies, p)
}

func (d *decoder) challenges(node *yaml.Node, ptr string) []Challenge {
	if node.Kind != yaml.SequenceNode {
		d.add(ptr, CodeInvalidValue, node, "challenges must be a sequence")
		return nil
	}
	out := make([]Challenge, 0, len(node.Content))
	for i, item := range node.Content {
		if c := d.challenge(item, jptr(ptr, i)); c != nil {
			out = append(out, c)
		}
	}
	return out
}

// challenge decodes one challenge declaration. The type key selects which other
// keys are allowed, so a threshold on a delay is reported as an unknown key
// rather than quietly ignored.
func (d *decoder) challenge(node *yaml.Node, ptr string) Challenge {
	if node.Kind != yaml.MappingNode {
		d.add(ptr, CodeInvalidValue, node, "a challenge is a mapping with a type")
		return nil
	}
	kind := ChallengeType("")
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == "type" {
			kind = ChallengeType(node.Content[i+1].Value)
		}
	}
	skip := func(*yaml.Node) {}
	switch kind {
	case ChallengeQuorum:
		c := Quorum{}
		d.walk(node, ptr, map[string]func(*yaml.Node){
			"type":      skip,
			"threshold": func(n *yaml.Node) { c.Threshold = d.scalarInt(n, jptr(ptr, "threshold")) },
			"approvers": func(n *yaml.Node) {
				if set := d.approverSet(n, jptr(ptr, "approvers")); set != nil {
					c.Approvers = *set
				}
			},
		})
		return c
	case ChallengeMFA:
		c := MFA{Mode: DefaultMFAMode}
		d.walk(node, ptr, map[string]func(*yaml.Node){
			"type": skip,
			"mode": func(n *yaml.Node) { c.Mode = MFAMode(d.scalarString(n, jptr(ptr, "mode"))) },
			"acr_values": func(n *yaml.Node) {
				c.ACRValues = d.stringSequence(n, jptr(ptr, "acr_values"))
			},
		})
		return c
	case ChallengeDelay:
		c := Delay{}
		d.walk(node, ptr, map[string]func(*yaml.Node){
			"type":     skip,
			"duration": func(n *yaml.Node) { c.Duration = d.scalarDuration(n, jptr(ptr, "duration")) },
			"cancellable_by": func(n *yaml.Node) {
				c.CancellableBy = d.approverSet(n, jptr(ptr, "cancellable_by"))
			},
		})
		return c
	case ChallengeExternal:
		c := External{}
		d.walk(node, ptr, map[string]func(*yaml.Node){
			"type":   skip,
			"target": func(n *yaml.Node) { c.Target = d.scalarString(n, jptr(ptr, "target")) },
		})
		return c
	default:
		names := make([]string, 0, len(ChallengeTypes()))
		for _, k := range ChallengeTypes() {
			names = append(names, string(k))
		}
		d.add(jptr(ptr, "type"), CodeUnknownChallenge, node,
			"challenge type must be one of %s, got %q", strings.Join(names, ", "), kind)
		return nil
	}
}

func (d *decoder) approverSet(node *yaml.Node, ptr string) *ApproverSet {
	if node.Kind != yaml.MappingNode {
		d.add(ptr, CodeInvalidValue, node,
			"an approver set is a mapping with members, claim, or source")
		return nil
	}
	set := &ApproverSet{}
	var source *SourceRef
	ok := true
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i].Value, node.Content[i+1]
		switch key {
		case "members":
			set.Members = d.stringSequence(value, jptr(ptr, "members"))
		case "claim":
			set.Claim = d.scalarString(value, jptr(ptr, "claim"))
		case "source":
			if source == nil {
				source = &SourceRef{}
			}
			source.Name = d.scalarString(value, jptr(ptr, "source"))
		case "args":
			if source == nil {
				source = &SourceRef{}
			}
			if value.Kind != yaml.SequenceNode {
				d.add(jptr(ptr, "args"), CodeInvalidValue, value, "args must be a sequence")
				ok = false
				continue
			}
			for j, item := range value.Content {
				arg := d.operand(item, jptr(ptr, "args", j))
				if arg == nil {
					ok = false
					continue
				}
				source.Args = append(source.Args, arg)
			}
		default:
			d.add(jptr(ptr, key), CodeUnknownKey, node.Content[i],
				"unknown key %q in an approver set", key)
			ok = false
		}
	}
	set.Source = source
	if !ok {
		return nil
	}
	return set
}

func (d *decoder) scalarInt(node *yaml.Node, ptr string) int {
	raw := d.scalarString(node, ptr)
	value, err := strconv.Atoi(raw)
	if err != nil {
		d.add(ptr, CodeInvalidValue, node, "%q is not a whole number", raw)
		return 0
	}
	return value
}

func (d *decoder) scalarDuration(node *yaml.Node, ptr string) time.Duration {
	raw := d.scalarString(node, ptr)
	value, err := time.ParseDuration(raw)
	if err != nil {
		d.add(ptr, CodeInvalidValue, node, "%q is not a duration such as 1h30m", raw)
		return 0
	}
	return value
}

func (d *decoder) stringSequence(node *yaml.Node, ptr string) []string {
	if node.Kind != yaml.SequenceNode {
		d.add(ptr, CodeInvalidValue, node, "expected a sequence")
		return nil
	}
	out := make([]string, 0, len(node.Content))
	for i, item := range node.Content {
		out = append(out, d.scalarString(item, jptr(ptr, i)))
	}
	return out
}

// conditionKeys are the mapping keys that discriminate one condition node shape
// from another.
var conditionKeys = []string{"all", "any", "not", "left"}

func (d *decoder) condition(node *yaml.Node, ptr string) Node {
	if node.Kind != yaml.MappingNode {
		d.add(ptr, CodeInvalidDocument, node, "a condition is a mapping keyed by one of %s",
			strings.Join(conditionKeys, ", "))
		return nil
	}
	present := map[string]*yaml.Node{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		present[node.Content[i].Value] = node.Content[i+1]
	}
	switch {
	case present["all"] != nil:
		return d.logic(LogicAll, present["all"], node, ptr)
	case present["any"] != nil:
		return d.logic(LogicAny, present["any"], node, ptr)
	case present["not"] != nil:
		inner := d.condition(present["not"], jptr(ptr, "not"))
		if inner == nil {
			return nil
		}
		return Not(inner)
	case present["left"] != nil:
		return d.leaf(present, node, ptr)
	default:
		d.add(ptr, CodeInvalidDocument, node, "a condition needs one of %s",
			strings.Join(conditionKeys, ", "))
		return nil
	}
}

func (d *decoder) logic(op LogicOp, seq, node *yaml.Node, ptr string) Node {
	if seq.Kind != yaml.SequenceNode {
		d.add(jptr(ptr, string(op)), CodeInvalidValue, node, "%q takes a sequence of conditions", op)
		return nil
	}
	operands := make([]Node, 0, len(seq.Content))
	for i, item := range seq.Content {
		child := d.condition(item, jptr(ptr, string(op), i))
		if child == nil {
			return nil
		}
		operands = append(operands, child)
	}
	return Logic{Op: op, Operands: operands}
}

func (d *decoder) leaf(present map[string]*yaml.Node, node *yaml.Node, ptr string) Node {
	left := d.operand(present["left"], jptr(ptr, "left"))
	reference, isReference := left.(Reference)
	if left != nil && !isReference {
		d.add(jptr(ptr, "left"), CodeInvalidOperand, node,
			"the left side of a rule reads a declared field or fact source; write a constant on the right")
		return nil
	}
	for _, key := range []string{"in", "not_in"} {
		if collection := present[key]; collection != nil {
			operand := d.operand(collection, jptr(ptr, key))
			if reference == nil || operand == nil {
				return nil
			}
			return Member{Left: reference, Collection: operand, Negate: key == "not_in"}
		}
	}
	if present["op"] == nil || present["right"] == nil {
		d.add(ptr, CodeMissingField, node,
			"a rule needs either op and right, or in, or not_in")
		return nil
	}
	right := d.operand(present["right"], jptr(ptr, "right"))
	if reference == nil || right == nil {
		return nil
	}
	return Compare{
		Left:  reference,
		Op:    CompareOp(d.scalarString(present["op"], jptr(ptr, "op"))),
		Right: right,
	}
}

// operand decodes one operand. A mapping names a declared field, a declared
// fact source, or an explicitly typed constant; a bare scalar or sequence is a
// constant whose type YAML resolves.
func (d *decoder) operand(node *yaml.Node, ptr string) Operand {
	switch node.Kind {
	case yaml.ScalarNode:
		return d.inferredScalar(node, ptr)
	case yaml.SequenceNode:
		return d.inferredList(node, ptr)
	case yaml.MappingNode:
		return d.operandMapping(node, ptr)
	default:
		d.add(ptr, CodeInvalidOperand, node, "unsupported operand")
		return nil
	}
}

func (d *decoder) operandMapping(node *yaml.Node, ptr string) Operand {
	present := map[string]*yaml.Node{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		switch key {
		case "field", "source", "args", "value", "type":
			present[key] = node.Content[i+1]
		default:
			d.add(jptr(ptr, key), CodeUnknownKey, node.Content[i], "unknown key %q in an operand", key)
			return nil
		}
	}
	switch {
	case present["field"] != nil:
		return d.fieldRef(present["field"], ptr)
	case present["source"] != nil:
		name := d.scalarString(present["source"], jptr(ptr, "source"))
		ref := SourceRef{Name: name}
		if args := present["args"]; args != nil {
			if args.Kind != yaml.SequenceNode {
				d.add(jptr(ptr, "args"), CodeInvalidValue, args, "args must be a sequence")
				return nil
			}
			for i, item := range args.Content {
				arg := d.operand(item, jptr(ptr, "args", i))
				if arg == nil {
					return nil
				}
				ref.Args = append(ref.Args, arg)
			}
		}
		return ref
	case present["value"] != nil:
		return d.typedValue(present["value"], present["type"], ptr)
	default:
		d.add(ptr, CodeInvalidOperand, node,
			"an operand mapping needs one of field, source, or value")
		return nil
	}
}

func (d *decoder) fieldRef(node *yaml.Node, ptr string) Operand {
	raw := d.scalarString(node, jptr(ptr, "field"))
	role, attribute, found := strings.Cut(raw, ".")
	if !found {
		d.add(jptr(ptr, "field"), CodeInvalidValue, node,
			"a field reference is written role.attribute, for example subject.department")
		return nil
	}
	return FieldRef{Role: Role(role), Attribute: attribute}
}

func (d *decoder) typedValue(value, typeNode *yaml.Node, ptr string) Operand {
	if typeNode == nil {
		switch value.Kind {
		case yaml.ScalarNode:
			return d.inferredScalar(value, jptr(ptr, "value"))
		case yaml.SequenceNode:
			return d.inferredList(value, jptr(ptr, "value"))
		default:
			d.add(jptr(ptr, "value"), CodeInvalidValue, value, "expected a scalar or a sequence")
			return nil
		}
	}
	declared := Type(d.scalarString(typeNode, jptr(ptr, "type")))
	if !declared.Valid() {
		d.add(jptr(ptr, "type"), CodeUnknownType, typeNode, "unknown type %q", declared)
		return nil
	}
	if declared.IsList() {
		if value.Kind != yaml.SequenceNode {
			d.add(jptr(ptr, "value"), CodeInvalidValue, value, "type %s needs a sequence", declared)
			return nil
		}
		items := make([]any, 0, len(value.Content))
		for i, item := range value.Content {
			data, ok := d.scalarData(declared.Elem(), item, jptr(ptr, "value", i))
			if !ok {
				return nil
			}
			items = append(items, data)
		}
		return Literal{Type: declared, Data: items}
	}
	data, ok := d.scalarData(declared, value, jptr(ptr, "value"))
	if !ok {
		return nil
	}
	return Literal{Type: declared, Data: data}
}

// scalarData converts a YAML scalar to the Go value a declared type calls for.
func (d *decoder) scalarData(t Type, node *yaml.Node, ptr string) (any, bool) {
	if node.Kind != yaml.ScalarNode {
		d.add(ptr, CodeInvalidValue, node, "expected a scalar of type %s", t)
		return nil, false
	}
	raw := node.Value
	switch t {
	case TypeBool:
		v, err := strconv.ParseBool(raw)
		if err != nil {
			d.add(ptr, CodeInvalidValue, node, "%q is not a bool", raw)
			return nil, false
		}
		return v, true
	case TypeInt:
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			d.add(ptr, CodeInvalidValue, node, "%q is not an int", raw)
			return nil, false
		}
		return v, true
	case TypeDouble:
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			d.add(ptr, CodeInvalidValue, node, "%q is not a finite double", raw)
			return nil, false
		}
		return v, true
	case TypeString:
		return raw, true
	case TypeTimestamp:
		v, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			d.add(ptr, CodeInvalidValue, node, "%q is not an RFC 3339 timestamp", raw)
			return nil, false
		}
		return v.UTC(), true
	case TypeDuration:
		v, err := time.ParseDuration(raw)
		if err != nil {
			d.add(ptr, CodeInvalidValue, node, "%q is not a duration such as 1h30m", raw)
			return nil, false
		}
		return v, true
	default:
		d.add(ptr, CodeUnknownType, node, "unknown type %q", t)
		return nil, false
	}
}

// inferredScalar reads a bare scalar as a constant, taking the type from the
// tag YAML resolved. Duration has no YAML spelling of its own, so a duration
// constant always uses the explicit {value, type} form.
func (d *decoder) inferredScalar(node *yaml.Node, ptr string) Operand {
	t, ok := typeForTag(node.Tag)
	if !ok {
		d.add(ptr, CodeInvalidValue, node,
			"cannot tell the type of %q; write it as {value: %s, type: <type>}", node.Value, node.Value)
		return nil
	}
	data, ok := d.scalarData(t, node, ptr)
	if !ok {
		return nil
	}
	return Literal{Type: t, Data: data}
}

func (d *decoder) inferredList(node *yaml.Node, ptr string) Operand {
	if len(node.Content) == 0 {
		d.add(ptr, CodeInvalidValue, node,
			"an empty list has no element type; write it as {value: [], type: list<string>}")
		return nil
	}
	elem, ok := typeForTag(node.Content[0].Tag)
	if !ok {
		d.add(jptr(ptr, 0), CodeInvalidValue, node.Content[0],
			"cannot tell the element type of this list; use the explicit {value, type} form")
		return nil
	}
	items := make([]any, 0, len(node.Content))
	for i, item := range node.Content {
		itemType, ok := typeForTag(item.Tag)
		if !ok || itemType != elem {
			d.add(jptr(ptr, i), CodeTypeMismatch, item,
				"list elements must all be %s", elem)
			return nil
		}
		data, ok := d.scalarData(elem, item, jptr(ptr, i))
		if !ok {
			return nil
		}
		items = append(items, data)
	}
	return Literal{Type: ListOf(elem), Data: items}
}

func typeForTag(tag string) (Type, bool) {
	switch tag {
	case "!!bool":
		return TypeBool, true
	case "!!int":
		return TypeInt, true
	case "!!float":
		return TypeDouble, true
	case "!!str":
		return TypeString, true
	case "!!timestamp":
		return TypeTimestamp, true
	default:
		return "", false
	}
}
