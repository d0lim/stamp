package revision

// apply.go is the file authoring path: a directory of documents is the desired
// state, and applying it is one revision proposal against the state in force.
//
// Four things about it are the point rather than the plumbing.
//
// **The directory is the unit, and the file is not.** A policy's identity is
// the `id` inside its document, so moving a policy between files, renaming a
// file or splitting one file into ten changes nothing the comparison can see.
// That is why a rename is a rename here and not a delete plus a create.
//
// **The comparison is scoped to file-authored policies (R45, D23).** A
// console-authored policy missing from the directory is not a deletion. Without
// the scoping the default configuration does not work at all: the next CI apply
// computes every console-authored policy as a deletion and proposes wiping them
// on every merge.
//
// **There is no partial apply.** Static validation runs over the whole set and
// one failure means no proposal at all. The code path for "apply the four that
// validated" does not exist, because a policy set is a set — the four that
// validated may be four halves of pairs.
//
// **Order at the door is payload limits, then the gate, then the parser.** A
// caller holding a pending revision from the other path is turned away before
// anything is parsed, and an oversized payload before that. Both refusals are
// cheap by construction rather than by luck.
//
// What this file does *not* do is decide anything. The delta it computes goes
// to the same governance pipeline a form edit goes to (D22) — the weakening
// classifier, the approval requirement, the binding hash and the revaluation
// hook are all owned by the governance path and none of them is reimplemented
// here.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// Errors the file authoring path returns as sentinels.
var (
	// ErrPayloadTooLarge reports an apply payload over a declared limit. It is
	// returned before the payload is parsed.
	ErrPayloadTooLarge = errors.New("revision: the apply payload exceeds a declared limit")

	// ErrInvalidPayload reports a payload that could not be read as a policy
	// set, or one that is structurally not something this path may apply.
	ErrInvalidPayload = errors.New("revision: the apply payload is not a valid policy set")

	// ErrOriginConflict reports a document that would change a policy the other
	// authoring path owns. R54 gives origin exactly one way to move — an
	// explicit handover declaration — so this is not something an apply may do
	// by writing the identifier.
	ErrOriginConflict = errors.New("revision: this document would change a policy the console path owns")
)

// The adoption declaration.
const (
	// AdoptionKind is the document kind that hands a policy over to the file
	// path (R54).
	//
	// It is a document in the directory rather than a flag on the command,
	// because the requirement is that the *file* declares the handover: a flag
	// would make the transfer a property of one invocation nobody can read
	// afterwards, while a document is in the diff and in the review.
	AdoptionKind = "Adoption"
)

// PayloadLimits bound an apply payload (R45).
//
// The document count and the per-document size are checked before anything is
// parsed, which is what makes them a defence rather than a diagnostic. The
// structural limits cannot be — a condition's node count is not knowable
// without reading the condition — so they are enforced by the validator, over
// a payload already bounded in bytes.
type PayloadLimits struct {
	// MaxDocuments bounds how many documents one payload carries. A payload
	// entry may itself be a YAML stream of several policies; MaxPolicies is
	// what bounds that, at validation.
	MaxDocuments int
	// MaxDocumentBytes bounds each document.
	MaxDocumentBytes int
	// MaxTotalBytes bounds the payload as a whole, so that a legal document
	// count times a legal document size is not itself the attack.
	MaxTotalBytes int
	// MaxPolicies bounds the policy set the payload decodes to.
	MaxPolicies int
	// MaxConditionNodes and MaxConditionDepth bound one condition.
	MaxConditionNodes int
	MaxConditionDepth int
}

// DefaultPayloadLimits is what an installation gets when it configures none.
func DefaultPayloadLimits() PayloadLimits {
	base := policy.DefaultLimits()
	return PayloadLimits{
		MaxDocuments:      1000,
		MaxDocumentBytes:  base.MaxDocumentBytes,
		MaxTotalBytes:     32 << 20,
		MaxPolicies:       base.MaxPolicies,
		MaxConditionNodes: base.MaxConditionNodes,
		MaxConditionDepth: base.MaxConditionDepth,
	}
}

func (l PayloadLimits) orDefault() PayloadLimits {
	d := DefaultPayloadLimits()
	if l.MaxDocuments <= 0 {
		l.MaxDocuments = d.MaxDocuments
	}
	if l.MaxDocumentBytes <= 0 {
		l.MaxDocumentBytes = d.MaxDocumentBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = d.MaxTotalBytes
	}
	if l.MaxPolicies <= 0 {
		l.MaxPolicies = d.MaxPolicies
	}
	if l.MaxConditionNodes <= 0 {
		l.MaxConditionNodes = d.MaxConditionNodes
	}
	if l.MaxConditionDepth <= 0 {
		l.MaxConditionDepth = d.MaxConditionDepth
	}
	return l
}

// policyLimits renders the structural half for the validator.
func (l PayloadLimits) policyLimits() policy.Limits {
	return policy.Limits{
		MaxDocumentBytes:  l.MaxTotalBytes,
		MaxPolicies:       l.MaxPolicies,
		MaxConditionNodes: l.MaxConditionNodes,
		MaxConditionDepth: l.MaxConditionDepth,
	}
}

// Document is one file of an apply payload.
type Document struct {
	// Name is where it came from, for error messages only. Nothing about the
	// name reaches the policy set: identity is the `id` inside the document.
	Name string `json:"name"`
	// Content is the document's bytes, exactly as written.
	Content []byte `json:"content"`
}

// Payload is a directory as it arrived.
type Payload struct {
	Documents []Document `json:"documents"`
}

// ReadDir reads a directory into a payload.
//
// It takes every .yaml and .yml file, at any depth, sorted by path so that two
// runs over one directory produce the same payload. Layout is a repository's
// business: the set is the same however the documents are distributed.
func ReadDir(dir string) (Payload, error) {
	var out Payload
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isPolicyFile(d.Name()) {
			return nil
		}
		content, rerr := os.ReadFile(path) //nolint:gosec // the caller named the directory
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			rel = path
		}
		out.Documents = append(out.Documents, Document{Name: filepath.ToSlash(rel), Content: content})
		return nil
	})
	if err != nil {
		return Payload{}, fmt.Errorf("revision: read the policy directory %q: %w", dir, err)
	}
	sort.Slice(out.Documents, func(i, j int) bool { return out.Documents[i].Name < out.Documents[j].Name })
	return out, nil
}

func isPolicyFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}

// Check enforces the limits that can be enforced without parsing (R45).
func (p Payload) Check(limits PayloadLimits) error {
	limits = limits.orDefault()
	if len(p.Documents) == 0 {
		// An empty payload is a legitimate desired state — every file-authored
		// policy deleted — so it is not an error. It is checked here only so
		// that "no documents" is a decision this function has made rather than
		// one the loop below fell through.
		return nil
	}
	if len(p.Documents) > limits.MaxDocuments {
		return fmt.Errorf("%w: the payload carries %d documents and the limit is %d",
			ErrPayloadTooLarge, len(p.Documents), limits.MaxDocuments)
	}
	total := 0
	for _, doc := range p.Documents {
		if len(doc.Content) > limits.MaxDocumentBytes {
			return fmt.Errorf("%w: document %q is %d bytes and the limit is %d",
				ErrPayloadTooLarge, doc.Name, len(doc.Content), limits.MaxDocumentBytes)
		}
		total += len(doc.Content)
	}
	if total > limits.MaxTotalBytes {
		return fmt.Errorf("%w: the payload is %d bytes and the limit is %d",
			ErrPayloadTooLarge, total, limits.MaxTotalBytes)
	}
	return nil
}

// parsed is what a payload decodes to: the desired policy set and the handovers
// the directory declared.
type parsed struct {
	set   *policy.Set
	adopt []string
}

// parse splits the adoption declarations out of the payload and loads the rest
// as one policy set.
//
// Loading is all or nothing (R45). policy.Load runs every static check and
// finishes by compiling each condition, so a payload that gets past here is one
// the engine can hold; a single failure returns diagnostics for the whole set
// and no delta is computed at all.
func (p Payload) parse(limits PayloadLimits) (parsed, error) {
	var (
		stream bytes.Buffer
		adopt  []string
	)
	for _, doc := range p.Documents {
		kinds, err := documentKinds(doc)
		if err != nil {
			return parsed{}, err
		}
		if !slices.Contains(kinds, AdoptionKind) {
			appendDocument(&stream, doc.Content)
			continue
		}
		if len(kinds) != adoptionCount(kinds) {
			// Mixing the two in one file would make the handover declaration
			// depend on document order inside a file, which is the one thing
			// about a file this path is supposed to be indifferent to.
			return parsed{}, fmt.Errorf(
				"%w: %q mixes an %s declaration with policy documents; keep the declaration in its own file",
				ErrInvalidPayload, doc.Name, AdoptionKind)
		}
		ids, err := decodeAdoption(doc)
		if err != nil {
			return parsed{}, err
		}
		adopt = append(adopt, ids...)
	}

	set, err := policy.LoadWithLimits(bytes.NewReader(stream.Bytes()), limits.policyLimits())
	if err != nil {
		return parsed{}, fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}
	sort.Strings(adopt)
	return parsed{set: set, adopt: adopt}, nil
}

// appendDocument joins a document onto a stream, inserting the separator each
// document was written without.
func appendDocument(b *bytes.Buffer, doc []byte) {
	if b.Len() > 0 {
		if !bytes.HasSuffix(b.Bytes(), []byte("\n")) {
			b.WriteString("\n")
		}
		b.WriteString("---\n")
	}
	b.Write(doc)
}

// documentKinds reports the `kind` of every document in one payload entry. It
// is a shallow read: the full parse belongs to the policy package, and this is
// only deciding which parser a document goes to.
func documentKinds(doc Document) ([]string, error) {
	dec := yaml.NewDecoder(bytes.NewReader(doc.Content))
	var kinds []string
	for {
		var probe struct {
			Kind string `yaml:"kind"`
		}
		err := dec.Decode(&probe)
		if errors.Is(err, io.EOF) {
			return kinds, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s is not readable YAML: %w", ErrInvalidPayload, doc.Name, err)
		}
		kinds = append(kinds, probe.Kind)
	}
}

// Adoption is the handover declaration a directory carries (R54).
type Adoption struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind"       json:"kind"`
	Policies   []string `yaml:"policies"   json:"policies"`
}

func decodeAdoption(doc Document) ([]string, error) {
	dec := yaml.NewDecoder(bytes.NewReader(doc.Content))
	var out []string
	for {
		var declaration Adoption
		err := dec.Decode(&declaration)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s is not a readable %s declaration: %w",
				ErrInvalidPayload, doc.Name, AdoptionKind, err)
		}
		if declaration.APIVersion != policy.APIVersion {
			return nil, fmt.Errorf("%w: %s declares apiVersion %q, want %q",
				ErrInvalidPayload, doc.Name, declaration.APIVersion, policy.APIVersion)
		}
		if len(declaration.Policies) == 0 {
			return nil, fmt.Errorf("%w: %s adopts nothing", ErrInvalidPayload, doc.Name)
		}
		out = append(out, declaration.Policies...)
	}
}

// ---------------------------------------------------------------------------
// the comparison
// ---------------------------------------------------------------------------

// CurrentPolicy is one effective policy together with the path that owns it.
type CurrentPolicy struct {
	Policy *policy.Policy
	Origin store.Origin
}

// CurrentState is the effective policy set an apply is compared against.
type CurrentState struct {
	Schema   policy.Schema
	Policies []CurrentPolicy
}

// PlanApply computes the delta a desired state implies (R45, R54).
//
// It is a pure function of the two states and the handover declarations, so the
// rules that make the default configuration work — the file-origin scoping, the
// conflict, the handover — are testable without a database and are stated in
// one place rather than spread through the write path.
func PlanApply(current CurrentState, desired *policy.Set, adopt []string) (Delta, error) {
	if desired == nil {
		desired = &policy.Set{Schema: current.Schema}
	}
	owner := make(map[string]CurrentPolicy, len(current.Policies))
	for _, held := range current.Policies {
		if held.Policy == nil {
			continue
		}
		owner[held.Policy.ID] = held
	}
	adopting := make(map[string]bool, len(adopt))
	for _, id := range adopt {
		adopting[id] = true
	}

	schemaBefore := current.Schema
	schemaAfter := desired.Schema
	delta := Delta{SchemaBefore: &schemaBefore, SchemaAfter: &schemaAfter}

	seen := make(map[string]bool, len(desired.Policies))
	for i := range desired.Policies {
		p := &desired.Policies[i]
		if IsReserved(p.ID) {
			// The rule that governs revisions is not a policy a revision may
			// author. It is written against its own schema and its quorum is
			// the thing standing between this payload and the policy set.
			return Delta{}, fmt.Errorf("%w: %q is reserved and cannot be authored from a file",
				ErrInvalidPayload, p.ID)
		}
		seen[p.ID] = true
		held, exists := owner[p.ID]
		switch {
		case !exists:
			delta.Changes = append(delta.Changes, Change{Kind: ChangeAdd, PolicyID: p.ID, After: p})
		case held.Origin == store.OriginFile:
			if !samePolicy(held.Policy, p) {
				delta.Changes = append(delta.Changes,
					Change{Kind: ChangeModify, PolicyID: p.ID, Before: held.Policy, After: p})
			}
		case adopting[p.ID]:
			delta.Changes = append(delta.Changes, Change{
				Kind:       ChangeTakeOwnership,
				PolicyID:   p.ID,
				Before:     held.Policy,
				After:      p,
				FromOrigin: held.Origin,
				ToOrigin:   store.OriginFile,
			})
		case samePolicy(held.Policy, p):
			// The document says exactly what the console-authored policy
			// already says, so there is nothing to conflict over and nothing to
			// change. This is what makes export → apply a no-op on a deployment
			// that has only ever authored in the console (R48): the export
			// carries the whole effective set, and re-applying it must not
			// propose taking ownership of it.
		default:
			return Delta{}, fmt.Errorf(
				"%w: %q is owned by the %q path; declare the handover in an %s document to move it",
				ErrOriginConflict, p.ID, held.Origin, AdoptionKind)
		}
	}

	for id := range adopting {
		if !seen[id] {
			return Delta{}, fmt.Errorf("%w: the %s declaration names %q, which the directory does not carry",
				ErrInvalidPayload, AdoptionKind, id)
		}
		if held, exists := owner[id]; !exists || held.Origin == store.OriginFile {
			return Delta{}, fmt.Errorf("%w: the %s declaration names %q, which the file path already owns",
				ErrInvalidPayload, AdoptionKind, id)
		}
	}

	// Only file-authored policies are deleted for being absent. This is the
	// whole of D23 in the write direction: a console-authored policy missing
	// from a directory the console never writes to means nothing at all.
	deleted := make([]string, 0, len(owner))
	for id, held := range owner {
		if held.Origin == store.OriginFile && !seen[id] {
			deleted = append(deleted, id)
		}
	}
	sort.Strings(deleted)
	for _, id := range deleted {
		held := owner[id]
		delta.Changes = append(delta.Changes, Change{Kind: ChangeDelete, PolicyID: id, Before: held.Policy})
	}

	sort.SliceStable(delta.Changes, func(i, j int) bool {
		return delta.Changes[i].PolicyID < delta.Changes[j].PolicyID
	})
	return delta, nil
}

// ---------------------------------------------------------------------------
// the apply
// ---------------------------------------------------------------------------

// FileApplyRequest is one declarative apply.
type FileApplyRequest struct {
	// Proposer is the authenticated author. A workload credential never
	// authors policy, so a CI applies as a person's token or not at all.
	Proposer *identity.Subject
	// Payload is the directory.
	Payload Payload
	// Mode is how open decisions are treated. The empty mode is revaluation.
	Mode decision.ApplicationMode
	// BootstrapToken authorizes an apply before the lock, and is ignored after
	// it.
	BootstrapToken string
}

// FileApplyResult is what one apply produced.
type FileApplyResult struct {
	// NoChange reports a directory that already describes the state in force.
	// No proposal is created for it: a revision nobody has to approve is not a
	// revision, and a CI applying on every merge would otherwise fill the
	// approval inbox with empty diffs.
	NoChange bool `json:"no_change"`
	// Proposal is the revision this apply opened, and is the zero value when
	// NoChange is set.
	Proposal Proposal `json:"proposal,omitzero"`
	// Adopted names the policies this apply took over from the console path.
	Adopted []string `json:"adopted,omitempty"`
}

// ApplyFiles turns a directory into one revision proposal (R45, R46).
//
// It returns as soon as the proposal exists. Governance is asynchronous — the
// quorum may be minutes or a day away — so there is no synchronous "applied"
// for this to return, and pretending otherwise is what R46 forbids. The caller
// that wants to wait polls the revision.
func (s *Service) ApplyFiles(ctx context.Context, req FileApplyRequest) (FileApplyResult, error) {
	if req.Proposer == nil || req.Proposer.Kind != identity.SubjectUser {
		return FileApplyResult{}, decision.ErrUnauthenticated
	}
	if err := s.checkAuthoring(store.OriginFile); err != nil {
		return FileApplyResult{}, err
	}
	// The order is the requirement's: limits, then the gate, then the parser.
	if err := req.Payload.Check(s.limits); err != nil {
		return FileApplyResult{}, err
	}
	if err := s.gate(ctx, store.OriginFile); err != nil {
		return FileApplyResult{}, err
	}

	desired, err := req.Payload.parse(s.limits)
	if err != nil {
		return FileApplyResult{}, err
	}
	current, err := s.currentState(ctx)
	if err != nil {
		return FileApplyResult{}, err
	}
	delta, err := PlanApply(current, desired.set, desired.adopt)
	if err != nil {
		return FileApplyResult{}, err
	}
	if len(delta.Changes) == 0 && !delta.SchemaChanged() {
		return FileApplyResult{NoChange: true}, nil
	}

	proposal, err := s.Propose(ctx, ProposeRequest{
		Proposer:       req.Proposer,
		Delta:          delta,
		Origin:         store.OriginFile,
		Mode:           req.Mode,
		BootstrapToken: req.BootstrapToken,
	})
	if err != nil {
		return FileApplyResult{}, err
	}
	return FileApplyResult{Proposal: proposal, Adopted: desired.adopt}, nil
}

// currentState reads the effective set with each policy's owner, which is the
// state a desired state is compared against.
func (s *Service) currentState(ctx context.Context) (CurrentState, error) {
	schema, err := store.LatestSchema(ctx, s.store.Pool())
	if err != nil {
		return CurrentState{}, err
	}
	decoded, err := DecodeSchema(schema.Document)
	if err != nil {
		return CurrentState{}, err
	}
	records, err := store.EffectivePolicies(ctx, s.store.Pool())
	if err != nil {
		return CurrentState{}, err
	}
	out := CurrentState{Schema: *decoded}
	for _, rec := range records {
		if IsReserved(rec.ID) {
			continue
		}
		p, perr := rec.Policy()
		if perr != nil {
			return CurrentState{}, perr
		}
		out.Policies = append(out.Policies, CurrentPolicy{Policy: p, Origin: rec.Origin})
	}
	return out, nil
}

func adoptionCount(kinds []string) int {
	n := 0
	for _, k := range kinds {
		if k == AdoptionKind {
			n++
		}
	}
	return n
}
