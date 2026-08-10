// Package revision turns a change to the policy set into something STAMP has to
// authorize with its own decision machinery.
//
// Four things live here and they are deliberately one package.
//
// The proposal's data type is a delta of the policy *set* — add, modify, delete
// and take-ownership entries, plus the schema on either side — and never a
// single policy. A one-policy edit is a one-element delta. Modelling the single
// policy as the base type and the set as a special case would give the weakening
// classifier, the approval hash and the revaluation hook two implementations
// each, and the second one always arrives after the first has already been
// trusted (D22).
//
// Weakening is classified over that delta as a whole. A delta is weakening if
// any element of it is, the requirement is computed once for the set, and the
// revision takes effect all or not at all — there is no partial approval, so
// there is no bundle in which a relaxation rides along with additions and
// inherits their lighter treatment (R6, R33).
//
// The governance policy is itself a reserved policy in the store, so changing
// the rules for changing policies goes through the rules currently in force
// (D6). Installation starts in solo-admin mode; the lock action replaces the
// reserved policy with a quorum-bearing one and cannot be undone from inside the
// running system (R34).
//
// Everything before the lock is gated by a one-time bootstrap token printed at
// first start. The token constrains who may act, not where the process listens,
// so a container or a Helm deployment still binds whatever address it was
// given.
package revision

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// Errors the delta type returns as sentinels.
var (
	// ErrInvalidDelta reports a proposal that is not well formed: an empty
	// change list, an add carrying a "before", two entries for one policy.
	ErrInvalidDelta = errors.New("revision: malformed revision delta")

	// ErrDecodeDelta reports a stored or submitted delta whose policy documents
	// could not be read back.
	ErrDecodeDelta = errors.New("revision: cannot decode revision delta")
)

// DeltaDigestContext is the domain separator in a delta's digest. The digest
// travels in the governance decision's request, which is covered by the approval
// binding hash, so an approval is bound to the exact change set the approver was
// shown. Separating the domain keeps a digest computed here from being
// replayable as a digest computed anywhere else.
const DeltaDigestContext = "stamp.revision-delta.v1"

// ChangeKind names what one element of a delta does to one policy.
type ChangeKind string

// The change kinds.
const (
	// ChangeAdd introduces a policy that does not exist yet.
	ChangeAdd ChangeKind = "add"
	// ChangeModify replaces a live policy with a new version.
	ChangeModify ChangeKind = "modify"
	// ChangeDelete tombstones a live policy.
	ChangeDelete ChangeKind = "delete"
	// ChangeTakeOwnership moves a policy between authoring paths. It is the
	// explicit handover D23 requires: origin never moves implicitly, so the
	// intent has to be an element of the delta rather than a side effect of a
	// write.
	ChangeTakeOwnership ChangeKind = "take_ownership"
)

// ChangeKinds returns every change kind, in declaration order.
func ChangeKinds() []ChangeKind {
	return []ChangeKind{ChangeAdd, ChangeModify, ChangeDelete, ChangeTakeOwnership}
}

// Valid reports whether k is one of the declared change kinds.
func (k ChangeKind) Valid() bool {
	for _, known := range ChangeKinds() {
		if k == known {
			return true
		}
	}
	return false
}

// Change is one element of a delta.
//
// Before and After are the policy on either side of the change. Which of them
// are set is fixed by Kind and checked by [Delta.Validate]: an add has only an
// After, a delete has only a Before, and the other two have both. A take-
// ownership entry may carry an unchanged policy — moving a policy between
// authoring paths is a change to who owns it, not necessarily to what it says.
//
// Before is not the submitter's to state. The governance path replaces it with
// the policy the store holds before anything reads it (see before.go), so a
// submission may leave it empty and a submission that fills it in wrongly is
// corrected rather than believed. After is the proposal; Before is the fact.
type Change struct {
	Kind     ChangeKind
	PolicyID string
	Before   *policy.Policy
	After    *policy.Policy

	// FromOrigin and ToOrigin are set on a take-ownership entry and name the
	// authoring paths the policy moves between.
	FromOrigin store.Origin
	ToOrigin   store.Origin
}

// Delta is a proposed change to the policy set.
//
// The schema sits alongside the policy changes because a fact source's failure
// behaviour is declared there, and loosening one from deny to allow is a
// weakening that no policy-level diff would ever show (R33).
//
// SchemaBefore, like [Change.Before], is the server's: the governance path fills
// it from the schema in force whenever a delta proposes a schema at all.
type Delta struct {
	Changes      []Change
	SchemaBefore *policy.Schema
	SchemaAfter  *policy.Schema
}

// Single builds the one-element delta a form edit produces. A nil before is an
// add, a nil after is a delete, and both present is a modify.
func Single(before, after *policy.Policy) Delta {
	switch {
	case before == nil && after == nil:
		return Delta{}
	case before == nil:
		return Delta{Changes: []Change{{Kind: ChangeAdd, PolicyID: after.ID, After: after}}}
	case after == nil:
		return Delta{Changes: []Change{{Kind: ChangeDelete, PolicyID: before.ID, Before: before}}}
	default:
		return Delta{Changes: []Change{{Kind: ChangeModify, PolicyID: after.ID, Before: before, After: after}}}
	}
}

// Diff computes the delta that turns before into after.
//
// It compares by policy identifier and by encoded document, never by file or by
// position. The caller decides what "before" contains: the file path hands it
// only the file-authored policies, because a comparison over the whole set would
// compute every console-authored policy as a deletion on every run (D23).
func Diff(before, after *policy.Set) Delta {
	var d Delta
	if before != nil {
		schema := before.Schema
		d.SchemaBefore = &schema
	}
	if after != nil {
		schema := after.Schema
		d.SchemaAfter = &schema
	}

	beforeByID := indexPolicies(before)
	afterByID := indexPolicies(after)

	ids := make([]string, 0, len(beforeByID)+len(afterByID))
	for id := range beforeByID {
		ids = append(ids, id)
	}
	for id := range afterByID {
		if _, ok := beforeByID[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	for _, id := range ids {
		old, hadOld := beforeByID[id]
		fresh, hasNew := afterByID[id]
		switch {
		case !hadOld:
			d.Changes = append(d.Changes, Change{Kind: ChangeAdd, PolicyID: id, After: fresh})
		case !hasNew:
			d.Changes = append(d.Changes, Change{Kind: ChangeDelete, PolicyID: id, Before: old})
		case !samePolicy(old, fresh):
			d.Changes = append(d.Changes, Change{Kind: ChangeModify, PolicyID: id, Before: old, After: fresh})
		}
	}
	return d
}

func indexPolicies(s *policy.Set) map[string]*policy.Policy {
	out := map[string]*policy.Policy{}
	if s == nil {
		return out
	}
	for i := range s.Policies {
		out[s.Policies[i].ID] = &s.Policies[i]
	}
	return out
}

// samePolicy compares two policies by their canonical documents. Comparing the
// Go values would report a difference for two spellings of the same policy —
// a nil argument list and an empty one — that normalization exists to collapse.
func samePolicy(a, b *policy.Policy) bool {
	left, lerr := EncodePolicy(a)
	right, rerr := EncodePolicy(b)
	if lerr != nil || rerr != nil {
		return false
	}
	return left == right
}

// Len reports how many policies the delta touches.
func (d Delta) Len() int { return len(d.Changes) }

// PolicyIDs returns the identifiers the delta touches, sorted.
func (d Delta) PolicyIDs() []string {
	out := make([]string, 0, len(d.Changes))
	for _, c := range d.Changes {
		out = append(out, c.PolicyID)
	}
	sort.Strings(out)
	return out
}

// Touches reports whether the delta changes a named policy.
func (d Delta) Touches(id string) bool {
	for _, c := range d.Changes {
		if c.PolicyID == id {
			return true
		}
	}
	return false
}

// Change returns the delta's entry for a policy.
func (d Delta) Change(id string) (Change, bool) {
	for _, c := range d.Changes {
		if c.PolicyID == id {
			return c, true
		}
	}
	return Change{}, false
}

// SchemaChanged reports whether the delta carries a schema revision.
func (d Delta) SchemaChanged() bool {
	if d.SchemaBefore == nil || d.SchemaAfter == nil {
		return d.SchemaBefore != d.SchemaAfter
	}
	left, lerr := EncodeSchema(d.SchemaBefore)
	right, rerr := EncodeSchema(d.SchemaAfter)
	if lerr != nil || rerr != nil {
		return true
	}
	return left != right
}

// Validate reports whether the delta is well formed.
//
// It says nothing about whether the change is permitted — that is the
// classifier's and the governance path's job. It only refuses proposals that
// cannot be reasoned about at all: an empty one, an add carrying a before, two
// entries claiming the same policy.
func (d Delta) Validate() error {
	if len(d.Changes) == 0 && !d.SchemaChanged() {
		return fmt.Errorf("%w: a revision must change at least one policy or the schema", ErrInvalidDelta)
	}
	seen := make(map[string]struct{}, len(d.Changes))
	for i, c := range d.Changes {
		if !c.Kind.Valid() {
			return fmt.Errorf("%w: change %d has unknown kind %q", ErrInvalidDelta, i, c.Kind)
		}
		if c.PolicyID == "" || !policy.ValidName(c.PolicyID) {
			return fmt.Errorf("%w: change %d names policy %q, which is not a valid identifier",
				ErrInvalidDelta, i, c.PolicyID)
		}
		if _, dup := seen[c.PolicyID]; dup {
			return fmt.Errorf("%w: policy %q appears in more than one change; a delta states one outcome per policy",
				ErrInvalidDelta, c.PolicyID)
		}
		seen[c.PolicyID] = struct{}{}

		if err := c.validateShape(i); err != nil {
			return err
		}
	}
	return nil
}

func (c Change) validateShape(index int) error {
	wantBefore := c.Kind != ChangeAdd
	wantAfter := c.Kind != ChangeDelete
	switch {
	case wantBefore && c.Before == nil:
		return fmt.Errorf("%w: change %d is a %s and carries no previous policy", ErrInvalidDelta, index, c.Kind)
	case !wantBefore && c.Before != nil:
		return fmt.Errorf("%w: change %d is an %s and carries a previous policy", ErrInvalidDelta, index, c.Kind)
	case wantAfter && c.After == nil:
		return fmt.Errorf("%w: change %d is a %s and carries no new policy", ErrInvalidDelta, index, c.Kind)
	case !wantAfter && c.After != nil:
		return fmt.Errorf("%w: change %d is a %s and carries a new policy", ErrInvalidDelta, index, c.Kind)
	}
	if c.Before != nil && c.Before.ID != c.PolicyID {
		return fmt.Errorf("%w: change %d names %q but its previous document says %q",
			ErrInvalidDelta, index, c.PolicyID, c.Before.ID)
	}
	if c.After != nil && c.After.ID != c.PolicyID {
		return fmt.Errorf("%w: change %d names %q but its new document says %q",
			ErrInvalidDelta, index, c.PolicyID, c.After.ID)
	}
	if c.Kind == ChangeTakeOwnership {
		if !c.FromOrigin.Valid() || !c.ToOrigin.Valid() {
			return fmt.Errorf("%w: change %d hands %q over without naming both authoring paths",
				ErrInvalidDelta, index, c.PolicyID)
		}
		if c.FromOrigin == c.ToOrigin {
			return fmt.Errorf("%w: change %d hands %q from the %s path to itself",
				ErrInvalidDelta, index, c.PolicyID, c.FromOrigin)
		}
	}
	return nil
}

// Result applies the delta to a base set and returns what the policy set becomes.
//
// This is what the whole revision is validated against before it is ever
// proposed: a delta whose outcome does not validate is refused at the door
// rather than after a quorum has spent its attention on it.
func (d Delta) Result(base *policy.Set) (*policy.Set, error) {
	out := &policy.Set{}
	if base != nil {
		out.Schema = base.Schema
		out.Policies = append(out.Policies, base.Policies...)
	}
	if d.SchemaAfter != nil {
		out.Schema = *d.SchemaAfter
	}
	byID := make(map[string]int, len(out.Policies))
	for i := range out.Policies {
		byID[out.Policies[i].ID] = i
	}
	for _, c := range d.Changes {
		idx, exists := byID[c.PolicyID]
		switch c.Kind {
		case ChangeDelete:
			if !exists {
				return nil, fmt.Errorf("%w: cannot delete %q, which the set does not hold", ErrInvalidDelta, c.PolicyID)
			}
			out.Policies = append(out.Policies[:idx], out.Policies[idx+1:]...)
			byID = make(map[string]int, len(out.Policies))
			for i := range out.Policies {
				byID[out.Policies[i].ID] = i
			}
		case ChangeAdd:
			if exists {
				return nil, fmt.Errorf("%w: cannot add %q, which the set already holds", ErrInvalidDelta, c.PolicyID)
			}
			out.Policies = append(out.Policies, *c.After)
			byID[c.PolicyID] = len(out.Policies) - 1
		case ChangeModify, ChangeTakeOwnership:
			if !exists {
				return nil, fmt.Errorf("%w: cannot change %q, which the set does not hold", ErrInvalidDelta, c.PolicyID)
			}
			out.Policies[idx] = *c.After
		}
	}
	return out, nil
}

// Digest is the delta's content digest.
//
// It travels in the governance decision's request payload, and the request is
// one of the approval binding hash's inputs, so an approval collected for a
// revision is cryptographically bound to the change set the approver was shown.
// Without it an approver would be endorsing a revision identifier and trusting
// that nothing behind it moved.
func (d Delta) Digest() ([32]byte, error) {
	encoded, err := d.MarshalJSON()
	if err != nil {
		return [32]byte{}, err
	}
	var canonical any
	if err := json.Unmarshal(encoded, &canonical); err != nil {
		return [32]byte{}, fmt.Errorf("%w: %w", ErrDecodeDelta, err)
	}
	// encoding/json sorts object keys, so re-encoding the decoded form is a
	// function of the content and not of the order the fields were written in.
	stable, err := json.Marshal(map[string]any{"context": DeltaDigestContext, "delta": canonical})
	if err != nil {
		return [32]byte{}, fmt.Errorf("revision: digest delta: %w", err)
	}
	return sha256.Sum256(stable), nil
}

// ---------------------------------------------------------------------------
// serialization
//
// A delta is persisted and shipped over HTTP, and both sides of a policy change
// are stored as the exchange-format document rather than as a struct dump. The
// document is the artifact a person reads in a diff, and it is the one form for
// which "two spellings of the same policy are the same policy" already holds.
// ---------------------------------------------------------------------------

type changeJSON struct {
	Kind       ChangeKind   `json:"kind"`
	PolicyID   string       `json:"policy_id"`
	Before     string       `json:"before,omitempty"`
	After      string       `json:"after,omitempty"`
	FromOrigin store.Origin `json:"from_origin,omitempty"`
	ToOrigin   store.Origin `json:"to_origin,omitempty"`
}

type deltaJSON struct {
	Changes      []changeJSON `json:"changes"`
	SchemaBefore string       `json:"schema_before,omitempty"`
	SchemaAfter  string       `json:"schema_after,omitempty"`
}

// MarshalJSON renders the delta with each policy as its exchange-format
// document.
func (d Delta) MarshalJSON() ([]byte, error) {
	out := deltaJSON{Changes: make([]changeJSON, 0, len(d.Changes))}
	for _, c := range d.Changes {
		entry := changeJSON{
			Kind:       c.Kind,
			PolicyID:   c.PolicyID,
			FromOrigin: c.FromOrigin,
			ToOrigin:   c.ToOrigin,
		}
		var err error
		if c.Before != nil {
			if entry.Before, err = EncodePolicy(c.Before); err != nil {
				return nil, err
			}
		}
		if c.After != nil {
			if entry.After, err = EncodePolicy(c.After); err != nil {
				return nil, err
			}
		}
		out.Changes = append(out.Changes, entry)
	}
	var err error
	if d.SchemaBefore != nil {
		if out.SchemaBefore, err = EncodeSchema(d.SchemaBefore); err != nil {
			return nil, err
		}
	}
	if d.SchemaAfter != nil {
		if out.SchemaAfter, err = EncodeSchema(d.SchemaAfter); err != nil {
			return nil, err
		}
	}
	return json.Marshal(out)
}

// UnmarshalJSON reads a delta back, decoding each document through the same
// parser a hand-written file goes through.
func (d *Delta) UnmarshalJSON(raw []byte) error {
	var in deltaJSON
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return fmt.Errorf("%w: %w", ErrDecodeDelta, err)
	}
	out := Delta{Changes: make([]Change, 0, len(in.Changes))}
	for i, entry := range in.Changes {
		c := Change{
			Kind:       entry.Kind,
			PolicyID:   entry.PolicyID,
			FromOrigin: entry.FromOrigin,
			ToOrigin:   entry.ToOrigin,
		}
		var err error
		if entry.Before != "" {
			if c.Before, err = DecodePolicy(entry.Before); err != nil {
				return fmt.Errorf("%w: change %d: %w", ErrDecodeDelta, i, err)
			}
		}
		if entry.After != "" {
			if c.After, err = DecodePolicy(entry.After); err != nil {
				return fmt.Errorf("%w: change %d: %w", ErrDecodeDelta, i, err)
			}
		}
		out.Changes = append(out.Changes, c)
	}
	var err error
	if in.SchemaBefore != "" {
		if out.SchemaBefore, err = DecodeSchema(in.SchemaBefore); err != nil {
			return fmt.Errorf("%w: schema_before: %w", ErrDecodeDelta, err)
		}
	}
	if in.SchemaAfter != "" {
		if out.SchemaAfter, err = DecodeSchema(in.SchemaAfter); err != nil {
			return fmt.Errorf("%w: schema_after: %w", ErrDecodeDelta, err)
		}
	}
	*d = out
	return nil
}

// EncodePolicy renders one policy as its exchange-format document.
//
// The encoder normalizes in place, so the value handed in is canonicalized as a
// side effect. Callers that share a policy value between goroutines must clone
// it first; every caller in this package owns what it passes.
func EncodePolicy(p *policy.Policy) (string, error) {
	if p == nil {
		return "", nil
	}
	doc, err := policy.Marshal(&policy.Set{Policies: []policy.Policy{*p}})
	if err != nil {
		return "", fmt.Errorf("revision: encode policy %q: %w", p.ID, err)
	}
	return string(doc), nil
}

// DecodePolicy reads one policy back from its document.
func DecodePolicy(document string) (*policy.Policy, error) {
	set, err := policy.Decode(strings.NewReader(document))
	if err != nil {
		return nil, err
	}
	if len(set.Policies) != 1 {
		return nil, fmt.Errorf("%w: a change document must hold exactly one policy, got %d",
			ErrDecodeDelta, len(set.Policies))
	}
	return &set.Policies[0], nil
}

// EncodeSchema renders a schema as its exchange-format document.
func EncodeSchema(s *policy.Schema) (string, error) {
	if s == nil {
		return "", nil
	}
	doc, err := policy.Marshal(&policy.Set{Schema: *s})
	if err != nil {
		return "", fmt.Errorf("revision: encode schema: %w", err)
	}
	return string(doc), nil
}

// DecodeSchema reads a schema back from its document.
func DecodeSchema(document string) (*policy.Schema, error) {
	set, err := policy.Decode(strings.NewReader(document))
	if err != nil {
		return nil, err
	}
	schema := set.Schema
	return &schema, nil
}

// Clone returns a deep copy of a policy, taken through the exchange format.
//
// It exists because normalization rewrites a condition tree in place: two
// callers holding one policy value are two callers writing to the same nodes.
// Anything this package keeps beyond the life of a call goes through here first.
func Clone(p *policy.Policy) (*policy.Policy, error) {
	doc, err := EncodePolicy(p)
	if err != nil {
		return nil, err
	}
	if doc == "" {
		return nil, nil
	}
	return DecodePolicy(doc)
}
