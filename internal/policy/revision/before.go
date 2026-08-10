package revision

// before.go rebuilds the "before" face of a submitted revision from the state in
// force.
//
// The weakening classifier decides how many approvals a revision needs (R33),
// and it decides it by comparing two policy sets. One of them is the state in
// force. Until this ran, both of them arrived in the proposer's request body:
// [Change.Before] was whatever the submitter said the policy used to be, and
// [Delta.SchemaBefore] was whatever the submitter said the schema used to be.
// [Delta.Validate] checked the *shape* of those fields — present when the kind
// wants one, naming the policy the change names — and nothing checked them
// against anything. A proposer who wrote a flattering previous state wrote their
// own classification: a quorum cut looks like a no-op, a widened approver set
// looks like a no-op, and a fact source moved from deny to allow is invisible
// because the classifier gives up on a nil schema before.
//
// So the server writes that half of the delta. Three things about how are the
// point rather than the plumbing.
//
// **It reconstructs and does not extend.** Only the changes the proposer
// declared are touched, and no change is invented for a policy the proposer did
// not name. Computing the before face as "everything in the store" would turn
// every console-authored policy into a deletion on every file apply, which is
// the whole of D23 in reverse.
//
// **It runs before everything.** Validate, CheckSatisfiable, the outcome check,
// the classifier and the digest all read the reconstructed delta.
// Reconstructing before Validate is what turns "an add carries no before" from a
// check on the client's echo into an invariant, and has the side effect that the
// console need not send a before at all. Reconstructing before the digest is
// R31: the hash an approval is bound to, and the delta an approver is shown,
// have to be the same delta, and it has to be the true one.
//
// **It leaves the kind alone, and leaves a change alone whose policy the store
// does not hold.** A modify of a policy that does not exist and an add of one
// that does are already refused — by [Delta.Result], through the outcome check,
// which runs before the classifier. Filling in a nil before for a policy that is
// not there would move that refusal into [Delta.Validate] and give it a worse
// error message for no gain.

import (
	"context"

	"github.com/d0lim/stamp/internal/store"
)

// reconstructed returns d with its before face taken from the state in force.
//
// The schema before is the stored effective schema, and is filled in only when
// the delta proposes a schema at all: a delta that carries no schema after has
// no schema face, and giving it a before would make [Delta.SchemaChanged] report
// a schema revision for every policy edit — including for the empty delta
// [Delta.Validate] exists to refuse.
func (s *Service) reconstructed(ctx context.Context, d Delta) (Delta, error) {
	out := Delta{SchemaAfter: d.SchemaAfter}
	if len(d.Changes) > 0 {
		out.Changes = make([]Change, len(d.Changes))
		copy(out.Changes, d.Changes)
	}

	if d.SchemaAfter != nil {
		rec, err := store.LatestSchema(ctx, s.store.Pool())
		if err != nil {
			return Delta{}, err
		}
		schema, err := DecodeSchema(rec.Document)
		if err != nil {
			return Delta{}, err
		}
		out.SchemaBefore = schema
	}

	if len(out.Changes) == 0 {
		return out, nil
	}
	records, err := store.EffectivePolicies(ctx, s.store.Pool())
	if err != nil {
		return Delta{}, err
	}
	held := make(map[string]store.PolicyRecord, len(records))
	for _, rec := range records {
		held[rec.ID] = rec
	}

	for i := range out.Changes {
		c := &out.Changes[i]
		if c.Kind == ChangeAdd {
			// An add has no before by definition, and an add that carries one is
			// malformed. Overwriting the field here would swallow that.
			continue
		}
		rec, exists := held[c.PolicyID]
		if !exists {
			continue
		}
		// Decoded per change rather than shared: normalization rewrites a
		// condition tree in place, and the classifier normalizes what it is
		// handed.
		stored, perr := rec.Policy()
		if perr != nil {
			return Delta{}, perr
		}
		c.Before = stored
	}
	return out, nil
}
