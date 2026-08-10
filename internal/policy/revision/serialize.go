package revision

// serialize.go owns the gate that admits one pending revision at a time, and
// the fourth way out of it.
//
// D24 chose serialization so that an approver always reviews one diff against
// the state currently in force, and then observed that serialization alone
// sticks. Three of the four release paths belong to the governance unit: the
// proposer's own withdrawal, a quorum-sized withdrawal of somebody else's
// proposal, and the operator's pending-lifetime cap. The fourth is here.
//
// Same-origin supersession exists for one usage in particular, and D24's table
// names it exactly: a CI that applies on every merge. Such a proposal is not
// one change among many, it is a statement of the *whole* desired state, so the
// next merge's proposal strictly replaces the last one. Refusing it would leave
// the gate held by a diff nobody intends to approve while every later merge
// fails. The approvals collected so far are void when it happens — they were
// endorsements of a different change set, and the approval binding hash covers
// the delta digest precisely so that they cannot be carried over.
//
// Supersession is therefore restricted to the file path, and not extended to
// two console submissions that merely share an origin. Two form edits are two
// people's separate intentions, not two versions of one desired state, and
// letting the second replace the first would be a way to discard a colleague's
// revision under review without a withdrawal anybody can see. A console
// proposal holding the gate is released by the other three paths — its
// proposer, a quorum, or the lifetime cap — which is why D24 needs all four.
//
// A proposal from the *other* origin never supersedes either, for the same
// reason in the larger: one authoring path discarding the other's revision is
// the reverse of what the gate is for.
//
// All four paths are rate limited. Without that, withdraw-and-resubmit — or
// supersede-and-supersede — is an unbounded way to hold the gate forever while
// never leaving an approver anything to act on.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/d0lim/stamp/internal/store"
)

// AuditKindRevisionSuperseded records a pending proposal replaced by a newer
// one from the same authoring path.
const AuditKindRevisionSuperseded = "policy.revision.superseded"

// ErrRateLimited reports a submission refused because the origin has already
// taken and released the gate too often inside the window.
var ErrRateLimited = errors.New("revision: this authoring path is submitting revisions too quickly")

// Rate bounds how often one authoring origin may open a revision.
type Rate struct {
	// Window is the trailing period the submissions are counted over.
	Window time.Duration
	// Burst is how many submissions that window admits.
	Burst int
}

// DefaultRate is the bound an installation gets when it configures none.
//
// It is loose enough that a repository merging every few minutes never sees it
// and tight enough that a loop cannot hold the gate: the failure it answers is
// automation stuck in a retry, not a human clicking twice.
func DefaultRate() Rate { return Rate{Window: time.Minute, Burst: 10} }

// PendingRevision is what a caller refused by the gate is told about the
// proposal holding it.
//
// R47 requires the identifier and the collection status together. The
// identifier alone would send a CI to a console to find out whether the
// revision it is blocked behind is one approval short or has not been looked
// at; a count alone would not say which revision it counted.
type PendingRevision struct {
	ID         string       `json:"id"`
	Origin     store.Origin `json:"origin"`
	ProposerID string       `json:"proposer_id"`
	Weakening  bool         `json:"weakening"`
	Threshold  int          `json:"threshold"`
	Collected  int          `json:"collected"`
	CreatedAt  time.Time    `json:"created_at"`
}

// PendingError is the gate's refusal, carrying the open proposal.
type PendingError struct {
	Pending PendingRevision
}

// Error renders the refusal with everything a caller needs to act without a
// second request.
func (e *PendingError) Error() string {
	return fmt.Sprintf("%s: revision %q from the %q path is open with %d of %d approvals collected",
		ErrRevisionPending.Error(), e.Pending.ID, e.Pending.Origin, e.Pending.Collected, e.Pending.Threshold)
}

// Unwrap makes the sentinel test work on the richer error, so every caller that
// already handles [ErrRevisionPending] keeps working.
func (e *PendingError) Unwrap() error { return ErrRevisionPending }

// PendingStatus reports the open revision and how far its approvals have got.
func (s *Service) PendingStatus(ctx context.Context) (PendingRevision, bool, error) {
	proposal, ok, err := s.Pending(ctx)
	if err != nil || !ok {
		return PendingRevision{}, false, err
	}
	out := PendingRevision{
		ID:         proposal.ID,
		Origin:     proposal.Origin,
		ProposerID: proposal.ProposerID,
		Weakening:  proposal.Weakening,
		Threshold:  proposal.Threshold,
		CreatedAt:  proposal.CreatedAt,
	}
	if proposal.DecisionID != "" && proposal.Threshold > 0 {
		collected, cerr := store.CountApprovals(ctx, s.store.Pool(), proposal.DecisionID, 0, store.VerdictApprove)
		if cerr != nil {
			return PendingRevision{}, false, cerr
		}
		out.Collected = collected
	}
	return out, true, nil
}

// gate refuses a submission the open revision blocks.
//
// It is advisory: the authoritative serialization is the partial unique index,
// which [Service.insertProposal] runs into inside its transaction. This check
// exists so the refusal happens before the work — a caller holding a directory
// of documents should not have them parsed and statically validated only to be
// turned away at the insert.
func (s *Service) gate(ctx context.Context, origin store.Origin) error {
	pending, ok, err := s.PendingStatus(ctx)
	if err != nil || !ok {
		return err
	}
	if supersedes(pending.Origin, origin) {
		// The declarative path may replace its own proposal; the replacement
		// happens inside the insert's transaction, where the index is.
		return nil
	}
	return &PendingError{Pending: pending}
}

// supersedes reports whether a submission from one origin replaces the pending
// proposal of another.
//
// It is one predicate rather than a condition spelled out at each of the two
// places that need it, because the two places are an advisory check outside a
// transaction and the authoritative one inside it: the day they disagree, one
// path would discard a proposal the other said it would not.
func supersedes(pending, incoming store.Origin) bool {
	return pending == incoming && incoming == store.OriginFile
}

// checkRate refuses an origin that has opened too many revisions in the window.
func (s *Service) checkRate(ctx context.Context, q store.Querier, origin store.Origin) error {
	if s.rate.Burst <= 0 || s.rate.Window <= 0 {
		return nil
	}
	var n int
	err := q.QueryRow(ctx,
		`SELECT count(*) FROM policy_revisions WHERE origin = $1 AND created_at > $2`,
		string(origin), s.now().UTC().Add(-s.rate.Window)).Scan(&n)
	if err != nil {
		return fmt.Errorf("revision: count recent revisions: %w", err)
	}
	if n < s.rate.Burst {
		return nil
	}
	return fmt.Errorf("%w: the %q path has opened %d revisions in the last %s, and the limit is %d",
		ErrRateLimited, origin, n, s.rate.Window, s.rate.Burst)
}

// supersede closes the pending proposal of one origin so a newer one from the
// same origin can take the gate.
//
// It runs on the caller's transaction rather than through a helper of its own:
// the audit writer holds its append mutex across the whole audited transaction,
// so a nested call that opened a second one would deadlock against the very
// writer this Appender belongs to.
func (s *Service) supersede(ctx context.Context, tx pgx.Tx, ap *store.Appender,
	origin store.Origin, replacement string,
) error {
	var id string
	err := tx.QueryRow(ctx,
		`SELECT id FROM policy_revisions WHERE state = 'pending' FOR UPDATE`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("revision: read the pending revision: %w", err)
	}
	open, err := readProposal(ctx, tx, id)
	if err != nil {
		return err
	}
	if !supersedes(open.Origin, origin) {
		// Re-checked inside the transaction because the advisory check outside
		// it can lose a race, and losing it silently would mean one path
		// discarding another's revision.
		pending := PendingRevision{
			ID: open.ID, Origin: open.Origin, ProposerID: open.ProposerID,
			Weakening: open.Weakening, Threshold: open.Threshold, CreatedAt: open.CreatedAt,
		}
		if open.DecisionID != "" && open.Threshold > 0 {
			collected, cerr := store.CountApprovals(ctx, tx, open.DecisionID, 0, store.VerdictApprove)
			if cerr != nil {
				return cerr
			}
			pending.Collected = collected
		}
		return &PendingError{Pending: pending}
	}

	collected := 0
	if open.DecisionID != "" {
		n, cerr := store.CountApprovals(ctx, tx, open.DecisionID, 0, store.VerdictApprove)
		if cerr != nil {
			return cerr
		}
		collected = n
	}
	if err := closeProposal(ctx, tx, open.ID, StateSuperseded, s.now().UTC()); err != nil {
		return err
	}
	if open.DecisionID != "" {
		// Cancelling the decision is what voids the approvals already
		// collected. They endorsed a delta digest that is not this one, and the
		// approval binding hash covers that digest, so carrying them over is
		// not a thing this system can express even if it wanted to.
		if err := cancelDecision(ctx, tx, ap, open.DecisionID,
			"superseded by a newer revision from the same authoring path"); err != nil {
			return err
		}
	}
	_, err = ap.Append(ctx, store.AuditEntry{
		Kind:    AuditKindRevisionSuperseded,
		Subject: open.ID,
		Payload: map[string]any{
			SeverityKey:             SeverityNotice,
			"origin":                string(origin),
			"replaced_by":           replacement,
			"approvals_invalidated": collected,
			"threshold":             open.Threshold,
		},
	})
	return err
}
