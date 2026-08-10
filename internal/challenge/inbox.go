package challenge

// inbox.go answers "what is waiting on me".
//
// R21 puts the inbox's filter on the server, and this is why it has to be here
// rather than in the API layer or the console: whether a person is a target of
// a quorum is a question about the frozen approver set and their token, and
// this package already answers it once, in isTarget, for Review and Submit. A
// second implementation anywhere else is a second opinion about who may
// approve — and the one that would be wrong is the one nobody submits through.
//
// The store's query is a candidate filter, not an authorization: it admits sets
// that name the member and every claim-resolved set, because SQL cannot read a
// token. Everything it returns is put through isTarget before it is shown. That
// split is deliberate — the index does the narrowing and the exact test decides.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/store"
)

// InboxRequest asks for the decisions one approver is holding up.
type InboxRequest struct {
	// Subject is the authenticated approver. Required.
	Subject *identity.Subject
	// Now is the instant expiry is judged against.
	Now time.Time
	// Limit bounds the page; zero selects the store's default.
	Limit int
}

// InboxItem is one row of the approval inbox.
//
// It carries no request body and no fact snapshot. A list is a list, and the
// material an approval binds to is served by [Quorum.Review] together with the
// hash that covers it — putting a partial copy of it here would create a second
// rendering of "what you are approving" that no hash is computed over.
type InboxItem struct {
	DecisionID string `json:"decision_id"`
	Ordinal    int    `json:"ordinal"`
	PolicyID   string `json:"policy_id"`
	SubjectID  string `json:"subject_id"`
	ResourceID string `json:"resource_id"`
	Action     string `json:"action"`
	// Have and Need are the collection state R21 asks the list to show.
	Have int            `json:"have"`
	Need int            `json:"need"`
	Mode ResolutionMode `json:"mode"`
	// Submitted reports whether this approver has already voted here.
	Submitted bool      `json:"submitted"`
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is the decision's own deadline and the sort key: R21 orders the
	// inbox by how soon the chance to act is lost.
	ExpiresAt time.Time `json:"expires_at"`
}

// InboxLister is the read the console's approval inbox performs.
type InboxLister interface {
	Inbox(ctx context.Context, req InboxRequest) ([]InboxItem, error)
}

var _ InboxLister = (*Quorum)(nil)

// Inbox returns the open quorum challenges this approver is a target of,
// soonest expiry first.
func (q *Quorum) Inbox(ctx context.Context, req InboxRequest) ([]InboxItem, error) {
	if q.db == nil {
		return nil, errors.New("challenge: this quorum handler has no store to read")
	}
	member, err := approverID(req.Subject)
	if err != nil {
		return nil, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	candidates, err := store.OpenQuorumChallenges(ctx, q.db, member, now.UTC(), req.Limit)
	if err != nil {
		return nil, err
	}

	out := make([]InboxItem, 0, len(candidates))
	for _, candidate := range candidates {
		detail, derr := decodeQuorumDetail(candidate.Challenge.Detail)
		if derr != nil {
			// A challenge row whose detail does not decode is a corrupted
			// record, not a reason to refuse the whole inbox: the approver
			// still has to be able to act on everything else waiting on them.
			// It stays out of the list, and Review would refuse it by name.
			continue
		}
		target, terr := isTarget(detail, req.Subject)
		if terr != nil {
			return nil, fmt.Errorf("challenge: inbox: decision %q: %w", candidate.Decision.ID, terr)
		}
		if !target {
			continue
		}
		out = append(out, InboxItem{
			DecisionID: candidate.Decision.ID,
			Ordinal:    candidate.Challenge.Ordinal,
			PolicyID:   candidate.Decision.PolicyID,
			SubjectID:  candidate.Decision.SubjectID,
			ResourceID: candidate.Decision.ResourceID,
			Action:     candidate.Decision.Action,
			Have:       candidate.Approvals,
			Need:       detail.Threshold,
			Mode:       detail.Mode,
			Submitted:  candidate.Submitted,
			CreatedAt:  candidate.Decision.CreatedAt,
			ExpiresAt:  candidate.Decision.ExpiresAt,
		})
	}
	return out, nil
}
