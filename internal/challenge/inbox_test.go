package challenge_test

import (
	"context"
	"testing"

	"github.com/d0lim/stamp/internal/challenge"
)

// R21's server-side filter, against the database. The property that matters is
// that the list and the submission agree about who may approve: the store's
// query is a candidate filter and isTarget is the answer, so a set the SQL
// cannot evaluate must be excluded here and not shown.

func (f *quorumFixture) inbox(t *testing.T, subject string, extra map[string]any) []challenge.InboxItem {
	t.Helper()
	items, err := f.handler.Inbox(context.Background(), challenge.InboxRequest{
		Subject: f.idp.user(t, subject, extra),
		Now:     testNow,
	})
	if err != nil {
		t.Fatalf("inbox for %s: %v", subject, err)
	}
	return items
}

func TestInboxOffersAMemberTheirOwnDecisionAndNobodyElseTheirs(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(2, "bob", "carol"))

	mine := f.inbox(t, "bob", nil)
	if len(mine) != 1 {
		t.Fatalf("bob's inbox has %d items, want 1: %+v", len(mine), mine)
	}
	item := mine[0]
	if item.DecisionID != f.decision.ID || item.Ordinal != 0 {
		t.Errorf("the item names %s/%d, want %s/0", item.DecisionID, item.Ordinal, f.decision.ID)
	}
	if item.Need != 2 || item.Have != 0 {
		t.Errorf("collection state is %d/%d, want 0/2", item.Have, item.Need)
	}
	if item.Submitted {
		t.Error("an approver who has not voted is reported as having submitted")
	}
	if !item.ExpiresAt.Equal(f.decision.ExpiresAt) {
		t.Errorf("the item reports expiry %s, want the decision's %s", item.ExpiresAt, f.decision.ExpiresAt)
	}
	if item.PolicyID != f.decision.PolicyID || item.SubjectID != f.decision.SubjectID {
		t.Errorf("the item does not carry the decision's policy and subject: %+v", item)
	}

	// A decision that is not waiting on dave does not appear in dave's inbox.
	if theirs := f.inbox(t, "dave", nil); len(theirs) != 0 {
		t.Errorf("a non-target's inbox has %d items: %+v", len(theirs), theirs)
	}
}

// Submitting moves the collection state the list reports, and the item stays:
// an approver who has voted still has to be able to watch the quorum fill.
func TestInboxCollectionStateFollowsASubmission(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(2, "bob", "carol"))
	if _, err := f.submit(f.idp.user(t, "bob", nil), ""); err != nil {
		t.Fatalf("submit: %v", err)
	}

	mine := f.inbox(t, "bob", nil)
	if len(mine) != 1 {
		t.Fatalf("after voting bob's inbox has %d items, want 1", len(mine))
	}
	if mine[0].Have != 1 || !mine[0].Submitted {
		t.Errorf("after voting the item is %d/%d submitted=%v, want 1/2 submitted=true",
			mine[0].Have, mine[0].Need, mine[0].Submitted)
	}
	// Carol has not voted, and sees the same progress from her side.
	hers := f.inbox(t, "carol", nil)
	if len(hers) != 1 || hers[0].Have != 1 || hers[0].Submitted {
		t.Errorf("carol's view is %+v, want 1/2 submitted=false", hers)
	}
}

// The exact test is isTarget's, and it is the reason the SQL filter is only a
// candidate filter: a claim-resolved set matches every row in the query, and
// only the token decides. A person without the claim must not be shown a
// decision whose submission would refuse them.
func TestInboxAppliesTheExactTargetTestToAClaimResolvedSet(t *testing.T) {
	f := newQuorumFixture(t, claimQuorum(1, "stamp_approver"))

	holder := f.inbox(t, "bob", map[string]any{"stamp_approver": true})
	if len(holder) != 1 {
		t.Fatalf("a claim holder's inbox has %d items, want 1", len(holder))
	}
	if holder[0].Mode != challenge.ResolveClaim {
		t.Errorf("the item reports mode %q, want %q", holder[0].Mode, challenge.ResolveClaim)
	}

	for _, claims := range []map[string]any{
		nil,
		{"stamp_approver": false},
		{"stamp_approver": ""},
		{"some_other_claim": true},
	} {
		if got := f.inbox(t, "mallory", claims); len(got) != 0 {
			t.Errorf("a token with claims %v was offered %d decisions it cannot approve", claims, len(got))
		}
	}
}

// The inbox and the review agree. A row shown here is a row the review endpoint
// will serve, because both ask the same question of the same frozen set.
func TestEveryInboxItemIsReviewable(t *testing.T) {
	f := newQuorumFixture(t, membersQuorum(2, "bob", "carol"))
	bob := f.idp.user(t, "bob", nil)

	items := f.inbox(t, "bob", nil)
	if len(items) != 1 {
		t.Fatalf("inbox has %d items", len(items))
	}
	review, err := f.handler.Review(context.Background(), challenge.QuorumReviewRequest{
		DecisionID: items[0].DecisionID,
		Ordinal:    items[0].Ordinal,
		Subject:    bob,
		Now:        testNow,
	})
	if err != nil {
		t.Fatalf("an item the inbox offered is not reviewable: %v", err)
	}
	if review.Need != items[0].Need || review.Have != items[0].Have {
		t.Errorf("the list says %d/%d and the review says %d/%d",
			items[0].Have, items[0].Need, review.Have, review.Need)
	}
	if review.BindingHash == "" {
		t.Error("the review served no binding hash")
	}
}
