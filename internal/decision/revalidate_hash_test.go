package decision_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/d0lim/stamp/internal/decision"
)

// Approval-hash verification is the gate between "the approvals we already have"
// and "the material we are now asking about". Every case below is a way to walk
// approvals across a revision they were not given for, and each was written
// before the check it exercises.
//
// The rule the cases encode: an approval survives only when the re-issued
// challenge binds to a digest that is present, well formed, and identical on
// both sides. Anything else invalidates, because the cost of invalidating
// wrongly is collecting an approval twice and the cost of preserving wrongly is
// an authorization nobody gave.

const (
	digestA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	digestB = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"
)

func detail(t *testing.T, threshold int, hash string, members ...string) json.RawMessage {
	t.Helper()
	body := map[string]any{"threshold": threshold, "mode": "members", "members": members}
	if hash != "" {
		body["binding_hash"] = hash
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}
	return raw
}

func TestApprovalsSurviveAnIdenticalBinding(t *testing.T) {
	preserved, err := decision.PreservesApprovals(
		detail(t, 2, digestA, "a", "b", "c"),
		detail(t, 2, digestA, "a", "b", "c"))
	if err != nil {
		t.Fatalf("PreservesApprovals: %v", err)
	}
	if !preserved {
		t.Fatal("preserved = false, want true for an unchanged binding")
	}
}

// R31 keeps the threshold out of the hash on purpose: raising a quorum must not
// evaporate the approvals already collected, or raising one would be harder than
// lowering one.
func TestRaisingTheThresholdAlonePreservesApprovals(t *testing.T) {
	preserved, err := decision.PreservesApprovals(
		detail(t, 2, digestA, "a", "b", "c"),
		detail(t, 3, digestA, "a", "b", "c"))
	if err != nil {
		t.Fatalf("PreservesApprovals: %v", err)
	}
	if !preserved {
		t.Fatal("preserved = false, want true — the threshold is not an input to the binding hash")
	}
}

// Hex casing is a rendering choice, not a change of material.
func TestBindingHashComparisonIgnoresHexCase(t *testing.T) {
	preserved, err := decision.PreservesApprovals(
		detail(t, 2, strings.ToUpper(digestA), "a", "b"),
		detail(t, 2, digestA, "a", "b"))
	if err != nil {
		t.Fatalf("PreservesApprovals: %v", err)
	}
	if !preserved {
		t.Fatal("preserved = false, want true — the digest is the same digest")
	}
}

func TestDifferentBindingInvalidatesApprovals(t *testing.T) {
	preserved, err := decision.PreservesApprovals(
		detail(t, 2, digestA, "a", "b"),
		detail(t, 2, digestB, "a", "b"))
	if err != nil {
		t.Fatalf("PreservesApprovals: %v", err)
	}
	if preserved {
		t.Fatal("preserved = true, want false — the approver reviewed different material")
	}
}

// Bypass: hand back a re-issued challenge with no binding hash at all. A check
// that only compared the two strings would find "" equal to "" and preserve
// every approval ever collected.
func TestMissingBindingHashNeverPreservesApprovals(t *testing.T) {
	cases := map[string]struct{ stored, reissued json.RawMessage }{
		"reissued has none": {detail(t, 2, digestA, "a"), detail(t, 2, "", "a")},
		"stored has none":   {detail(t, 2, "", "a"), detail(t, 2, digestA, "a")},
		"neither has one":   {detail(t, 2, "", "a"), detail(t, 2, "", "a")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			preserved, err := decision.PreservesApprovals(tc.stored, tc.reissued)
			if err != nil {
				t.Fatalf("PreservesApprovals: %v", err)
			}
			if preserved {
				t.Fatal("preserved = true, want false — an absent digest binds nothing")
			}
		})
	}
}

// Bypass: put a short, matching string in both details. Two equal values that
// are not digests are not evidence that the material is unchanged.
func TestMalformedBindingHashNeverPreservesApprovals(t *testing.T) {
	cases := map[string]string{
		"too short":    "00",
		"not hex":      strings.Repeat("z", 64),
		"too long":     digestA + "00",
		"whitespace":   "  " + digestA + "  ",
		"empty object": "",
	}
	for name, hash := range cases {
		t.Run(name, func(t *testing.T) {
			preserved, err := decision.PreservesApprovals(
				detail(t, 2, hash, "a"), detail(t, 2, hash, "a"))
			if err != nil {
				t.Fatalf("PreservesApprovals: %v", err)
			}
			if preserved {
				t.Fatalf("preserved = true for %q, want false — that is not a digest", hash)
			}
		})
	}
}

// Bypass: hand over a detail the decoder cannot read and hope the failure is
// treated as "nothing changed".
func TestUnreadableDetailNeverPreservesApprovals(t *testing.T) {
	cases := map[string]json.RawMessage{
		"empty":   {},
		"null":    json.RawMessage("null"),
		"garbage": json.RawMessage("{not json"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			preserved, _ := decision.PreservesApprovals(raw, detail(t, 2, digestA, "a"))
			if preserved {
				t.Fatal("preserved = true, want false for an unreadable stored detail")
			}
			preserved, _ = decision.PreservesApprovals(detail(t, 2, digestA, "a"), raw)
			if preserved {
				t.Fatal("preserved = true, want false for an unreadable re-issued detail")
			}
		})
	}
}
