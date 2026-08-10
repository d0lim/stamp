package revision

// weakening.go answers one question about a revision delta: does it relax any
// control the set currently enforces?
//
// The answer decides how expensive the revision is to adopt, so the classifier
// is the place a determined author would attack. Three properties are what make
// it hold up.
//
// It classifies the delta, never an element. A relaxation bundled with twenty
// additions is a weakening revision, because the revision takes effect all or
// not at all and no approver can endorse only the additions (R6).
//
// It errs toward weakening. The trigger comparison is a soundness proof in one
// direction only: a change is treated as a narrowing unless the new trigger can
// be *proved* to fire on at least every request the old one fired on. An
// undecidable condition edit therefore costs a weakening revision rather than
// slipping through as neutral, because the failure modes are not symmetric —
// over-charging a revision is friction, under-charging it is the bypass.
//
// It reads the schema as well as the policies. A fact source flipped from deny
// to allow on error is a fail-open switch that no policy-level diff would show
// (R33).

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/d0lim/stamp/internal/policy"
)

// Errors the classifier and the requirement computation return as sentinels.
var (
	// ErrUnsatisfiable reports a revision whose own approver set could never
	// meet its own quorum, or one whose approval requirement no eligible
	// approver set could meet (R34).
	ErrUnsatisfiable = errors.New("revision: the approver set cannot satisfy the quorum")

	// ErrFloorViolated reports a revision that breaks an operator floor. R23
	// stops such a revision at submission rather than collecting approvals for
	// something that could never take effect.
	ErrFloorViolated = errors.New("revision: the revision violates an operator floor")
)

// SchemaSubject is the finding subject used for a weakening that belongs to the
// schema rather than to any one policy — a fact source's failure behaviour, for
// instance. It is not a legal policy identifier, so it cannot collide with one.
const SchemaSubject = "@schema"

// Reason names one ground on which a revision is weakening. The set is R33's,
// closed: a classifier that invented grounds would be an operator surprise, and
// one that dropped them would be a bypass.
type Reason string

// The weakening grounds.
const (
	// ReasonQuorumReduced is a quorum threshold that went down.
	ReasonQuorumReduced Reason = "quorum_reduced"
	// ReasonApproverSetWidened is an approver set that admits somebody it did
	// not admit before.
	ReasonApproverSetWidened Reason = "approver_set_widened"
	// ReasonErrorBehaviourLoosened is a fact source whose failure behaviour went
	// from deny to allow.
	ReasonErrorBehaviourLoosened Reason = "error_behaviour_loosened"
	// ReasonChallengeRemoved is a challenge a policy no longer demands.
	ReasonChallengeRemoved Reason = "challenge_removed"
	// ReasonPolicyDeleted is a deleted policy. Deleting a policy removes every
	// challenge it carried, so it is always weakening.
	ReasonPolicyDeleted Reason = "policy_deleted"
	// ReasonTriggerNarrowed is a policy that now fires on fewer requests than it
	// did, which is deletion by another route.
	ReasonTriggerNarrowed Reason = "trigger_narrowed"
)

// Reasons returns every weakening ground, in declaration order.
func Reasons() []Reason {
	return []Reason{
		ReasonQuorumReduced, ReasonApproverSetWidened, ReasonErrorBehaviourLoosened,
		ReasonChallengeRemoved, ReasonPolicyDeleted, ReasonTriggerNarrowed,
	}
}

// Finding is one weakening the classifier found.
type Finding struct {
	// Subject is the policy identifier, or [SchemaSubject] for a schema-level
	// finding.
	Subject string `json:"subject"`
	Reason  Reason `json:"reason"`
	Detail  string `json:"detail"`
}

// String renders a finding for an audit payload or an error message.
func (f Finding) String() string { return string(f.Reason) + " on " + f.Subject + ": " + f.Detail }

// Classification is what the classifier concluded about a whole delta.
type Classification struct {
	Findings []Finding `json:"findings"`
}

// Weakening reports whether any element of the delta weakens the set.
//
// It is a property of the delta and never of one element. A revision that
// bundles a relaxation with additions is a weakening revision, because it takes
// effect all or not at all and no approver may endorse only the additions.
func (c Classification) Weakening() bool { return len(c.Findings) > 0 }

// Subjects returns the policies the findings name, in order and deduplicated.
func (c Classification) Subjects() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(c.Findings))
	for _, f := range c.Findings {
		if _, dup := seen[f.Subject]; dup {
			continue
		}
		seen[f.Subject] = struct{}{}
		out = append(out, f.Subject)
	}
	return out
}

// Classify reports every way the delta weakens the policy set.
//
// The policies it is handed are normalized as a side effect: structural
// comparison only means anything on canonical values, and normalization rewrites
// a condition tree in place. Every caller in this package owns what it passes;
// a caller that shares a policy value across goroutines must clone it first.
func Classify(d Delta) Classification {
	var out Classification
	out.Findings = append(out.Findings, schemaFindings(d.SchemaBefore, d.SchemaAfter)...)
	for _, c := range d.Changes {
		out.Findings = append(out.Findings, changeFindings(c)...)
	}
	return out
}

// schemaFindings reports fact sources whose failure behaviour was loosened.
//
// A source that disappears from the schema is not reported here: a condition
// referring to it would fail validation, so the revision is refused before the
// classification matters.
func schemaFindings(before, after *policy.Schema) []Finding {
	if before == nil || after == nil {
		return nil
	}
	var out []Finding
	for i := range before.Sources {
		old := normalizedOnError(before.Sources[i].OnError)
		fresh, ok := after.Source(before.Sources[i].Name)
		if !ok {
			continue
		}
		if old == policy.OnErrorDeny && normalizedOnError(fresh.OnError) == policy.OnErrorAllow {
			out = append(out, Finding{
				Subject: SchemaSubject,
				Reason:  ReasonErrorBehaviourLoosened,
				Detail: fmt.Sprintf("fact source %q now allows on error, and used to deny",
					before.Sources[i].Name),
			})
		}
	}
	return out
}

func normalizedOnError(e policy.OnError) policy.OnError {
	if e == "" {
		return policy.DefaultOnError
	}
	return e
}

func changeFindings(c Change) []Finding {
	switch c.Kind {
	case ChangeDelete:
		return []Finding{{
			Subject: c.PolicyID,
			Reason:  ReasonPolicyDeleted,
			Detail:  "the policy is removed, and with it every challenge it demanded",
		}}
	case ChangeAdd:
		// A new policy can only add requirements: the evaluator's restrictive-wins
		// rule means an added policy never relaxes an existing one (R33).
		return nil
	case ChangeModify, ChangeTakeOwnership:
		before, after := canonical(c.Before), canonical(c.After)
		if before == nil || after == nil {
			return nil
		}
		var out []Finding
		out = append(out, triggerFindings(c.PolicyID, before, after)...)
		out = append(out, challengeFindings(c.PolicyID, before, after)...)
		return out
	default:
		return nil
	}
}

// canonical returns the policy in normalized form. It copies the struct and
// normalizes, which is the form every structural comparison below assumes.
func canonical(p *policy.Policy) *policy.Policy {
	if p == nil {
		return nil
	}
	set := policy.Set{Policies: []policy.Policy{*p}}
	set.Normalize()
	return &set.Policies[0]
}

// ---------------------------------------------------------------------------
// the trigger
// ---------------------------------------------------------------------------

// triggerFindings reports a policy that now fires on fewer requests.
//
// The trigger is the actions a policy governs, the entity roles it binds, and
// the condition under which it applies. Narrowing any of the three is the same
// act as deleting the policy for the requests that fall out of it, and R33 puts
// deletion and narrowing on the same side for exactly that reason.
func triggerFindings(id string, before, after *policy.Policy) []Finding {
	if reason, narrowed := narrowing(before, after); narrowed {
		return []Finding{{Subject: id, Reason: ReasonTriggerNarrowed, Detail: reason}}
	}
	return nil
}

func narrowing(before, after *policy.Policy) (string, bool) {
	for _, a := range before.Actions {
		if !slices.Contains(after.Actions, a) {
			return fmt.Sprintf("the policy no longer governs the %q action", a), true
		}
	}
	for _, role := range policy.Roles() {
		oldBound, hadOld := before.EntityFor(role)
		newBound, hasNew := after.EntityFor(role)
		switch {
		case !hasNew:
			// An unbound role matches every request, so dropping a binding can
			// only widen.
			continue
		case !hadOld:
			return fmt.Sprintf("the policy now binds %s, so requests that do not carry one fall out of it", role), true
		case oldBound != newBound:
			return fmt.Sprintf("the policy binds %s to %q where it used to bind %q", role, newBound, oldBound), true
		}
	}
	if !widens(before.Condition, after.Condition) {
		return "the condition cannot be shown to hold wherever the previous one did", true
	}
	return "", false
}

// widens reports whether the new condition holds wherever the old one did.
//
// It is a proof, not a decision procedure: it answers true only for shapes it
// can actually establish, and false for everything else — including changes that
// happen to be widenings it cannot see. That asymmetry is the point. A false
// negative costs a revision a stricter approval requirement; a false positive
// would let an author narrow a policy out of existence for the price of a
// tightening.
//
// Every recursive call strictly reduces the total size of the two trees, so this
// terminates.
func widens(before, after policy.Node) bool {
	switch {
	case after == nil:
		// No condition means the policy applies whenever it matches, which is
		// the widest a trigger gets.
		return true
	case before == nil:
		return false
	case reflect.DeepEqual(before, after):
		return true
	}

	if l, ok := after.(policy.Logic); ok && l.Op == policy.LogicAny {
		for _, operand := range l.Operands {
			if widens(before, operand) {
				return true
			}
		}
	}
	if l, ok := before.(policy.Logic); ok && l.Op == policy.LogicAll {
		for _, operand := range l.Operands {
			if widens(operand, after) {
				return true
			}
		}
	}
	if l, ok := after.(policy.Logic); ok && l.Op == policy.LogicAll && len(l.Operands) > 0 {
		all := true
		for _, operand := range l.Operands {
			if !widens(before, operand) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	if l, ok := before.(policy.Logic); ok && l.Op == policy.LogicAny && len(l.Operands) > 0 {
		all := true
		for _, operand := range l.Operands {
			if !widens(operand, after) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return comparisonWidens(before, after)
}

// comparisonWidens handles the one arithmetic case worth proving: the same
// reference held to a looser numeric bound. Raising a monetary threshold is the
// most common narrowing there is, and lowering one is the most common widening,
// so leaving both to the conservative branch would charge every tightening a
// weakening revision's price.
func comparisonWidens(before, after policy.Node) bool {
	oldCmp, ok := before.(policy.Compare)
	if !ok {
		return false
	}
	newCmp, ok := after.(policy.Compare)
	if !ok {
		return false
	}
	if oldCmp.Op != newCmp.Op || !reflect.DeepEqual(oldCmp.Left, newCmp.Left) {
		return false
	}
	oldBound, ok := numericLiteral(oldCmp.Right)
	if !ok {
		return false
	}
	newBound, ok := numericLiteral(newCmp.Right)
	if !ok {
		return false
	}
	switch oldCmp.Op {
	case policy.OpGe, policy.OpGt:
		return newBound <= oldBound
	case policy.OpLe, policy.OpLt:
		return newBound >= oldBound
	default:
		return false
	}
}

func numericLiteral(o policy.Operand) (float64, bool) {
	lit, ok := o.(policy.Literal)
	if !ok {
		return 0, false
	}
	switch v := lit.Data.(type) {
	case int64:
		return float64(v), true
	case float64:
		return v, true
	default:
		return 0, false
	}
}

// ---------------------------------------------------------------------------
// the challenges
// ---------------------------------------------------------------------------

// challengeFindings reports challenges a policy stopped demanding, quorums it
// lowered, and approver sets it widened.
func challengeFindings(id string, before, after *policy.Policy) []Finding {
	var out []Finding

	beforeByKind := groupChallenges(before)
	afterByKind := groupChallenges(after)
	for _, kind := range policy.ChallengeTypes() {
		had, has := len(beforeByKind[kind]), len(afterByKind[kind])
		if has < had {
			out = append(out, Finding{
				Subject: id,
				Reason:  ReasonChallengeRemoved,
				Detail:  fmt.Sprintf("the policy demanded %d %s challenge(s) and now demands %d", had, kind, has),
			})
		}
	}

	// Quorums are paired in declaration order. Normalization sorts challenges by
	// kind stably, so two quorums keep the order they were written in and the
	// pairing is the one an author would draw.
	oldQuorums, newQuorums := quorumsOf(beforeByKind), quorumsOf(afterByKind)
	for i := range oldQuorums {
		if i >= len(newQuorums) {
			break
		}
		old, fresh := oldQuorums[i], newQuorums[i]
		if fresh.Threshold < old.Threshold {
			out = append(out, Finding{
				Subject: id,
				Reason:  ReasonQuorumReduced,
				Detail:  fmt.Sprintf("quorum %d went from %d approvals to %d", i, old.Threshold, fresh.Threshold),
			})
		}
		if detail, widened := approverSetWidened(old.Approvers, fresh.Approvers); widened {
			out = append(out, Finding{Subject: id, Reason: ReasonApproverSetWidened, Detail: detail})
		}
	}
	return out
}

func groupChallenges(p *policy.Policy) map[policy.ChallengeType][]policy.Challenge {
	out := map[policy.ChallengeType][]policy.Challenge{}
	for _, c := range p.Challenges {
		out[c.ChallengeType()] = append(out[c.ChallengeType()], c)
	}
	return out
}

func quorumsOf(byKind map[policy.ChallengeType][]policy.Challenge) []policy.Quorum {
	var out []policy.Quorum
	for _, c := range byKind[policy.ChallengeQuorum] {
		if q, ok := c.(policy.Quorum); ok {
			out = append(out, q)
		}
	}
	return out
}

// approverSetWidened reports an approver set that admits somebody it did not
// admit before.
//
// Two explicit lists are compared member by member. Anything else — a list that
// became a claim, a claim that changed name, a group source that moved — cannot
// be compared without resolving it, and an unresolvable comparison is treated as
// a widening. Guessing the other way would make "switch the set to a claim
// everybody holds" the cheapest possible revision.
func approverSetWidened(before, after policy.ApproverSet) (string, bool) {
	oldMode, newMode := approverMode(before), approverMode(after)
	if oldMode != newMode {
		return fmt.Sprintf("the approver set is resolved by %s where it used to be resolved by %s, "+
			"and the two cannot be compared without resolving them", newMode, oldMode), true
	}
	switch oldMode {
	case "members":
		var added []string
		for _, m := range after.Members {
			if !slices.Contains(before.Members, m) {
				added = append(added, m)
			}
		}
		if len(added) > 0 {
			sort.Strings(added)
			return "the approver set now admits " + strings.Join(added, ", "), true
		}
		return "", false
	case "claim":
		if before.Claim != after.Claim {
			return fmt.Sprintf("the approver set now admits holders of the %q claim rather than the %q claim",
				after.Claim, before.Claim), true
		}
		return "", false
	default:
		if !reflect.DeepEqual(before.Source, after.Source) {
			return "the approver set now resolves from a different group source", true
		}
		return "", false
	}
}

func approverMode(a policy.ApproverSet) string {
	switch {
	case a.Source != nil:
		return "source"
	case a.Claim != "":
		return "claim"
	default:
		return "members"
	}
}

// ---------------------------------------------------------------------------
// the requirement
// ---------------------------------------------------------------------------

// Floor is the operator's lower bound on any governance revision.
//
// It is deployment configuration and not policy data. A policy author is
// assumed to be outside the trust boundary (D21), so the bound that stops a
// quorum from voting itself away has to live somewhere the author cannot reach.
type Floor struct {
	// MinApprovers is the smallest quorum threshold a revision may be decided
	// under, whatever the governance policy says.
	MinApprovers int
	// ProposerMayApprove permits a proposer's own approval to count. The default
	// is false, which is the "proposer is not an approver" half of R33's floor.
	ProposerMayApprove bool
}

// DefaultFloor is the floor a deployment gets when it configures none: the
// governance policy's own threshold, and no self-approval.
func DefaultFloor() Floor { return Floor{MinApprovers: 1} }

// Requirement is what a revision has to satisfy before it takes effect.
//
// Approvers is the eligible set with the proposer already removed when the floor
// says so. Removing them rather than discounting their vote afterwards is what
// makes the rule enforceable by the quorum handler: a proposer who submits an
// approval is refused as a non-target, which lands in the audit log, instead of
// being silently counted as zero.
type Requirement struct {
	Threshold       int
	Approvers       policy.ApproverSet
	ExcludeProposer bool
	Weakening       bool
	Findings        []Finding
}

// Quorum renders the requirement as the challenge specification a governance
// decision is gated by. A zero threshold means no quorum at all, which is
// solo-admin mode before the lock.
func (r Requirement) Quorum() (policy.Quorum, bool) {
	if r.Threshold <= 0 {
		return policy.Quorum{}, false
	}
	return policy.Quorum{Threshold: r.Threshold, Approvers: r.Approvers}, true
}

// Require computes the approval requirement for a delta.
//
// current is the quorum the effective governance policy demands, and is nil
// before the lock. proposed is the quorum the delta would install, and is nil
// when the delta does not touch the governance policy.
//
// A weakening revision is judged by the stricter of the two: the higher
// threshold and the narrower approver set. That is what stops a revision from
// governing its own adoption — lowering a quorum from three to one would
// otherwise need one approval, which is the number the revision is trying to
// establish rather than the number currently in force.
//
// The floor applies to every revision and not only to a weakening one. R33
// names the floor in the weakening clause, and applying it more widely satisfies
// that clause strictly; the alternative would leave self-approval available on
// every revision an author could get classified as neutral, and "get it
// classified as neutral" is the whole attack the classifier defends against.
func Require(current, proposed *policy.Quorum, class Classification, floor Floor, proposer string) (Requirement, error) {
	req := Requirement{Weakening: class.Weakening(), Findings: class.Findings}
	if current == nil {
		// Before the lock there is no quorum to meet. The bootstrap token is the
		// control on this path, and it is checked by the governance service
		// rather than expressed as a challenge.
		return req, nil
	}

	req.Threshold = current.Threshold
	req.Approvers = current.Approvers
	if class.Weakening() && proposed != nil {
		req.Threshold = max(current.Threshold, proposed.Threshold)
		req.Approvers = stricterApproverSet(current.Approvers, proposed.Approvers)
	}
	if req.Threshold < floor.MinApprovers {
		req.Threshold = floor.MinApprovers
	}
	req.ExcludeProposer = !floor.ProposerMayApprove
	if req.ExcludeProposer {
		req.Approvers = withoutMember(req.Approvers, proposer)
	}

	if approverMode(req.Approvers) == "members" && len(req.Approvers.Members) < req.Threshold {
		return Requirement{}, fmt.Errorf(
			"%w: %d eligible approver(s) cannot meet a requirement of %d",
			ErrUnsatisfiable, len(req.Approvers.Members), req.Threshold)
	}
	if req.Threshold < 1 {
		return Requirement{}, fmt.Errorf("%w: a requirement of %d approvals is not a quorum",
			ErrFloorViolated, req.Threshold)
	}
	return req, nil
}

// stricterApproverSet is the narrower of two sets.
//
// Two explicit lists intersect. Anything else keeps the set currently in force,
// because a revision must not be able to hand itself a set it invented — and
// widening a set is itself weakening, so the set in force is the stricter choice
// by construction whenever the two cannot be compared.
func stricterApproverSet(current, proposed policy.ApproverSet) policy.ApproverSet {
	if approverMode(current) != "members" || approverMode(proposed) != "members" {
		return current
	}
	out := policy.ApproverSet{}
	for _, m := range current.Members {
		if slices.Contains(proposed.Members, m) {
			out.Members = append(out.Members, m)
		}
	}
	return out
}

func withoutMember(set policy.ApproverSet, member string) policy.ApproverSet {
	if approverMode(set) != "members" || member == "" {
		return set
	}
	out := policy.ApproverSet{}
	for _, m := range set.Members {
		if m != member {
			out.Members = append(out.Members, m)
		}
	}
	return out
}

// CheckSatisfiable reports whether every quorum the delta leaves behind can
// actually be met by the approver set it names (R34).
//
// The check is on the outcome rather than on the change, because the hazard is
// an unreachable quorum however it got there: a set shrunk below the threshold
// and a threshold raised above the set are the same lockout.
func CheckSatisfiable(d Delta) error {
	for _, c := range d.Changes {
		if c.After == nil {
			continue
		}
		for i, ch := range c.After.Challenges {
			q, ok := ch.(policy.Quorum)
			if !ok {
				continue
			}
			if q.Threshold < 1 {
				return fmt.Errorf("%w: policy %q challenge %d asks for %d approvals",
					ErrUnsatisfiable, c.PolicyID, i, q.Threshold)
			}
			if approverMode(q.Approvers) != "members" {
				// A claim or a group source resolves at issue time; the quorum
				// handler refuses a set too small to meet its own threshold
				// there, which is the only place the size is known.
				continue
			}
			distinct := distinctMembers(q.Approvers.Members)
			if len(distinct) < q.Threshold {
				return fmt.Errorf("%w: policy %q challenge %d asks %d distinct approver(s) for a quorum of %d",
					ErrUnsatisfiable, c.PolicyID, i, len(distinct), q.Threshold)
			}
		}
	}
	return nil
}

func distinctMembers(members []string) []string {
	out := make([]string, 0, len(members))
	for _, m := range members {
		if trimmed := strings.TrimSpace(m); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
