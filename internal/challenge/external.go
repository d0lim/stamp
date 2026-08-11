package challenge

// external.go implements R3's external challenge: a webhook round trip to a
// system the operator allows STAMP to talk to.
//
// # The round trip, and why it is two legs
//
// Issue posts a notification and the target answers 2xx to say it has the work.
// The verdict comes back later on the callback listener. The outbound call is
// therefore an acknowledgement, never an answer: a target that wanted to decide
// synchronously would have to hold Issue open while it thought, and Issue runs
// inside decide() on the request path. Splitting the trip keeps the hot path
// bounded by a timeout the operator sets, and keeps "the target said yes" and
// "the target received the question" from being the same 200.
//
// # The policy author names a list entry, not a destination
//
// D21 puts the policy author outside the trust boundary, so [policy.External]
// carries a name and the operator's configuration carries the URL, the secret
// and the timeouts. A document that writes a URL in the target field names a
// target that does not exist, which is an issue-time refusal rather than a
// request. The URL the operator did configure still goes through U6's gate at
// load and again at call time, and the gate's dialler re-checks the resolved
// address — a hostname is not a way to spell an address the operator did not
// permit, whoever wrote it down.
//
// # Fail closed, in one direction
//
// A round trip that did not happen leaves the challenge failed: an unreachable
// target, a timeout, a redirect, a non-2xx answer, a blocked destination, and a
// callback that never arrives all resolve the decision to deny. None of them
// leaves a challenge pending and none of them can produce an allow. The one
// distinction the code keeps is between a misconfiguration and an outage — an
// unknown target name or an unusable secret is an error the operator has to
// fix, while a target that failed to answer is a decision that got made.
//
// # The callback authenticates itself
//
// The listener takes no credential (see [api.SurfaceCallback]), so the proof a
// callback carries is a server-issued correlator plus an HMAC over the material
// under the target's shared secret. The signature travels in the body rather
// than in a header because the lifecycle hands a handler a payload and not a
// header set, and because it makes the signature part of the object that gets
// stored, retried and logged. The nonce is not itself a secret — knowing it
// buys nothing without the key — it is what binds one answer to one issuance,
// so a callback for a challenge that was re-issued cannot settle the new one.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/stream"
)

// Protocol constants of the external challenge. They are exported because they
// are the contract a target implements, not an internal detail.
const (
	// ExternalNotifyContext and ExternalCallbackContext are domain separators.
	// Each digest covers the string naming what it is for, so a signature
	// computed over an outbound notification cannot be presented as a
	// signature over a callback.
	ExternalNotifyContext   = "stamp.external-notify.v1"
	ExternalCallbackContext = "stamp.external-callback.v1"

	// ExternalSignatureHeader carries the outbound notification's signature,
	// written "v1=<hex>".
	ExternalSignatureHeader = "X-Stamp-Signature"

	// ExternalVerdictApproved and ExternalVerdictDenied are the two answers a
	// callback may carry. There is no third: a target that cannot decide
	// should not answer, and let the deadline do it.
	ExternalVerdictApproved = "approved"
	ExternalVerdictDenied   = "denied"
)

// Why a round trip did not complete, as recorded in [ExternalDetail.Failure].
//
// The vocabulary is closed and short on purpose. It is written into the audit
// trail from a call whose far end is not trusted, and a free-text reason there
// would be a remote system choosing what an operator reads.
const (
	ExternalFailureEgressBlocked = "egress_blocked"
	ExternalFailureTimeout       = "timeout"
	ExternalFailureTransport     = "transport"
	ExternalFailureRedirect      = "redirect"
	ExternalFailureStatus        = "status"

	// ExternalFailureRetargeted is a revision that pointed this challenge at a
	// different target. It is the one word in this vocabulary STAMP writes
	// about itself rather than about a remote, and it exists because the
	// alternative — re-issuing — would post a second webhook from inside the
	// revalidation transaction, while that transaction holds a row lock on
	// every open decision.
	ExternalFailureRetargeted = "retargeted"

	// ExternalFailureRateLimited is a notification that was not sent because the
	// subject was over the per-subject dispatch budget (R43).
	//
	// It is the second word STAMP writes about itself, and it is its own word
	// rather than a reuse of `transport` for the reason the whole vocabulary is
	// closed: an operator reading a denied decision has to be able to tell "the
	// target was unreachable" — which is an incident — from "we declined to call
	// it" — which is this deployment working as configured.
	ExternalFailureRateLimited = "rate_limited"
)

// Defaults for an operator who configures a target and leaves the timings
// alone.
const (
	// DefaultExternalTimeout bounds the outbound notification. It is short
	// because it runs on the decide path.
	DefaultExternalTimeout = 5 * time.Second

	// DefaultExternalResponseBytes caps what is read from a target's
	// acknowledgement, which carries no content this side reads.
	DefaultExternalResponseBytes int64 = 8 << 10

	// MinExternalSecretBytes is the shortest shared secret this build accepts.
	// The callback listener holds no credential, so this key is the whole of
	// what stands between an unauthenticated caller and an allow.
	MinExternalSecretBytes = 16

	// DefaultMaxTrackedSubjects bounds the dispatch-budget table, for the reason
	// [stream.Limiter] is bounded at all: its keys are subject identifiers, and
	// an unbounded table would let whoever can name subjects grow this process.
	DefaultMaxTrackedSubjects = 4096

	// externalNonceBytes is the correlator width.
	externalNonceBytes = 32
)

// DefaultExternalSubjectRate is how often one subject's decisions may cause an
// outbound notification in a deployment that configured no budget (R43).
//
// It is looser than the step-up budget because what it spends is a machine's
// attention rather than a person's, and tighter than the decide budget because
// every unit of it is a request this deployment makes to somebody else's system
// — a limit that fires here is STAMP declining to be the load in an incident on
// a target it does not operate.
//
// An operator who wants no limit says so with a negative rate.
var DefaultExternalSubjectRate = stream.RateLimit{PerSecond: 1, Burst: 10}

// ErrTargetUnknown reports a policy naming a target the operator did not
// configure. It wraps [ErrUnsupportedSpec]: to a caller it is a declaration
// this deployment cannot serve, and it is refused at issue rather than at
// collection time.
var ErrTargetUnknown = errors.New("challenge: no such external target in the operator's configuration")

// ExternalTarget is one operator-configured webhook destination.
type ExternalTarget struct {
	// Name is what a policy's target field selects.
	Name string
	// URL is the endpoint the notification is posted to. It must be admitted
	// by the egress gate, which is checked when the handler is built and again
	// on every call.
	URL string
	// Secret is the shared key both legs are signed under. Required, and at
	// least [MinExternalSecretBytes] long.
	Secret string
	// Timeout bounds the outbound notification. Zero selects
	// [DefaultExternalTimeout].
	Timeout time.Duration
	// RespondWithin is how long the callback may take. Zero gives the
	// challenge no timer of its own, so it ends when its decision expires —
	// the same arrangement a quorum has.
	RespondWithin time.Duration
}

// ExternalConfig configures an [External].
type ExternalConfig struct {
	// Gate is U6's egress gate. Required: there is no ungated mode.
	Gate *fact.Gate
	// Targets is the operator's destination list.
	Targets []ExternalTarget
	// CallbackBaseURL is the absolute base address of this deployment's
	// callback listener, told to the target so it knows where to answer. Empty
	// omits it, for a deployment whose targets are configured with the address
	// out of band.
	CallbackBaseURL string
	// MaxResponseBytes caps a target's acknowledgement body. Zero selects
	// [DefaultExternalResponseBytes].
	MaxResponseBytes int64
	// SubjectRate bounds how often one subject's decisions may cause an outbound
	// notification (R43). A zero field selects [DefaultExternalSubjectRate] for
	// that field; a negative rate removes the limit.
	SubjectRate stream.RateLimit
	// MaxTrackedSubjects overrides [DefaultMaxTrackedSubjects].
	MaxTrackedSubjects int
}

// External is the webhook round-trip handler.
type External struct {
	targets     map[string]ExternalTarget
	client      *http.Client
	gate        *fact.Gate
	callbackURL string
	maxBytes    int64

	// The per-subject dispatch budget. limitAt is the instant the charge in
	// progress is dated at: [stream.Limiter] takes its clock at construction and
	// the lifecycle supplies the issuing instant per request, so the two are
	// joined by writing it here immediately before Allow reads it. Every access
	// to either field — including the clock closure's, which only ever runs
	// inside Allow — happens under limitMu.
	limitMu     sync.Mutex
	limiter     *stream.Limiter
	subjectRate stream.RateLimit
	limitAt     time.Time
}

// External deliberately does not implement [Targeter]. Its counterparty is a
// machine that authenticates with a signature, not an identity STAMP can name,
// so it vouches for nobody's read access — which is the fail-closed answer.
var _ Handler = (*External)(nil)

// NewExternal builds the external handler and refuses a configuration it
// cannot serve safely.
//
// Every target's URL is put through the gate here, at load, so a deployment
// pointed at a metadata address or an origin nobody allowlisted fails to start
// rather than failing on the first decision that reaches it. Resolution is not
// forced: DNS is allowed to be down when a process starts, and the dialler
// checks the answer on every call anyway.
func NewExternal(cfg ExternalConfig) (*External, error) {
	if cfg.Gate == nil {
		return nil, errors.New("challenge: an external handler needs an egress gate")
	}
	x := &External{
		targets:     make(map[string]ExternalTarget, len(cfg.Targets)),
		client:      cfg.Gate.HTTPClient(),
		gate:        cfg.Gate,
		maxBytes:    cfg.MaxResponseBytes,
		subjectRate: cfg.SubjectRate,
	}
	if x.maxBytes <= 0 {
		x.maxBytes = DefaultExternalResponseBytes
	}
	// A zero field takes the default for that field, so an operator who raised
	// the burst does not have to restate the rate.
	if x.subjectRate.PerSecond == 0 {
		x.subjectRate.PerSecond = DefaultExternalSubjectRate.PerSecond
	}
	if x.subjectRate.Burst == 0 {
		x.subjectRate.Burst = DefaultExternalSubjectRate.Burst
	}
	tracked := cfg.MaxTrackedSubjects
	if tracked <= 0 {
		tracked = DefaultMaxTrackedSubjects
	}
	x.limiter = stream.NewLimiter(tracked, x.chargedAt)
	if cfg.CallbackBaseURL != "" {
		u, err := url.Parse(cfg.CallbackBaseURL)
		if err != nil || !u.IsAbs() || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("challenge: callback base %q must be an absolute http or https URL",
				cfg.CallbackBaseURL)
		}
		x.callbackURL = strings.TrimRight(cfg.CallbackBaseURL, "/")
	}

	for _, target := range cfg.Targets {
		name := strings.TrimSpace(target.Name)
		switch {
		case name == "":
			return nil, errors.New("challenge: an external target needs a name for a policy to select it by")
		case len(target.Secret) < MinExternalSecretBytes:
			return nil, fmt.Errorf("challenge: external target %q needs a shared secret of at least %d bytes",
				name, MinExternalSecretBytes)
		}
		if _, dup := x.targets[name]; dup {
			return nil, fmt.Errorf("challenge: external target %q is configured twice", name)
		}
		if err := cfg.Gate.CheckURL(target.URL); err != nil {
			return nil, fmt.Errorf("challenge: external target %q: %w", name, err)
		}
		target.Name = name
		if target.Timeout <= 0 {
			target.Timeout = DefaultExternalTimeout
		}
		x.targets[name] = target
	}
	return x, nil
}

// Kind implements [Handler].
func (x *External) Kind() policy.ChallengeType { return policy.ChallengeExternal }

// ExternalDetail is what an external challenge persists on its challenge row.
type ExternalDetail struct {
	// Target is the operator entry this challenge was opened against.
	Target string `json:"target"`
	// Nonce is the server-issued correlator a callback must echo.
	Nonce string `json:"nonce"`
	// RequestedAt is when the notification was attempted, and RespondBy the
	// instant after which no callback is accepted.
	RequestedAt time.Time  `json:"requested_at"`
	RespondBy   *time.Time `json:"respond_by,omitempty"`
	// Acknowledged records that the target took the work.
	Acknowledged bool `json:"acknowledged,omitempty"`
	// Failure is why the round trip could not start, from the closed
	// vocabulary above. It is the field Status reads to keep a failed issue
	// failed: the lifecycle stores every challenge pending and asks Status
	// afterwards, so a refusal that lived only in Issue's return value would
	// leave the challenge open.
	Failure string `json:"failure,omitempty"`
	// Verdict is the answer a callback delivered, and RespondedAt when.
	Verdict     string     `json:"verdict,omitempty"`
	RespondedAt *time.Time `json:"responded_at,omitempty"`
}

// ExternalNotification is the body posted to a target. It is the wire contract
// the target reads and signs against.
type ExternalNotification struct {
	// Context names what this document is, and is covered by the signature.
	Context string `json:"context"`
	// DecisionID and Ordinal name the challenge to answer for.
	DecisionID string `json:"decision_id"`
	Ordinal    int    `json:"challenge_ordinal"`
	// Nonce is the correlator the callback must echo.
	Nonce string `json:"nonce"`
	// Target is the operator entry name, so a target serving several
	// deployments can tell which configuration is in play.
	Target string `json:"target"`
	// The decision's identity, as frozen. There is deliberately no fact
	// snapshot here: the target is being asked to make its own judgement about
	// a named access, not handed STAMP's evidence for one.
	SubjectID  string `json:"subject_id"`
	ResourceID string `json:"resource_id"`
	Action     string `json:"action"`
	PolicyID   string `json:"policy_id"`
	// IssuedAt is when STAMP asked, and RespondBy the instant after which the
	// answer is no longer accepted.
	IssuedAt  time.Time  `json:"issued_at"`
	RespondBy *time.Time `json:"respond_by,omitempty"`
	// CallbackURL is where to answer, when the deployment publishes one.
	CallbackURL string `json:"callback_url,omitempty"`
}

// ExternalCallback is the body a target answers with.
type ExternalCallback struct {
	// Nonce is the correlator from the notification.
	Nonce string `json:"nonce"`
	// Verdict is [ExternalVerdictApproved] or [ExternalVerdictDenied].
	Verdict string `json:"verdict"`
	// Signature is the hex digest from [ExternalCallbackSignature].
	Signature string `json:"signature"`
}

// Issue posts the notification and opens the wait for a callback.
//
// A refused declaration comes back as an error and a refused round trip comes
// back as a failed challenge. The difference is who has to act: an unknown
// target is a policy or a deployment that has to change, while a target that
// did not answer is a decision this system just made, and burying that in a 500
// would turn a deny into an outage.
func (x *External) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	spec, ok := req.Spec.(policy.External)
	if !ok {
		return IssueResult{}, fmt.Errorf("%w: %T is not an external challenge", ErrUnsupportedSpec, req.Spec)
	}
	target, ok := x.targets[strings.TrimSpace(spec.Target)]
	if !ok {
		return IssueResult{}, fmt.Errorf("%w: %w: %q", ErrUnsupportedSpec, ErrTargetUnknown, spec.Target)
	}
	nonce, err := newExternalNonce()
	if err != nil {
		return IssueResult{}, err
	}

	now := req.Now.UTC()
	detail := ExternalDetail{Target: target.Name, Nonce: nonce, RequestedAt: now}
	var deadline *time.Time
	if target.RespondWithin > 0 {
		by := now.Add(target.RespondWithin)
		detail.RespondBy = &by
		deadline = &by
	}

	// The budget is charged before the call and not after it, which is the whole
	// point of standing here: a limit applied after the POST has not declined to
	// make the POST. The refusal takes the shape every other refused round trip
	// takes — a failed challenge, so the lifecycle denies the decision and audits
	// it — because there is no HTTP response of this handler's own to put a
	// status code on. Issue answers the decide path, not the target.
	if !x.allowNotify(req.Decision.SubjectID, req.Now) {
		detail.Failure = ExternalFailureRateLimited
		return IssueResult{State: StateFailed, Detail: detail}, nil
	}

	if err := x.notify(ctx, target, detail, req.Instance, req.Decision); err != nil {
		// The timer goes with the wait: a challenge that is already failed has
		// nothing to wake up for, and a deadline on it would have the sweeper
		// claim a decision that is finished.
		detail.Failure = externalFailure(err)
		return IssueResult{State: StateFailed, Detail: detail}, nil
	}
	detail.Acknowledged = true
	return IssueResult{State: StatePending, Detail: detail, Deadline: deadline}, nil
}

// chargedAt is the clock [stream.Limiter] reads. It is only ever called from
// inside Allow, which is only ever called by allowNotify with limitMu held.
func (x *External) chargedAt() time.Time { return x.limitAt }

// allowNotify charges one outbound notification against the subject's budget.
//
// The key follows the decide surface's convention — prefixed, so that adding a
// second namespace to this table later cannot silently collide with this one —
// and it is the subject identifier alone. Not the target: a subject's budget has
// to be one budget, or a caller with two targets to name would have two of them.
// Not the caller, because what is being bounded is how much of somebody else's
// system this deployment will consume on one subject's account, and N callers
// each holding a full budget is N times the flood arriving at the same webhook.
//
// A decision with no subject identifier is not charged. It cannot be keyed, and
// inventing a shared key for it would put every such decision in one bucket.
func (x *External) allowNotify(subjectID string, now time.Time) bool {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return true
	}
	x.limitMu.Lock()
	defer x.limitMu.Unlock()
	x.limitAt = now
	return x.limiter.Allow("subject\x1f"+subjectID, x.subjectRate, 1)
}

// notify performs the outbound leg.
//
// The allowlist is checked again here even though NewExternal already passed
// it, for U6's reason: a deployment's configuration outlives a process start
// and the cost of asking twice is a map lookup.
func (x *External) notify(ctx context.Context, target ExternalTarget, detail ExternalDetail,
	instance Instance, dec DecisionContext,
) error {
	if err := x.gate.CheckURL(target.URL); err != nil {
		return err
	}
	body, err := json.Marshal(ExternalNotification{
		Context:     ExternalNotifyContext,
		DecisionID:  instance.DecisionID,
		Ordinal:     instance.Ordinal,
		Nonce:       detail.Nonce,
		Target:      target.Name,
		SubjectID:   dec.SubjectID,
		ResourceID:  dec.ResourceID,
		Action:      dec.Action,
		PolicyID:    dec.PolicyID,
		IssuedAt:    detail.RequestedAt,
		RespondBy:   detail.RespondBy,
		CallbackURL: x.CallbackURLFor(instance),
	})
	if err != nil {
		return fmt.Errorf("challenge: encode external notification: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, target.Timeout)
	defer cancel()

	// The URL keeps the hostname the operator configured. The address pin
	// happens in the gate's dialler, which is what leaves the certificate to be
	// checked against that name rather than against whatever it resolved to.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	// Header is set, not added to: the request starts empty and stays that way
	// apart from these lines. There is no place a credential could enter, and
	// the deployment's identity is not spent on a policy author's behalf.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "stamp-challenge/1")
	req.Header.Set(ExternalSignatureHeader, "v1="+ExternalNotificationSignature(target.Secret, body))

	resp, err := x.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, x.maxBytes))

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// Redirects are never followed, so a 3xx is an answer rather than a
		// step. The destination it names would have to be on the allowlist to
		// be called, and letting the far end choose the next hop is exactly
		// what the allowlist exists to prevent.
		return &externalStatusError{code: resp.StatusCode, redirect: true}
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return &externalStatusError{code: resp.StatusCode}
	default:
		return nil
	}
}

// CallbackURLFor renders where a target should answer for one challenge, or
// empty when the deployment publishes no callback base.
func (x *External) CallbackURLFor(instance Instance) string {
	if x.callbackURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/external/%s/%d", x.callbackURL, instance.DecisionID, instance.Ordinal)
}

// Submit takes a callback and records its verdict.
//
// Everything is verified before anything is recorded, and the order is: is this
// challenge one we can verify against at all, is the body readable, does the
// correlator match, does the signature hold. A caller that fails any of them
// gets [ErrNotTarget] or [ErrInvalidPayload] and changes nothing.
//
// req.Submitter is deliberately not consulted. The callback listener takes no
// credential, so a credential presented there proves nothing about being this
// target — and a console user holding a perfectly good token is no closer to
// satisfying this challenge than a stranger is.
func (x *External) Submit(_ context.Context, req SubmitRequest) (SubmitResult, error) {
	detail, err := decodeExternalDetail(req.Detail)
	if err != nil {
		return SubmitResult{}, err
	}
	target, ok := x.targets[detail.Target]
	if !ok {
		// The target was configured when the challenge was opened and is not
		// now. There is no key to verify against, so there is no way to accept
		// this answer: the challenge waits out its deadline and fails.
		return SubmitResult{}, fmt.Errorf("%w: %w: %q", ErrUnsupportedSpec, ErrTargetUnknown, detail.Target)
	}
	body, err := decodeExternalCallback(req.Payload)
	if err != nil {
		return SubmitResult{}, err
	}

	if subtle.ConstantTimeCompare([]byte(body.Nonce), []byte(detail.Nonce)) != 1 {
		return SubmitResult{}, fmt.Errorf("%w: the callback for %s carries another correlator",
			ErrNotTarget, req.Instance)
	}
	want := ExternalCallbackSignature(
		target.Secret, req.Instance.DecisionID, req.Instance.Ordinal, detail.Nonce, body.Verdict)
	if !hmac.Equal([]byte(strings.ToLower(body.Signature)), []byte(want)) {
		return SubmitResult{}, fmt.Errorf("%w: the callback for %s is not signed by %q",
			ErrNotTarget, req.Instance, target.Name)
	}

	at := req.Now.UTC()
	detail.Verdict = body.Verdict
	detail.RespondedAt = &at
	return SubmitResult{State: externalState(body.Verdict), Detail: detail}, nil
}

// Status reports where a round trip stands as of req.Now.
//
// It recomputes from the detail rather than trusting the row, which is what
// makes a failed Issue stay failed: the lifecycle writes every challenge
// pending and asks this afterwards, so the recorded failure is the only place
// the refusal survives.
//
// An elapsed deadline here is a failure, which is the exact opposite of what
// the same elapsed deadline means to a delay. The two live in one file each and
// answer for themselves, which is why the contract has no callback that would
// have had to pick one.
func (x *External) Status(_ context.Context, req StatusRequest) (Status, error) {
	detail, err := decodeExternalDetail(req.Detail)
	if err != nil {
		return Status{}, err
	}
	deadline := detail.RespondBy
	if deadline == nil {
		deadline = req.Deadline
	}
	state := req.Stored
	if !state.Terminal() {
		switch {
		case detail.Failure != "":
			state = StateFailed
		case detail.Verdict != "":
			state = externalState(detail.Verdict)
		case deadline != nil && !req.Now.Before(*deadline):
			state = StateFailed
		default:
			state = StatePending
		}
	}
	// The one failure the decision layer has to be able to name. Every other
	// word in this handler's vocabulary — a blocked egress, a timeout, a
	// transport fault — is a round trip that was attempted and went wrong; this
	// one is a round trip this deployment declined to make, so the target was
	// never told and the decision's ground is load shedding rather than refusal.
	return Status{State: state, Deadline: deadline, Shed: detail.Failure == ExternalFailureRateLimited}, nil
}

// externalState maps a recorded verdict to a challenge state. Anything that is
// not an approval is a refusal, which is the fail-closed reading of a detail
// that somehow holds a verdict this build does not know.
func externalState(verdict string) State {
	if verdict == ExternalVerdictApproved {
		return StateSatisfied
	}
	return StateFailed
}

// ---------------------------------------------------------------------------
// signatures
// ---------------------------------------------------------------------------

// ExternalNotificationSignature is the digest an outbound notification carries
// in [ExternalSignatureHeader], hex-encoded.
//
// It covers the domain separator and the exact bytes on the wire, so a target
// verifies what it received rather than what it parsed.
func ExternalNotificationSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(ExternalNotifyContext))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// ExternalCallbackSignature is the digest a callback must carry, hex-encoded.
//
// It covers the fields rather than the serialized body, so a target is free to
// send whitespace and member order however it likes and STAMP does not have to
// canonicalize somebody else's JSON to check a signature. Each field is
// terminated rather than joined, so no two different field sets produce the
// same input — "ab" and "" cannot be confused with "a" and "b".
//
// The decision identifier and the ordinal are in the material, which is what
// stops a valid callback for one challenge from being replayed at another; the
// verdict is in it, which is what stops a denial from being flipped in transit.
func ExternalCallbackSignature(secret, decisionID string, ordinal int, nonce, verdict string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	for _, part := range []string{
		ExternalCallbackContext, decisionID, strconv.Itoa(ordinal), nonce, verdict,
	} {
		_, _ = mac.Write([]byte(part))
		_, _ = mac.Write([]byte{'\n'})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func newExternalNonce() (string, error) {
	var b [externalNonceBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("challenge: generate external correlator: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ---------------------------------------------------------------------------
// failure classification
// ---------------------------------------------------------------------------

// externalStatusError is a target that answered something other than success.
type externalStatusError struct {
	code     int
	redirect bool
}

func (e *externalStatusError) Error() string {
	if e.redirect {
		return "remote answered " + strconv.Itoa(e.code) + " and redirects are not followed"
	}
	return "remote answered " + strconv.Itoa(e.code)
}

// externalFailure reduces a failed round trip to one word from the closed
// vocabulary.
//
// The egress refusal is tested first for U6's reason: a block happens inside
// the dialler and comes back wrapped by the HTTP client, so checking anything
// else first would file an SSRF attempt as a generic transport failure and hide
// it in the audit trail among the outages.
func externalFailure(err error) string {
	var status *externalStatusError
	switch {
	case errors.Is(err, fact.ErrBlocked):
		return ExternalFailureEgressBlocked
	case errors.As(err, &status):
		if status.redirect {
			return ExternalFailureRedirect
		}
		return ExternalFailureStatus
	case errors.Is(err, context.DeadlineExceeded):
		return ExternalFailureTimeout
	default:
		return ExternalFailureTransport
	}
}

// ---------------------------------------------------------------------------
// decoding
// ---------------------------------------------------------------------------

// DecodeExternalDetail reads a stored external detail.
//
// It is exported for the revision effect hook, which has to know which target a
// round trip is already out to. That question has to be answerable without
// calling [External.Issue] again: Issue performs a network POST, and the
// revision path runs inside a transaction holding a row lock on every open
// decision.
func DecodeExternalDetail(raw json.RawMessage) (ExternalDetail, error) {
	return decodeExternalDetail(raw)
}

func decodeExternalDetail(raw json.RawMessage) (ExternalDetail, error) {
	var detail ExternalDetail
	if err := json.Unmarshal(raw, &detail); err != nil {
		return ExternalDetail{}, fmt.Errorf("%w: external detail: %w", ErrInvalidPayload, err)
	}
	if detail.Target == "" || detail.Nonce == "" {
		return ExternalDetail{}, fmt.Errorf(
			"%w: external detail names no target or carries no correlator", ErrInvalidPayload)
	}
	return detail, nil
}

// decodeExternalCallback reads a callback body.
//
// The structural checks are separated from the cryptographic ones on purpose: a
// body this build cannot read is [ErrInvalidPayload] and a body it read but
// could not verify is [ErrNotTarget]. Unknown members are refused, because the
// member a caller is most likely to invent is one that looks like it changes
// the outcome.
func decodeExternalCallback(raw json.RawMessage) (ExternalCallback, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return ExternalCallback{}, fmt.Errorf("%w: the callback carries no body", ErrInvalidPayload)
	}
	var body ExternalCallback
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return ExternalCallback{}, fmt.Errorf("%w: external callback: %w", ErrInvalidPayload, err)
	}
	switch {
	case body.Nonce == "":
		return ExternalCallback{}, fmt.Errorf("%w: the callback carries no correlator", ErrInvalidPayload)
	case body.Verdict != ExternalVerdictApproved && body.Verdict != ExternalVerdictDenied:
		return ExternalCallback{}, fmt.Errorf("%w: verdict %q is neither %q nor %q",
			ErrInvalidPayload, body.Verdict, ExternalVerdictApproved, ExternalVerdictDenied)
	case body.Signature == "":
		return ExternalCallback{}, fmt.Errorf("%w: the callback is unsigned", ErrInvalidPayload)
	}
	if _, err := hex.DecodeString(body.Signature); err != nil {
		return ExternalCallback{}, fmt.Errorf("%w: signature is not a hex digest: %w", ErrInvalidPayload, err)
	}
	return body, nil
}
