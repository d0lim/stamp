// Package mfa implements R3's multi-factor challenge in its delegated mode:
// STAMP does not authenticate anybody, it asks an external IdP to and then
// judges what came back.
//
// # Why the judgement is the whole unit
//
// U0 stood a real IdP up and found that an `acr` request which the IdP cannot
// satisfy is not an error — it is a silent downgrade. `acr_values=2` against an
// unconfigured realm returned `acr=1`; the OIDC essential-claim form
// (`claims={"id_token":{"acr":{"essential":true,...}}}`) returned `acr=1` too;
// and once a mapping existed, a value absent from it returned the strongest
// mapped class rather than a refusal. Nothing in the protocol tells a relying
// party that its request was ignored.
//
// So [Delegated.Submit] verifying the returned `acr` against the operator
// allowlist is not a convenience check that a careful deployment could skip. It
// is the only thing standing between a password-only login and a satisfied
// step-up challenge, and a handler configured without an allowlist refuses to
// exist rather than run without it.
//
// # What binds a completion to a decision
//
// A server-issued correlator, matched exactly and consumed once. The
// `binding_message` an IdP shows the human does not bind anything (D16): it is
// display text, and U0 found it capped at 50 characters, space-free and
// plaintext-only, so a decision context cannot be serialized into it at all.
// What travels in it is [ReferenceCode] — a short code derived from the
// correlator — and the human-readable amount and payee come from a decision
// lookup on the approval screen.
//
// # What is required and what is merely matched
//
// Required: correlator, issuer, client, audience, an `acr` in the operator
// allowlist that also satisfies the policy's requirement, an `auth_time` after
// the challenge was issued, and a decision context that still hashes to what it
// hashed to at issue.
//
// Matched only when present: `amr`, and `nonce`. U0 found `amr` empty in
// default IdP configurations — the mapper is not in a default client scope, and
// even attached it returned `[]` after a password login — so requiring it would
// make this challenge structurally unsatisfiable. `nonce` is defence in depth
// for the flows that carry one; an IdP that omits it costs nothing, because it
// is the correlator that binds.
//
// # Two transports, one judgement
//
// CIBA and RFC 9470 step-up differ only in how the human is reached, so they
// are two [Initiator] implementations in front of one completion path. D26
// makes step-up the demo's default: CIBA needs a decoupled authentication
// server no self-hostable IdP ships, so the CIBA client here is verified
// against a mock OP rather than against the demo bundle.
//
// # Direct mode
//
// [policy.MFADirect] is defined by the contract and not implemented (D16).
// Policy validation already refuses it at load; this package refuses it again
// at issue, because a mode that is rejected in only one of the two places is a
// mode that arrives through the other one.
package mfa

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/policy"
)

// Errors this handler adds to the contract's sentinels.
//
// They are distinct rather than one "not satisfied" because every one of them
// is a different operational story: a mismatched correlator is somebody
// replaying, a downgraded `acr` is an IdP that is not configured the way the
// operator believes, and a changed context hash is a revision that landed
// mid-flight.
var (
	// ErrDirectModeUnimplemented reports a direct-mode declaration. It wraps
	// [challenge.ErrUnsupportedSpec]: v1 defines the mode in the contract and
	// implements only the delegated one (D16).
	ErrDirectModeUnimplemented = errors.New("mfa: the direct mode is defined by the contract but not implemented in v1")

	// ErrCorrelatorMismatch reports a completion whose correlator is not the
	// one this challenge was issued under — a token minted for another
	// decision, or a guess.
	ErrCorrelatorMismatch = errors.New("mfa: the completion does not carry this challenge's correlator")

	// ErrCorrelatorConsumed reports a second completion against a correlator
	// that has already been spent. R38 requires exactly one consumption.
	ErrCorrelatorConsumed = errors.New("mfa: this challenge's correlator has already been consumed")

	// ErrCredentialMismatch reports a completion token from the wrong issuer,
	// the wrong client, or for the wrong audience.
	ErrCredentialMismatch = errors.New("mfa: the completion token was not issued by the expected party")

	// ErrACRNotAllowed reports an authentication context class outside the
	// operator's allowlist. This is the check U0 proved load-bearing: without
	// it a silently downgraded authentication satisfies the challenge.
	ErrACRNotAllowed = errors.New("mfa: the authentication context class is not in the operator allowlist")

	// ErrACRUnsatisfied reports a class that the operator permits but that does
	// not meet what the policy asked for.
	ErrACRUnsatisfied = errors.New("mfa: the authentication context class does not satisfy the policy requirement")

	// ErrAMRMismatch reports a token that carries `amr` values, none of which
	// is one the deployment requires. A token carrying no `amr` at all is not
	// this error: U0 found that to be the IdP default.
	ErrAMRMismatch = errors.New("mfa: the authentication methods do not include a required one")

	// ErrStaleAuthentication reports an `auth_time` at or before the instant
	// the challenge was issued — a session that predates the question, or a
	// token with no `auth_time` at all.
	ErrStaleAuthentication = errors.New("mfa: the authentication predates this challenge")

	// ErrNonceMismatch reports a token whose `nonce` is not the one derived
	// from this challenge's correlator.
	ErrNonceMismatch = errors.New("mfa: the completion token carries another challenge's nonce")

	// ErrContextChanged reports a decision whose content no longer hashes to
	// what it hashed to at issue.
	ErrContextChanged = errors.New("mfa: the decision changed since the challenge was issued")

	// ErrInitiationUnsupported reports an initiator that cannot serve a
	// request — the CIBA client against an IdP with no decoupled
	// authentication server behind it (D26). It is what a fallback chain
	// branches on.
	ErrInitiationUnsupported = errors.New("mfa: this initiator cannot start that authentication")

	// ErrBindingMessage reports a reference code an IdP would refuse. U0 got
	// `invalid_binding_message` for anything over 50 characters, containing a
	// space, or outside basic plaintext.
	ErrBindingMessage = errors.New("mfa: the binding message is not one an idp will accept")
)

// Method names how the human was reached.
type Method string

// The delegation methods.
const (
	// MethodStepUp is an RFC 9470 authorization request carrying `acr_values`.
	// D26 makes it the demo's default path.
	MethodStepUp Method = "step_up"
	// MethodCIBA is an OIDC CIBA backchannel authentication request.
	MethodCIBA Method = "ciba"
)

// Valid reports whether m is one of the declared methods.
func (m Method) Valid() bool { return m == MethodStepUp || m == MethodCIBA }

// Domain separators. Every derived value states what it is derived for, so a
// digest computed for one purpose cannot be presented as a digest computed for
// another.
const (
	// ContextBindingContext separates the decision-context hash.
	ContextBindingContext = "stamp.mfa-context.v1"
	// ReferenceCodeContext separates the reference code shown to the human.
	ReferenceCodeContext = "stamp.mfa-reference.v1"
	// NonceContext separates the nonce sent with an authorization request.
	NonceContext = "stamp.mfa-nonce.v1"
)

// MaxBindingMessageLength is the cap U0 measured on a real IdP. It is a
// property of the IdP rather than of STAMP, which is why it is stated here
// rather than negotiated: a request over it is refused with
// `invalid_binding_message` before any human sees anything.
const MaxBindingMessageLength = 50

// ReferenceCodePrefix labels the code a human reads back over the phone.
const ReferenceCodePrefix = "STAMP-"

// Detail is what a delegated MFA challenge persists on its challenge row.
//
// It is the terms the challenge was opened under, frozen: who must complete it,
// which classes count, what the decision hashed to, and — once spent — that the
// correlator is spent. The handler gets it back verbatim at Submit and Status,
// so consumption is recorded in the same write that moves the challenge to
// satisfied rather than in a second statement that a crash could separate from
// it.
type Detail struct {
	// Mode is the declared MFA mode. Always [policy.MFADelegated] in v1.
	Mode policy.MFAMode `json:"mode"`
	// Method is how the human was reached.
	Method Method `json:"method"`
	// Correlator is the server-issued value a completion must carry exactly
	// once (R38).
	Correlator string `json:"correlator"`
	// Reference is the display code carried in `binding_message`. It is
	// derived from the correlator and binds nothing (D16).
	Reference string `json:"reference"`
	// Nonce is the value sent with the authorization request, matched against
	// the token's `nonce` when the token carries one.
	Nonce string `json:"nonce"`
	// SubjectID is the decision's subject: the person whose authentication is
	// being asked for, and the only one whose completion counts.
	SubjectID string `json:"subject_id"`
	// RequiredACRValues is the policy's requirement, empty when the policy
	// named none and the operator allowlist is the whole requirement.
	RequiredACRValues []string `json:"required_acr_values,omitempty"`
	// AllowedACRValues is the operator allowlist as it stood at issue. It is
	// recorded for the audit trail; the check at submit runs against the
	// deployment's current allowlist, so tightening it takes effect on
	// challenges that are already open.
	AllowedACRValues []string `json:"allowed_acr_values,omitempty"`
	// Issuer, ClientID and Audience are the party a completion token must come
	// from, frozen from operator configuration at issue.
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
	Audience string `json:"audience"`
	// IssuedAt is the instant the challenge opened, and the lower bound an
	// `auth_time` has to beat.
	IssuedAt time.Time `json:"issued_at"`
	// ContextHash is the decision content at issue, hex-encoded.
	ContextHash string `json:"context_hash"`
	// AuthorizationURL is the step-up redirect the subject is sent to.
	AuthorizationURL string `json:"authorization_url,omitempty"`
	// AuthReqID is the CIBA backchannel request identifier.
	AuthReqID string `json:"auth_req_id,omitempty"`
	// State is the value the step-up's `state` parameter carries, and the value
	// the callback has to echo.
	//
	// It is not the correlator (KTD2). The callback path already names the
	// decision and the ordinal, so `state` has one job — proving the redirect
	// was caused by the request this deployment made — and putting the
	// correlator in it would put a binding secret in an address bar, a referrer
	// header and a browser history entry to do a job a fresh random value does
	// as well.
	State string `json:"state,omitempty"`
	// CodeVerifier is the PKCE secret the authorization request committed to
	// and the token call spends (KTD3). It lives here because it has to survive
	// the browser round trip, and the challenge row is the thing that already
	// does — see the package doc on where the correlator and nonce live.
	CodeVerifier string `json:"code_verifier,omitempty"`
	// ConsumedAt and ConsumedBy record the one completion that spent the
	// correlator.
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
	ConsumedBy string     `json:"consumed_by,omitempty"`
}

// Consumed reports whether the correlator has been spent.
func (d Detail) Consumed() bool { return d.ConsumedAt != nil }

// Submission is the body of an MFA completion.
//
// It carries the correlator and nothing else. The authentication itself arrives
// as the verified [identity.Subject] on [challenge.SubmitRequest], because the
// one place a credential is turned into a caller in this system is the identity
// package — a second token-verification path in a challenge handler is a second
// place the trust boundary could be got wrong.
type Submission struct {
	// Correlator is the value the challenge was issued under.
	Correlator string `json:"correlator"`
}

// InitiateRequest asks an [Initiator] to start an authentication.
type InitiateRequest struct {
	// Instance names the challenge being opened.
	Instance challenge.Instance
	// Decision is the decision's frozen content, for a login hint and for
	// whatever an initiator needs to address the right human.
	Decision challenge.DecisionContext
	// SubjectID is who must authenticate.
	SubjectID string
	// Correlator is the server-issued binding value. An initiator carries it
	// as `state` on a step-up and never as `binding_message`, which cannot
	// hold it.
	Correlator string
	// Reference is the display code for `binding_message`.
	Reference string
	// Nonce is the value to send with the request.
	Nonce string
	// ACRValues is what to ask the IdP for. U0 proved the IdP may ignore it
	// silently, which is why the response is checked rather than the request
	// trusted.
	ACRValues []string
	// RedirectURI is where a completion should land, empty when the deployment
	// uses one fixed callback for every challenge. It is supplied rather than
	// derived because the route pattern belongs to the API layer: a challenge
	// handler that built the path would be a second copy of it.
	RedirectURI string
	// Now is the issuing instant.
	Now time.Time
}

// InitiateResult is what starting an authentication produced.
//
// The last two fields are a step-up's, and a CIBA request leaves them empty:
// they are the halves of the round trip a redirect has and a backchannel push
// does not. They are returned rather than generated by the handler so that the
// transport owns its own protocol artifacts — the handler stores what it is
// given and never has to know what `state` is for.
type InitiateResult struct {
	// Method is which transport was used.
	Method Method
	// AuthorizationURL is where a step-up sends the subject.
	AuthorizationURL string
	// AuthReqID is what a CIBA request returned.
	AuthReqID string
	// State is the CSRF value the authorization request carries and the
	// callback must echo (KTD2).
	State string
	// CodeVerifier is the PKCE secret the token call will spend (KTD3).
	CodeVerifier string
}

// RedeemRequest asks a transport to turn its own callback into a credential.
type RedeemRequest struct {
	// Instance names the challenge the callback arrived for.
	Instance challenge.Instance
	// Params is the callback's query as received.
	Params map[string]string
	// ExpectedState is the value this challenge minted, for the transport to
	// compare the echoed one against.
	ExpectedState string
	// CodeVerifier is the PKCE secret frozen at issue.
	CodeVerifier string
	// RedirectURI is the callback target the authorization request named. The
	// token call has to repeat it byte for byte.
	RedirectURI string
}

// Redeemer turns a transport's own callback into the credential a completion
// carries.
//
// Only the redirect transport implements it: there is nothing to redeem in a
// CIBA push, whose token comes from polling with an `auth_req_id` the handler
// already holds. [Delegated] asks its initiator for this and answers
// [challenge.ErrNotRedeemable] when the initiator cannot.
type Redeemer interface {
	Redeem(ctx context.Context, req RedeemRequest) (string, error)
}

// Initiator starts one delegated authentication.
//
// It is the seam between the two transports. Everything downstream of it —
// correlator matching, `acr` verification, one-time consumption — is identical
// for both, which is the point: D26 changed which transport the demo uses and
// changed nothing about what satisfies a challenge.
type Initiator interface {
	Initiate(ctx context.Context, req InitiateRequest) (InitiateResult, error)
}

// ContextHash computes the digest a completion is checked against.
//
// The inputs are the decision's frozen identity and content: who is asking, for
// what, under which policy, with which facts and obligations. Two things are
// excluded on purpose and for the same reason [challenge.ApprovalBindingHash]
// excludes them — the timestamps are still moving while sibling challenges are
// being issued, and the ordinal is not a term of the authorization.
//
// Every JSON member is re-serialized from its decoded form before hashing. The
// same content arrives as different bytes on either side of the database, and a
// hash over the bytes would differ between issue and submit.
func ContextHash(dec challenge.DecisionContext) ([32]byte, error) {
	request, err := decodeJSON(dec.Request)
	if err != nil {
		return [32]byte{}, fmt.Errorf("mfa: context hash: request: %w", err)
	}
	facts, err := decodeJSON(dec.FactSnapshot)
	if err != nil {
		return [32]byte{}, fmt.Errorf("mfa: context hash: fact snapshot: %w", err)
	}
	obligations, err := decodeJSON(dec.Obligations)
	if err != nil {
		return [32]byte{}, fmt.Errorf("mfa: context hash: obligations: %w", err)
	}
	material := map[string]any{
		"binding": ContextBindingContext,
		"decision": map[string]any{
			"id":          dec.DecisionID,
			"caller_id":   dec.CallerID,
			"subject_id":  dec.SubjectID,
			"resource_id": dec.ResourceID,
			"action":      dec.Action,
			"policy_id":   dec.PolicyID,
		},
		"request":       request,
		"fact_snapshot": facts,
		"obligations":   obligations,
		"challenge":     map[string]any{"kind": string(policy.ChallengeMFA)},
	}
	raw, err := json.Marshal(material)
	if err != nil {
		return [32]byte{}, fmt.Errorf("mfa: context hash: %w", err)
	}
	return sha256.Sum256(raw), nil
}

// PreservesCompletion reports whether an MFA challenge issued under stored
// detail still binds to dec.
//
// It exists for the revision path. An MFA challenge must not be re-issued when
// the decision content is unchanged — re-issuing rotates the correlator and
// strands whatever step-up the subject has open in another tab, the same way
// re-issuing a delay would restart its timer. When the content has changed the
// answer is false and the challenge has to be opened again, because the
// authentication that is in flight was requested for material nobody is being
// asked about any more.
//
// It is fail-closed in every direction: an unreadable detail, a detail with no
// hash, and a context that will not hash all answer false.
func PreservesCompletion(stored json.RawMessage, dec challenge.DecisionContext) (bool, error) {
	detail, err := DecodeDetail(stored)
	if err != nil {
		return false, err
	}
	if detail.ContextHash == "" {
		return false, nil
	}
	sum, err := ContextHash(dec)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(hex.EncodeToString(sum[:]), detail.ContextHash), nil
}

// PreservesRequirement reports whether a challenge issued under stored detail
// still asks for the classes spec declares.
//
// It is the half of the revision question [PreservesCompletion] cannot see. A
// revision that changes only `acr_values` leaves the decision's content — and
// therefore its context hash — exactly as it was, so the hash says "unchanged"
// about a challenge that is now enforcing a requirement nobody declared, or
// failing to enforce one somebody just did.
//
// The comparison runs over the normalized lists so that reordering a
// declaration, or writing a class twice, is not a change: the frozen side was
// normalized at issue by the same function.
//
// It is fail-closed like its sibling: an unreadable detail answers false.
func PreservesRequirement(stored json.RawMessage, spec policy.MFA) (bool, error) {
	detail, err := DecodeDetail(stored)
	if err != nil {
		return false, err
	}
	return slices.Equal(detail.RequiredACRValues, normalizeACR(spec.ACRValues)), nil
}

// ReferenceCode derives the display code carried in `binding_message`.
//
// It is short, uppercase, space-free and made only of characters U0 saw an IdP
// accept, because the alternative — serializing the decision context — is
// refused outright with `invalid_binding_message`. It is derived from the
// correlator rather than being the correlator so that the value read aloud over
// a phone is not the value that satisfies the challenge.
func ReferenceCode(correlator string) string {
	sum := sha256.Sum256([]byte(ReferenceCodeContext + "\x00" + correlator))
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return ReferenceCodePrefix + code[:10]
}

// NonceFor derives the `nonce` sent with an authorization request from the
// correlator, so that a token minted for one challenge cannot be presented for
// another even by somebody who learned the correlator.
func NonceFor(correlator string) string {
	sum := sha256.Sum256([]byte(NonceContext + "\x00" + correlator))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ValidateBindingMessage refuses a value an IdP would refuse.
//
// The rules are U0's observation, not a guess: at most 50 characters, no
// spaces, basic plaintext only. Checking here rather than reading the IdP's
// error means a deployment that customizes the reference code learns at issue
// instead of at the moment a human is waiting for a prompt.
func ValidateBindingMessage(msg string) error {
	switch {
	case msg == "":
		return fmt.Errorf("%w: it is empty", ErrBindingMessage)
	case len([]rune(msg)) > MaxBindingMessageLength:
		return fmt.Errorf("%w: %d characters exceeds the %d character limit",
			ErrBindingMessage, len([]rune(msg)), MaxBindingMessageLength)
	}
	for _, r := range msg {
		switch {
		case unicode.IsSpace(r):
			return fmt.Errorf("%w: %q contains whitespace", ErrBindingMessage, msg)
		case r > unicode.MaxASCII || !isPlainBindingRune(r):
			return fmt.Errorf("%w: %q contains %q, which is outside basic plaintext",
				ErrBindingMessage, msg, r)
		}
	}
	return nil
}

func isPlainBindingRune(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '-', r == '_', r == '.', r == ':':
		return true
	default:
		return false
	}
}

// DecodeDetail reads a stored MFA detail.
func DecodeDetail(raw json.RawMessage) (Detail, error) {
	var detail Detail
	if err := json.Unmarshal(raw, &detail); err != nil {
		return Detail{}, fmt.Errorf("%w: mfa detail: %w", challenge.ErrInvalidPayload, err)
	}
	if detail.Correlator == "" {
		return Detail{}, fmt.Errorf("%w: mfa detail carries no correlator", challenge.ErrInvalidPayload)
	}
	if !detail.Method.Valid() {
		return Detail{}, fmt.Errorf("%w: mfa detail names delegation method %q",
			challenge.ErrInvalidPayload, detail.Method)
	}
	return detail, nil
}

// decodeSubmission reads a completion body.
//
// Unknown members are refused rather than ignored, for the reason the quorum
// handler refuses an approver field: a client that believes it can name the
// authenticated subject should find that out, not have the claim silently
// dropped.
func decodeSubmission(raw json.RawMessage) (Submission, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return Submission{}, fmt.Errorf("%w: an mfa completion must carry a correlator",
			challenge.ErrInvalidPayload)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var body Submission
	if err := dec.Decode(&body); err != nil {
		return Submission{}, fmt.Errorf("%w: mfa completion: %w", challenge.ErrInvalidPayload, err)
	}
	if strings.TrimSpace(body.Correlator) == "" {
		return Submission{}, fmt.Errorf("%w: an mfa completion must carry a correlator",
			challenge.ErrInvalidPayload)
	}
	return body, nil
}

// NormalizeACRValues trims, drops blanks and deduplicates a class list while
// keeping declaration order: an author's preference order is information, so it
// is not sorted away.
//
// It is exported because two things outside this package have to agree with the
// handler about when two `acr` requirements are the same one: the revision
// effect hook, which decides whether a step-up has to be re-opened, and the
// weakening classifier, which decides what a revised requirement costs to adopt.
// Three implementations of "the same classes" would be two too many, and the one
// that drifted would be a bypass rather than a bug.
func NormalizeACRValues(values []string) []string { return normalizeACR(values) }

// normalizeACR trims, drops blanks and deduplicates a class list while keeping
// declaration order.
func normalizeACR(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed != "" && !slices.Contains(out, trimmed) {
			out = append(out, trimmed)
		}
	}
	return out
}

func decodeJSON(raw json.RawMessage) (any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
