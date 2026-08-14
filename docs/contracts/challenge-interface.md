---
contract: challenge-interface
version: 1.4.0
source: internal/challenge
---

# challenge interface contract

How the part of a decision that policy evaluation alone cannot answer is handled — a quorum to be gathered, a step-up to be completed, a delay to run out, an external system to answer. One of the three public contracts, versioned with semver (R11). The source of truth is `internal/challenge/contract.go`, and that file's `ContractVersion` constant has to equal this document's `version` — the release workflow compares them.

The decision lifecycle owns **when** a challenge is opened and **what** its outcome does to the decision; this contract owns only the **shape** of the conversation between the two.

## Version rules

Carried over verbatim from the source of truth.

| Change | Level |
|---|---|
| Adding a method to `Handler`, changing a method signature, changing what a `State` value means | major |
| Adding a field to a request or result struct, adding an optional interface such as `Targeter` | minor |

## There are three verbs

```go
type Handler interface {
    Kind() policy.ChallengeType
    Issue(ctx context.Context, req IssueRequest) (IssueResult, error)
    Submit(ctx context.Context, req SubmitRequest) (SubmitResult, error)
    Status(ctx context.Context, req StatusRequest) (Status, error)
}
```

There is no fourth verb. In particular **there is no verb for "the deadline has passed, now what"** — when the sweeper asks `Status` with the current instant, a delay answers satisfied and a quorum answers pending. A passed deadline means the opposite thing for one kind than for the other, so a separate callback would necessarily be wrong about one of them.

There are three optional interfaces. All three exist so that a fourth verb does not have to, and a handler that implements none of them does not fail assembly.

```go
type Targeter interface {
    IsTarget(ctx context.Context, req TargetRequest) (bool, error)
}
```

A handler that does not implement it is treated as having no target — read standing is fail-closed (R40).

```go
type Viewer interface {
    View(ctx context.Context, req ViewRequest) (View, error)
}
```

**Added in 1.1.0** (adding an optional interface = minor). It answers with the part of an in-progress challenge **that the caller may be told**. The one field `View` currently has is `AuthorizationURL` — where a challenge that completes in a browser sends the subject. A handler that does not implement it discloses nothing, which is the answer quorum, delay and external all want.

```go
type Redeemer interface {
    Redeem(ctx context.Context, req RedeemRequest) (Redemption, error)
}
```

**Added in 1.2.0** (adding an optional interface = minor). When the redirect it sent comes back, it turns that into the material for a submission. A `Redemption` is not a submission but **the body that will travel alongside a credential that has not been verified yet** — turning a credential into a subject is the `identity` package's job, so that a second token verification path is not created inside a challenge handler. The round trip is therefore three steps: the lifecycle routes to the challenge (`Redeem`), the surface verifies the credential, and `Submit` runs as the caller that credential proved.

A handler that does not implement it has no redirect to bring back — that is `ErrNotRedeemable`, and no default is invented. Every refusal is the single `ErrRedemptionRefused`: whoever arrived has only followed a link and is not authenticated yet, so the difference between "the state was wrong" and "the code was already spent" is something an operator needs and a stranger does not.

**This is a whitelist rather than a projection of `Detail`.** `Detail` is for storage and holds secrets such as the correlator and the nonce. The decision lifecycle does not know any particular kind, so it cannot tell a URL from a secret inside `Detail` — which is why only **the fields the handler picked by name** are passed along. A new field means somebody has answered the question "may this value leave the deployment".

## States

`pending`, `satisfied`, `failed`, `cancelled`. The last three are terminal.

### `Status.Shed`: a failure that got no answer, and a failure that never opened

**Added in 1.3.0** (adding a field to a result struct = minor). `failed` covers two things with one word: a challenge that was asked and came back no, and a challenge that **was never opened at all**. The second is the case the per-subject challenge issuance limit shed (R43) — nothing reached the IdP or the target system, and the person received nothing.

`Shed` carries that distinction as **one bit**. It is a bit rather than the handler's failure word (`issue_rate_limited`, `rate_limited`) because the decision lifecycle must not know any kind's vocabulary — a decision layer that knows two such strings has to be edited every time a kind is added.

It rides on `Status` because a decision's ground is **recomputed on every read**. The lifecycle stores the challenge and then asks `Status`, and re-evaluation (R31) may write a shed issuance onto a decision that already exists — a bit that exists only in the issue return value is one nobody reads afterwards.

When `State` is not `failed` this value means nothing. A handler that does not implement it answers `false`, and that is the answer a kind with no shedding limit wants.

### `IssueResult.Shed` and `IssueResult.RetryAfter`: the bit that arrives too late

**Added in 1.4.0** (adding a field to a result struct = minor). The same bit, carried at issue time as well. 1.3.0 put it on `Status` alone — the paragraph above records why — and **the cost of that choice fell on people.** A bit that arrives only through `Status` arrives **after** the lifecycle has already written the challenge row, so a shed issuance became a `failed` row and the decision resolved that row into a final deny. And so "denied" accumulated on the history of a person nobody had asked anything.

Read at issue time, decide can back out **before it writes a row**. That is the answer the decision API contract describes in its 1.7.0 — a deny with no `id`, no stored row, and a `Retry-After`.

`RetryAfter` is the material for that `Retry-After`. Which budget refused is known only to the handler, and converting it to seconds and writing the header is the surface's job. It is a duration rather than a rate because what the surface has to write is one number of seconds, and a rate is one step of arithmetic away from it.

**Setting both is the implementer's duty.** A handler that raises `Shed` at issue has to raise it in `Status` for the same challenge as well. A row written by re-evaluation recomputes its ground on every read, and if the bit is absent then, that decision ends up wearing the same word as one a person refused.

## A handler stores its own detail, not the declaration

`Issue` takes the policy's declaration and returns a `Detail`, which the lifecycle stores on the challenge row and hands back unchanged to `Submit` and `Status`. A threshold or an approver set that will be needed later is something the handler puts into `Detail`. That way the conditions a challenge was opened under are frozen together with the fact snapshot and the policy version, and this package has no reason to serialize a policy AST.

## `Submit` has to be recomputable

The evidence row a handler writes and the challenge state the lifecycle writes are **two statements and not one.** So `Submit` has to be idempotent (a duplicate submission counts once), and `Status` has to be able to recompute progress from what the handler stored alone — because a crash between the two leaves the evidence written and the state not yet updated.

## Types

| Type | Fields |
|---|---|
| `Instance` | `DecisionID`, `Ordinal`, `Kind` |
| `DecisionContext` | The frozen content of the decision |
| `IssueRequest` | `Instance`, `Spec`, `Decision`, `Now` |
| `IssueResult` | `State`, `Detail`, `Deadline`, `Shed`, `RetryAfter` |
| `SubmitRequest` | `Instance`, `Decision`, `Detail`, `Submitter`, `Payload`, `Now` |
| `SubmitResult` | `State`, `Have`, `Need`, `Detail` |
| `StatusRequest` | `Instance`, `Decision`, `Detail`, `Stored`, `Deadline`, `Now` |
| `Status` | `State`, `Have`, `Need`, `Deadline`, `Detail`, `Shed` |
| `ViewRequest` | `Instance`, `Decision`, `Detail`, `Now` |
| `View` | `AuthorizationURL` |

## Errors

`ErrNoHandler`, `ErrDuplicateHandler`, `ErrNotSubmittable`, `ErrNotTarget`, `ErrInvalidPayload`, `ErrUnsupportedSpec`. Callers branch with `errors.Is`. **A kind with no handler cannot be satisfied** — absence is not read as permission.

The registry returns an error when two handlers are registered for one kind, and there is no deregistration.

## Detail by kind

`Detail` is stored and handed back unchanged, so its JSON representation is part of the contract.

| Kind | detail fields | Submission |
|---|---|---|
| `quorum` | `threshold`, `mode`, `issuer`, `members`, `claim`, `source`, `binding_hash` | `{verdict, binding_hash}` |
| `delay` | `duration`, `release_at`, `cancellable_by`, `cancelled_by`, `cancelled_at` | `{action}` |
| `external` | `target`, `nonce`, `requested_at`, `respond_by`, `acknowledged`, `failure`, `verdict`, `responded_at` | `{nonce, verdict, signature}` |
| `mfa` | `mfa.Detail` (`internal/challenge/mfa`) | `mfa.Submission` |

`mode` is how the approver set was resolved: `members`, `claim`, `source`.

An external challenge's outbound body is an `ExternalNotification`, and the inbound callback's signature arrives in the `X-Stamp-Signature` header. The target URL comes from the operator's allowlist rather than from a policy.

MFA implements delegated mode alone in v1 (D16). `direct` is defined in the contract only, and is refused at load with `ErrUnsupportedSpec` — an unimplemented thing is not left silent.
