---
contract: decision-api
version: 1.8.1
source: internal/api
---

# Decision API contract

The surface the engine exposes over HTTP. One of the three public contracts, versioned with semver (R11). The source of truth is the route declarations in `internal/api`, and the subset the console calls is exported separately in machine-readable form from `internal/api/contract.go` — the console has no endpoint outside this contract, and CI checks that (D19).

The `v1` in the paths is this contract's major.

## Version rules

| Change | Level |
|---|---|
| Removing an endpoint; changing a path, a method or an authentication requirement; removing a response field or changing its meaning; making a request field required | major |
| Adding an endpoint, adding an optional request field, adding a response field | minor |
| A correction that does not change meaning | patch |

## Three surfaces, and they are listeners rather than path prefixes

| Surface | Default address | Auth accepted | Callers |
|---|---|---|---|
| PEP | `:8080` | workload | workloads holding client credentials |
| console | `:8081` | user, static | operators and approvers holding end-user tokens |
| callback | unbound | workload, public | external systems completing a challenge |

A route mounted on one surface is not reachable through another. The other listener's router has never heard of it — a 404, not a 403. This is the form R39 takes, which asks that the callback-receiving surface be exposed separately from the PEP and console surfaces.

The same holds for a process with a role switched off. An endpoint belonging to a role that is not active answers 404 on that process.

Every surface answers `GET /healthz` and `GET /readyz` without authentication, and both responses carry an `X-Stamp-Surface` header naming which listener answered.

`GET /healthz` is **a liveness signal and not a readiness one** — it queries neither the database nor the audit buffer, and is always 200.

`GET /readyz` is the readiness signal. If a request sent to this process can actually be served it answers 200 `ready`; otherwise 503 and one line of plain text stating why. In 1.6.0 it answers on a single condition, the schema: whether the migration version applied to the database has reached the version this binary requires. Only the `api` tier applies migrations, and `helm upgrade` rolls every Deployment at once, so there is a window in which a decide pod on the new image is looking at the old schema. In that window this pod has to be out of its Service — otherwise every decision read becomes `42703 column ... does not exist` — and that is the whole of what this endpoint does. A dirty schema, or a database it cannot reach, is a 503 as well.

Neither path is in this document's endpoint table. The listener answers them itself, independently of any role, so there is no role for the table's fourth column to name.

## Endpoints

| Method and path | Surface | Auth | Roles |
|---|---|---|---|
| `POST /access/v1/evaluation` | PEP | workload | `check` |
| `POST /decisions` | PEP | workload | `decide` |
| `GET /decisions/{id}` | PEP | workload | `decide` |
| `POST /decisions/{id}/challenges/{ordinal}/approvals` | console | user | `decide` |
| `GET /decisions/{id}/challenges/{ordinal}/approval` | console | user | `decide` |
| `POST /decisions/{id}/challenges/{ordinal}/cancellation` | console | user | `decide` |
| `GET /decisions/inbox` | console | user | `decide` |
| `GET /audit/decisions` | console | user | `decide` |
| `GET /audit/decisions/{id}` | console | user | `decide` |
| `POST /decisions/{id}/challenges/{ordinal}/mfa` | callback | public | `decide` |
| `GET /decisions/{id}/challenges/{ordinal}/mfa` | callback | public | `decide` |
| `POST /external/{id}/{ordinal}` | callback | public | `decide` |
| `POST /ingest/v1/events` | callback | workload | `consumer` |
| `GET /policies` | console | user | `api` |
| `GET /policies/schema` | console | user | `api` |
| `POST /policies/apply` | console | user | `api` |
| `GET /policies/export` | console | user | `api` |
| `POST /policies/revisions` | console | user | `api` |
| `POST /policies/revisions/preview` | console | user | `api` |
| `GET /policies/revisions/{id}` | console | user | `api` |
| `POST /policies/revisions/{id}/withdrawal` | console | user | `api` |
| `POST /console/v1/policies/dry-run` | console | user | `api` |
| `GET /governance` | console | user | `api` |
| `POST /governance/lock` | console | user | `api` |
| `GET /console/config.json` | console | static | `console` |
| `/console/` (subtree) | console | static | `console` |
| `/console` (redirect into the subtree) | console | static | `console` |

**`internal/release` compares this table against the real mount table.** A route that is mounted with no row here, a row no component mounts, or a difference in surface, auth or roles turns CI red ([#44](https://github.com/d0lim/stamp/issues/44)). It is what comparing version strings structurally could not catch. **1.3.1 records the first thing that comparison caught** — the subtree redirect `/console` was missing from the table, and the subtree routes were written as though they carried `GET`. Not one endpoint changed; only the document was corrected (a correction that does not change meaning = patch). The unauthenticated `GET /healthz` and `GET /readyz` are not in this table — the listener answers them itself, independently of any role, so there is no role for the fourth column to name.

**The console's two static routes carry no method.** net/http answers 405 to a pattern whose path matches and whose method does not, so declaring the subtree as `GET /console/` would make a console-only tier answer 405 to `POST /console/v1/policies/dry-run` — the one tier that does not serve that endpoint saying "it is here". The method decision moved inside the handler, and comes back as a 404.

`public` on the callback endpoints means there is no authentication, not that there is no control. An external callback is bound by a signature (`X-Stamp-Signature`) and a server-issued nonce, and the MFA callback by a server-initiated correlator — those are the binding's source of truth rather than values carried for display (D16).

## AuthZEN check

`POST /access/v1/evaluation` is an AuthZEN Access Evaluation (D4).

```json
{"subject": {"type": "user", "id": "alice", "properties": {}},
 "resource": {"type": "account", "id": "acct-1"},
 "action": {"name": "transfer"},
 "context": {"amount": 25000}}
```

```json
{"decision": false,
 "context": {"stamp.reason": "...", "stamp.policy_id": "...",
             "stamp.policy_version": "...", "stamp.obligations": []}}
```

The four namespaced keys are always present. `stamp.obligations` is **always empty on the check path** — obligations arrive with a decision, and the key itself stays so that absent and empty do not become indistinguishable.

**A failed evaluation is a deny, not a 500.** The request body is bounded at 1MiB, and when the audit buffer saturates while fail-closed the surface denies before it reads the body.

**`subject.id` and `resource.id` may not exceed 255 bytes** (1.6.0). Over that it is `400 invalid_request`, and **no evaluation happens** — unlike the body bound, this is a bound on a single value. The reason it is needed is on the decide side: a subject identifier is a **key** in the per-subject rate limit table, and a map key holds on to its own bytes, so without a bound the table's limit of 8192 entries bounds only the **number** of entries while the caller picks their size. The same value goes verbatim into the refusal's audit event. The judgment is still the same on check and on decide — the two endpoints taking the same body (KTD1) means there must be no identifier one of them accepts and the other does not. 255 is the bound `Idempotency-Key` already carries, and the identifiers that exist in practice — account numbers, uuids, `sub` claims — come nowhere near it.

An error response is `{"error": "...", "message": "..."}` — the code vocabulary is described under "The `error` code vocabulary" below.

## Headers

| Header | Meaning |
|---|---|
| `X-Stamp-Surface` | Which listener answered `/healthz` or `/readyz` |
| `X-Stamp-Bootstrap-Token` | Where a pre-lock governance request carries the one-time bootstrap token |
| `X-Stamp-Signature` | The signature on an external challenge callback |
| `X-Stamp-Component` | The marker on a response the console served |
| `Retry-After` | Attached only to a response refused by a rate limit. The value is that budget's **refill interval**, in seconds |
| `Idempotency-Key` | An **optional** request header `POST /decisions` accepts. It is the name of that decide attempt, and since 1.7.0 that name is bound to the request it names (1.5.0, [#47](https://github.com/d0lim/stamp/issues/47)) |

**`Retry-After` is attached to a rate-limit refusal and not to a policy deny.** A policy deny is a judgment, and a judgment does not expire on a timer — retry it and the answer is the same forever. This header is what separates the two denies at the transport level, so attaching it to both is worse than attaching it to neither.

The value is the time until **one token is back**, not until **the bucket is full**. What a refused caller needs is the moment it may send once more; the burst above that is headroom it has already spent. Rounded up to whole seconds (floor 1 second, ceiling 3600).

On `decide` this header is attached to a **`200`** response. That is knowingly not where RFC 9110 puts it (429, 503, 3xx) — as "The `reason` on a deny" below says, a rate-limit refusal there is a **decision object**, and that is not being changed. Refusals of an approval submission and of a delay cancellation are `429`, and there the header sits exactly where the specification puts it.

**And in that position the header is effectively advisory. This paragraph is here so that fact is not hidden.** Client implementations that retry automatically almost without exception **branch on the status code first** — Go's `http.Client`, Python's urllib3 `Retry`, Java's `HttpClient` and the axios retry family all read the header only after seeing a `429` or a `5xx`. A shed refusal on decide is a `200`, so it **never reaches the layer that would read that header.** For the value to be honoured, the client has to read `state: denied` and `reason` and wait on its own — and that is code it could write with no header at all.

So what is gained. **Observability.** A mesh sidecar, a log pipeline and a metrics exporter read the header table without parsing the body, so shed requests can now be counted apart from judged ones — that is what [#45](https://github.com/d0lim/stamp/issues/45) actually delivered, not "the PEP sees this header and backs off". On the `429` of an approval submission and of a delay cancellation, by contrast, **it works exactly as specified, and clients do honour it.** Describe both positions in one sentence and one of them becomes an overstatement.

## decide

`POST /decisions` creates a decision. The request body is **the same shape as check's** (an AuthZEN Access Evaluation request) plus one optional field, `ttl` (a duration string, bounded by `DefaultMaxDecisionTTL` = 24h) — a PEP has to be able to call both with the same input. **The response is not AuthZEN.** It is a `decision.Result`, and it carries the four things R2 requires: the state, the challenges required and how far collection has got (`have`/`need`), the expiry, and the obligations.

The status code follows **the outcome rather than the validity of the request**:

| Outcome | Status | Body |
|---|---|---|
| A decision was created (pending or allow) | `201` + `Location: /decisions/{id}` | carries `id` |
| deny | `200` | no `id` — a deny creates no decision row |

So **a client cannot tell from the status code alone whether there is an `id`.** Both cases have to be read out of `state` and `id`.

`GET /decisions/{id}` is open **to the creating caller alone** (R40). The read for a targeted approver is `GET /audit/decisions/{id}` on the console surface — one route cannot serve both a workload credential and an end-user token. **A read without standing and a decision that does not exist are indistinguishable down to the response bytes**: whether a decision exists must not leak. Since 1.4.0 the same holds on the four console-side surfaces — see "The `error` code vocabulary" below.

### `Idempotency-Key`: how a retry is kept from creating a second decision

`POST /decisions` accepts the optional request header `Idempotency-Key`. The value is an opaque token the caller mints, and it is **the name of that attempt**. The name, though, **is bound to the request it names** (1.7.0) — when the server creates the decision it freezes a fingerprint of that request alongside it, and compares the fingerprint when the same key arrives again.

| Rule | What it says |
|---|---|
| Scope | **(caller, key)**. Another workload using the same key gets a different decision — a key is the name a caller gave its own attempt rather than a coordinate in a shared namespace, and a decision identifier is a value R40 governs reads of |
| Shape | 1–255 bytes, printable ASCII with no spaces. Outside that it is `400 invalid_request`, and **no evaluation happens** |
| When absent | **Exactly as it was before this header.** Two decides with no key are two decisions |
| Same key + **same request** | Answers the decision first created, **in the state it is in at that moment**. No new row, no new challenge, no new IdP call |
| Same key + **different request** | `409 idempotency_key_reused` (1.7.0). The first decision **does not come back**, and no identifier is carried. Use a new key |
| What the fingerprint covers | `action`, `subject`, `resource`, `context` — that is, the whole of the request that went into the evaluation. It does **not** cover the fact snapshot: facts are refreshed by the engine itself, so putting them in the fingerprint would turn an honest retry into a 409 every time a velocity counter ticks up |
| Response | A repeat of the same request is the same `201` + `Location` as the first. A retry that got a different status code would have to be branched on, and then "after a timeout, just send it again" stops being true |

**Why the comparison is needed.** Through 1.6.0 this document only said "the server does not compare the key against the request body", and it did not write down the cost. The cost was this: a caller that reused `job-91` for **a different subject, resource or action** got the first decision back — `201`, `state: allowed` and all — and the PEP permitted a transfer this engine had never judged. A `decision.Result` carries no subject, resource or action, so **the PEP did not even have a field to detect the substitution with.** With a key minted per attempt this is a bug inside one client; the moment keys are drawn from a value the business already numbers — an order number, a job id — it becomes a path reachable by anyone who can make two different requests carry one name.

**The fingerprint is computed from the evaluated input, not from the raw bytes.** A property the schema does not declare cannot move it (the surface rejects such a request first), and three requests sending `25000`, `25000.0` and `2.5e4` for a declared `int` attribute have one fingerprint. Values the policy reads identically mean the same request, and a fingerprint that judged differently from the evaluator would be the worse failure of the two.

**The lookup comes before the evaluation.** decide mints the decision identifier and writes the row **after it has issued every challenge** — the IdP push and the webhook dispatch happen before the database does. So a key held only by a unique index at insert time would ring the subject's phone once more on every retry and refuse afterwards. The unique index (`decisions_unique_idempotency_key`, migration 9 — the column, the fingerprint and the constraint are migration 8, and only the index is split out so it can be built `CONCURRENTLY`) is **a backstop for concurrent requests** and nothing more: when both found nothing in the lookup, one insert succeeds, and the loser reads the winner's decision and returns it — **only when the winner's fingerprint matches.** If the fingerprints differ, that race is not two retries racing but a substitution that arrived through the window the lookup cannot see, and the answer is the same `409`.

**A deny creates no row, so a request carrying a key is evaluated again.** That is safe because a deny leaves nothing behind — no outstanding slot, no open challenge, no notification that reached a person. What this header prevents is an orphaned **decision**, and a deny does not create a decision.

**The rate budget is charged for a retry too.** Whether a request is a retry is knowable only after the budget has been charged, and a request that can be sent for free is a request that can be sent forever.

### The challenge view

Each entry in `challenges[]` is one challenge's progress.

| Field | Meaning | When it appears |
|---|---|---|
| `ordinal` | The challenge's number within the decision | Always |
| `kind` | `quorum` · `mfa` · `delay` · `external` | Always |
| `state` | `pending` · `satisfied` · `failed` · `cancelled` | Always |
| `have` · `need` | How far collection has got | Always |
| `deadline` | That challenge's timer | When it has a timer |
| `authorization_url` | **Where to send the subject's browser** | Only on kinds that complete in a browser |

**`authorization_url` was added in 1.2.0** (adding a response field = minor). Delegated MFA completes through a step-up redirect (D26), and that address lived only on the challenge row and appeared in no response, so a caller had no way to know where to send the subject ([#41](https://github.com/d0lim/stamp/issues/41)). quorum, delay and external do not carry this field, and serialize **byte for byte** as they did before.

**The view carries only what the challenge handler picked by name.** The challenge row's `detail` is for storage, and holds the correlator, the nonce and the PKCE verifier — none of which go to the view, and there is no channel through which they could. The decision layer does not know any particular challenge kind (it asks only through the optional `challenge.Viewer` interface), so it cannot reach into a stored value and carry it itself.

**1.2.0's "known exposure" is closed.** Back then the step-up authorization request carried the correlator as `state`, and putting the URL in the response put the correlator in reach of the caller and the browser. In 1.3.0 `state` is a CSRF token minted per challenge (KTD2) — the correlator appears in no URL, and neither does the PKCE verifier. What identifies a challenge is the callback **path**.

### The step-up callback

`GET /decisions/{id}/challenges/{ordinal}/mfa` is where the IdP sends the subject's browser back. The existing `POST` stays as it was — the CIBA path and the mock OP verification use it.

| Query parameter | Meaning |
|---|---|
| `code` | The authorization code. STAMP redeems it with the verifier on the challenge row |
| `state` | The CSRF token this challenge issued. A mismatch is refused **before** the token exchange |
| `error` · `error_description` | Present when the IdP refused |

**The response is HTML a person reads.** What arrives on this route is somebody who has just entered a password, and a JSON 403 like the other callbacks' would leave them with no idea what went wrong. The page carries no script, no style and no external reference, and is served with a `default-src 'none'` CSP and `Referrer-Policy: no-referrer` — the authorization code is in the URL's query, so suppressing the referrer is a defence rather than a formality.

The status codes fall into two ranges.

| Range | Answer |
|---|---|
| Every failure **before** `state` is verified — no such decision, no such challenge, a wrong `state`, a code that does not redeem, a challenge already closed | **One `403`, one page.** A status code must not reveal whether a decision identifier exists (the same reason `POST /external` answers a uniform 403) |
| A failure **after** the exchange succeeded — a weak `acr`, a stale `auth_time`, a mismatched `nonce`, a correlator already consumed | A page that says what can be done about it. Whoever is at this point holds the `state` and is the subject, not a stranger |
| A failure on STAMP's side | `500`, and "nothing was recorded" |

**An unsatisfied `acr` is refused on this path too.** As S1 confirmed, an IdP answers an `acr` request it cannot satisfy with a silent downgrade rather than an error, so verifying the `acr` on the redeemed `id_token` is the only line of defence there is. The judgment happens in the challenge handler and nowhere else, and the callback surface judges nothing.

**PKCE is not optional.** The authorization request carries `code_challenge` and `code_challenge_method=S256`. On a client that registers a challenge method — the demo realm's `stamp-stepup` does — Keycloak reads it as a **requirement** and refuses a request without it with `error=invalid_request` (measured in U2). The verifier lives on the challenge row (KTD3) and leaves in no response.

### The `reason` on a deny

`state: denied` may be a final judgment or a momentary shed. **The only thing that separates them is `reason`.**

| `reason` | Meaning | Retry | `Retry-After` |
|---|---|---|---|
| A value the policy produced (`policy_matched`, and so on) | A policy judgment | No | None |
| `outstanding_cap` | The subject is over their outstanding-decision cap (R43) | Once the outstanding ones clear | None — the condition is another decision closing, not a length of time to wait |
| `rate_limited` | Over the per-caller or per-subject rate limit (R43) | Yes — once the window passes | Present (1.4.0, [#45](https://github.com/d0lim/stamp/issues/45)) |
| `challenge_failed` | A challenge was asked and not satisfied — refused, or timed out | No | None |
| `challenge_rate_limited` | The challenge that was needed **was never even opened**: the challenge issuance limit shed it (R43, [#40](https://github.com/d0lim/stamp/issues/40)) | Yes — once the window passes | **Present on decide** (1.7.0) |

**`challenge_failed` and `challenge_rate_limited` have to be separate words.** The first is a person answering no; the second is nothing having reached a person at all — no IdP push, no webhook. While they were one word an operator could not tell "the subject refused" from "we never asked", and those two call for opposite responses. Which challenge kind shed is not something `reason` says — the decision layer does not know the vocabulary of kinds (KTD1), and that word is on the challenge row.

**On decide, a shed issuance creates no decision** (1.7.0). Through 1.6.0 it did: the shed challenge was stored as `failed`, the lifecycle resolved that into a final deny, and so **"denied" accumulated a line at a time on the history of a person nobody had asked anything.** Holding somebody else's issuance budget empty was enough to have every legitimate authorization of theirs refused, with the record left in their name. The answer now has the same shape as the one the surface gives when it sheds on its own budget — a deny with no `id`, no row, nothing on the subject's history, and a `Retry-After`. The refusal itself is still audited as R43 requires, but as a record that a limit engaged rather than as a judgment about a person.

**So a `challenge_rate_limited` may or may not carry an `id`.** The one decide produces does not (above). The one that does comes from the **re-evaluation** path (R31): when a decision that already exists reopens a challenge after a policy revision and that issuance is shed, the decision already has a row, and that row is resolved on this ground. What a client branches on is never `reason` but always the presence of `id` — the same rule as "a client cannot tell from the status code alone whether there is an `id`".

**`challenge_rate_limited` is not `rate_limited`.** The two values are refusals from different budgets. `rate_limited` is the decide surface's own per-caller and per-subject budget; this one is the issuance budget a challenge handler spends towards an IdP or a webhook. They are different settings for an operator to reach for (`STAMP_DECIDE_*` against `STAMP_CHALLENGE_ISSUE_*`), and raising one leaves the other where it was.

**The rate limits are per instance.** N replicas have an effective limit of N times what is configured. The absolute bound is the outstanding-decision cap, which is counted in the database and binds across the whole cluster.

## The `error` code vocabulary

An error response is `{"error": "...", "message": "..."}`, where **`error` is a code a machine reads and `message` is a sentence a person reads**. A client branches on `error` and never on `message` — the sentences are reworded without notice.

**`error` and `reason` are different vocabularies.** `reason` says, **when a decision exists**, on what ground that decision was reached — the engine speaking. `error` is what the surface says **when no decision was reached**. Share a string between them and "there is no answer" and "this is the ground the answer was reached on" become one event to a client.

**The same server state gets the same code on every surface.** That is what 1.4.0 fixed.

| `error` | Status | Meaning |
|---|---|---|
| `unauthenticated` | `401` | The credential this endpoint requires is not there |
| `invalid_request` | `400` | The body, the path or the query is not the shape this endpoint takes |
| `invalid_property` · `invalid_submission` · `unsupported_verdict` | `400` | A value is not the shape the schema or the challenge accepts |
| `not_found` | `404` | **You cannot have that decision.** It does not exist, or you have no standing, or you are not its target — three states, one answer |
| `not_an_auditor` | `403` | No standing to read decision **history**. It says nothing about any particular decision (R22) |
| `expired` · `not_collecting` · `material_changed` | `409` | The decision's or the challenge's current state does not take that operation |
| `idempotency_key_reused` | `409` | This `Idempotency-Key` has already been used **for a different request**. The request is not wrong — the name is already taken, so what to fix is the key rather than the body (1.7.0) |
| `rate_limited` | `429` | An approval submission went over the per-approver budget, or a delay cancellation over the per-authority one (R43, 1.8.0). A rate refusal on decide is a deny rather than an error |
| `not_installed` | `503` | This deployment has no policy set, schema or governance installed yet |
| `unsupported_challenge` | `501` | The policy requires a challenge kind this build cannot handle |
| `internal_error` | `500` | A failure on the server's side. The cause is not described; it is in the audit chain |

**`not_found` is broad on purpose.** R40 restricts reading a decision to the creating caller or a targeted approver, and if refusal and absence answered differently, one identifier would be enough to ask "does that decision exist". So the response is identical down to the bytes not only on the decide surface (`GET /decisions/{id}`) but on **approval submission, the approval view read, delay cancellation and the audit detail read.** Through 1.3.1 those four console-side places answered `403 not_an_approver` and `403 not_readable` ([#38](https://github.com/d0lim/stamp/issues/38)).

**The cost is real.** Somebody who lost standing because a revision changed the approver set also gets "no such decision". The place that tells that person the truth is **the inbox** (`GET /decisions/inbox`) — a list holding only what is waiting for them leaks nothing by what it leaves out.

**The indistinguishability holds across the decision's states as well** (1.6.0). To a caller with no standing, **a decision that does not exist, one still pending, one already decided and one expired are one response rather than four.** Through 1.5.0 they were not. The table was right and the order was wrong — approval submission and delay cancellation asked "is this still collecting" before "does this person have standing", and the standing signal came only from the challenge handler after it. So somebody who was not a target, polling one identifier, read `404` while it was pending and `409` the moment it was decided or expired: an oracle leaking the decision's existence and **the moment it closed**, and a free one, because the delay-cancellation path had no rate limit (1.8.0 added that budget — fixing the order widened the range of the audit appends a caller with no standing can reach). The approval view read, too, judged expiry before it judged targeting.

**`idempotency_key_reused` is not an exception to that collapsing; it is a different kind of answer.** The `404` collapsing above is a rule that makes one answer out of "can you have that **decision**", and this `409` says nothing about a decision — the lookup is scoped to **the caller's own keys**, so what the caller learns is only "this key of mine is already taken". Nothing leaks about anybody else's key, about any decision identifier, or beyond what resending the request the key names would already tell them. So it is not an oracle, and the response carries neither a decision identifier nor a `Location`.

**The 409s were not collapsed. They go to callers with standing.** `expired` and `not_collecting` are the only signal by which an approver a decision is waiting on can tell "you are late" from "there is nothing here". Collapsing them into 404 to shut out a stranger would cut into the human experience this endpoint exists for, and the stranger now gets one answer regardless. So what changed is not the answer but **the order**: standing is judged first, state second. The MFA callback surface stays outside this collapsing — a completion by somebody who is not the target is still `403 not_the_subject`, and only the place that judges it moved from the handler to the lifecycle.

**The MFA callback's 403 is excluded from this collapsing.** That surface answers `acr_not_allowed`, `acr_unsatisfied`, `amr_mismatch`, `stale_authentication`, `correlator_mismatch`, `credential_mismatch` and `nonce_mismatch` as separate codes. The reader there is an **operator** rather than an attacker, and somebody who cannot tell an IdP misconfiguration from a policy requirement cannot find the cause of a step-up nobody is able to complete. Whether the decision exists is already hidden ahead of those codes by the one uniform `403` (see "The step-up callback" above).

### What 1.4.0 changed, and its level

- `Retry-After` is attached to a rate-limit refusal — **adding a response field = minor.**
- A missing policy set on decide answers `not_installed` instead of `policy_set_stale`.
- On the console's four surfaces, "no standing" becomes identical to "does not exist" down to the response bytes.

The last two **change what is visible on the wire.** There is one ground for not raising the major: **this document never promised either of them.** The `error` vocabulary was undocumented through 1.3.1 (a fact that was written down under "What this contract does not say yet"), and the console surfaces' status codes were in no table. The indistinguishability rule, by contrast, **had been written in this document since 1.1.0** and the code was not keeping it. So this is not a change that breaks the contract but one that brings the code to it.

Even so, **a client that hard-coded `403 not_an_approver` or `policy_set_stale` off the wire breaks.** This paragraph is here so that fact is not hidden.

### What 1.5.0 changed, and its level

- `POST /decisions` accepts the optional request header `Idempotency-Key` — **adding an optional request field = minor.** A client that does not send it gets the same answer as before, byte for byte.
- A deny produced by a shed challenge issuance carries `challenge_rate_limited` instead of `challenge_failed`.

The second **changes a value visible on the wire.** The ground for not raising the major is 1.4.0's: this document's `reason` table never promised that value, and on the contrary **the rule that "the only thing that separates a `state: denied` is `reason`" had been written since 1.1.0** while a shed issuance was carrying the same word as a final judgment and breaking it. Not a change that breaks the contract but one that brings the code to it. Even so, **a client that hard-coded `challenge_failed` as "the subject refused" now stops seeing the shed case** — that case went to another word, and that is the intent.

Not one endpoint was added or removed, and the **shape** of the responses is unchanged.

### What 1.6.0 changed, and its level

- The `409 expired` and `409 not_collecting` that a caller with no standing used to get from **approval submission, the approval view read and delay cancellation** become `404 not_found`. The 409s a caller with standing gets are **unchanged.**
- A `subject.id` or `resource.id` over 255 bytes is `400 invalid_request` — on check and on decide alike.

**The first changes an answer visible on the wire.** The ground for not raising the major is 1.4.0's, and it is narrower here: this document **never** promised those 409s to a caller with no standing, while the indistinguishability rule had been written since 1.1.0 and 1.4.0 tightened it to "**down to the response bytes**". The code was failing to keep it one level below the status code — what 1.4.0 fixed was the error table, and a table can say nothing about whether a caller with no standing **reaches** it at all. Not a change that breaks the contract but one that brings the code to it.

**The second refuses requests that were accepted until now.** The ground for leaving it at minor is that this is not a new required field but **a bound on an existing one**, and that this document never said the value was unbounded. Even so, a deployment that was sending identifiers over 255 bytes is now refused — such a deployment has to shorten the identifier to a stable key and carry the long form as a property. That value is also what an operator reads on the audit row.

Even so, **a client that read a `409` as "that decision is real" can now read it that way only when it has standing.** This paragraph is here so that fact is not hidden.

### What 1.7.0 changed, and its level

- `Idempotency-Key` is **bound to the request it names.** A different request under the same key is `409 idempotency_key_reused`, and the first decision does not come back — **adding an error code = minor.**
- On decide, **a shed challenge issuance creates no decision.** The deny with no `id` carries a `Retry-After`, and nothing is left on the subject's history.
- Each surface's challenge issuance budget is **split per (caller, subject), with a per-subject ceiling above it.** The settings are `STAMP_CHALLENGE_ISSUE_RATE_*` and `STAMP_CHALLENGE_ISSUE_SUBJECT_CEILING_*`. Nothing of it is visible on the wire.

**The first stops answering something it used to answer.** The ground for leaving it at minor is 1.4.0's, and narrower again. What this document promised was that **a repeat of the same key** answers the decision first created, and sending a different request under the same key is not the repeat that sentence describes. What this document did say, in 1.5.0, was "the server does not compare the key against the request body" — the sentence was true, and **what it meant was not written down.** It meant this: a caller that reused one key for a different subject, resource or action got the first decision back as `201 state: allowed`, the PEP permitted a transfer this engine had never judged, and since the response carries no subject, resource or action the PEP had no way of finding that out. Not a change that breaks the contract but one that stops behaviour the contract never promised. Even so, **a client that recycled one key across several requests now gets a 409** — such a client has to mint a new key per attempt.

**The second changes an answer visible on the wire.** A shed issuance was `201` + `Location` + `id` and becomes `200` with no `id`. The ground for not raising the major is that the only thing this document had said about it was **the one line stating that `challenge_rate_limited` carries an `id`** (1.5.0), and that line is the one now corrected. And the cost of not correcting it fell on people rather than on contract wording: a subject identifier is not a secret, so any workload that knew one could hold that person's issuance budget empty at one request every twenty seconds, and while it did, **every legitimate authorization of theirs was written into their history as a final deny.** A limit was writing judgments about a person, and stopping that costs one response shape. The rule that the presence of an `id` is not to be read off the status code has sat directly above that table since 1.1.0, and a client that kept it does not feel this change.

**The third is visible only to operators.** The existing `STAMP_CHALLENGE_ISSUE_RATE_*` is now a budget per (caller, subject), so a deployment that changed no values has that much per caller — what bounds the total reaching one person is the new ceiling (20 an hour by default, bursting to 10). The ceiling's burst **must be larger** than a single caller's, and a configuration where it is not is refused at boot: a ceiling one caller can empty in an instant is the shared bucket again.

**What remains is written down too.** The ceiling is still one bucket the callers share, so a determined caller can keep shedding somebody else's step-up at twenty an hour. A ceiling that cannot be emptied is not a ceiling. What changed is not the value but **the cost** — three a minute became twenty an hour, and above all a shed became a retryable refusal carrying a `Retry-After` rather than a judgment left on that person's record.

### What 1.8.0 changed, and its level

- **Delay cancellation gets a per-authority rate budget.** Over it, `429 rate_limited` with a `Retry-After` — **the same status, the same code and the same header** as an approval submission's refusal. The settings are `STAMP_CANCELLATION_RATE_PER_SECOND` and `STAMP_CANCELLATION_RATE_BURST`, defaulting to 1 a second bursting to 5, which is tighter than approval submission's (2 a second, bursting to 20).
- The refusal is audited as `cancellation_rate_limited`. That is neither the `error` vocabulary nor the `reason` one but **an audit ground**, and it is its own word, distinct from approval submission's `approval_rate_limited` and decide's `rate_limited` — an operator has to be able to tell which of the five write surfaces shed.

**The ground for leaving it at minor.** What this document promised about this endpoint is which answer follows from standing and from state; a promise that it may be called without limit is nowhere in it. `429` was already in this document's `error` table rather than being a new code, and it gained one more place to appear (adding a situation an error code answers = minor, the same shape as 1.7.0's ground). The path, the method and the authentication requirement are unchanged.

**Why now.** R43 required a budget on four write surfaces, and delay cancellation was the fifth. Not because a cancellation that succeeds is expensive — a cancellation resolves the decision, after which a second attempt is refused by the lifecycle. What is expensive is **a cancellation that is refused**: when a caller with no standing aims at a decision that **exists**, the lifecycle writes a synchronous audit-chain append, and 1.6.0's moving the standing judgment ahead of the state judgment made that append reachable across **the decision's whole life** rather than only while it was pending. That is, an authenticated console user could attach to a serialized write path without limit, holding one decision identifier. Closing the oracle in 1.6.0 raised that cost, and this version puts a budget on it.

**What changes on the wire.** Somebody attempting cancellations faster than one a second now gets a `429` instead of a `404` or a `200`. A cancellation a person makes in the console does not reach this limit — anything that does is a loop rather than a person.

## Surfaces the console does not call

The console subset of this contract is 17 endpoints (`console/contract/public-endpoints.json`). **Five of them are called by no console screen.** The contract states what the server serves and the console calls a subset of that subset, so the difference is a fact rather than a defect — but **a fact nobody wrote down is a fact nobody knows**, so it is written down here.

| Endpoint | Why it is not in the console |
|---|---|
| `delay-cancel` | R2's delay cancellation. **The server side is complete** — the endpoint, the per-authority budget, the `429` with a `Retry-After`, the `cancellation_rate_limited` audit ground (1.8.0). **None of it has anywhere to be rendered.** |
| `governance-lock` | The one-time bootstrap act that switches quorum governance on. That surface's refusal code says why: `403 bootstrap_token_required`. The token is held by whoever operates the deployment rather than by a console session, and carrying it into a browser to save one click puts the standing to install governance on the widest attack surface there is. |
| `policy-apply` · `policy-export` | The file-based authoring path. The console's builder changes policy through revision proposals (`revision-preview`, `revision-submit`, `revision-withdraw`) — a proposal is something a quorum can approve and a file apply is not. The callers of these two are the CLI and the CI that keep a repository and a deployment in step. |
| `schema-read` | The schema in force. The builder starts every draft from an empty schema and writes declarations into it, so it never reads what is already installed — **which is to say it cannot show an author what they are about to replace.** That is a hole rather than a judgment, and naming it here is how it is kept from becoming invisible. |

**Why documentation was chosen out of the three options.** Taking them out of the contract removes from the wire a surface other clients can already reach, which is a major, and these surfaces are not ones to remove. Building the screens is a new feature. What is left is **writing the non-implementation down as a fact**, and that becomes an input to the next round.

**This table is not a hand-written list.** The same five are listed with their reasons under `endpoints` in `console/contract/error-code-exemptions.json`, and `console/scripts/check-contract.mjs` compares the two directions — an endpoint no screen calls that is missing from the list is a failure, and so is one the list names that a screen calls. `internal/release` checks that this table and that file are the same set. A hand-written list goes wrong along with the thing it is describing.

### What 1.8.1 changed, and its level

- The section above was added. **Nothing changes on the wire** — not an endpoint, not a status code, not a response shape, not the `error` vocabulary. The document only wrote down what was already true, so: **a correction that does not change meaning = patch.**

**Why now.** This round turned the `error` codes the server can produce into a machine-readable artifact (`console/contract/error-codes.json`) and had it compared in both directions against the codes the console branches on. That comparison depends on the notion of "a surface the console does not reach" — there is no reason for the console to handle a callback listener's refusal codes. Once that notion is in use, **what the surfaces the console does not reach are has to be written down in one place.** Otherwise the ground for an exemption becomes a belief nobody checks.

## What this contract does not say yet

`Retry-After` speaks for **this instance's** budget. With several replicas the next request goes to another instance whose bucket is in another state — the header says "this much here", not "this much across the cluster".

The document format of the console subset (`console/contract/public-endpoints.json`) has a version field of its own, and that field numbers **the document's shape** rather than being this contract's version.
