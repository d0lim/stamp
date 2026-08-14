# Mutation matrix — the record of the tests proving they are tests

Origin: the completion round that added this discipline (U3, KTD5).
Subject: the fifteen hundred or so lines of new tests PR #51 brought in, and what U1 and U2 added on the same branch.

## Why this document exists

In PR #51's code review, seven of the eight lenses lost their results, and **the testing lens alone was neither recovered nor re-run.** Which means nobody looked at the tests that round brought in.

Running the same lens again is betting on the same failure mode a second time. And this project's habitual defect is the kind review is bad at catching — **a test that stays green while the thing it guards collapses.** The last round produced two of them: the console was green while exercising a code the server does not send (`not_an_approver`), and the chart's hand-written expectation map was wrong in the same direction the chart was (#46).

So instead of a review, **we plant defects and watch for red.** The output is not a report for a human to read, it is this table, and the next round can keep writing in it the same way.

## How to read it, and how to add to it

- **One row = one mutation.** It answers "if I change this one line of production code, is this test still green?"
- **Observed results quote the actual output.** No summaries — a summarized failure gives the next person no way to check whether they reproduced it.
- **The surviving mutations are this document's output.** A test that stayed green does not guard what it claims to guard. If it was fixed, write how; if it was not, write what it leaves uncovered.
- **Meaningless mutations are not invented to fill the table.** A change that alters nothing observable says nothing about the test in either direction. Those places go in §6 with the reason, instead of into a row.
- **The tree is restored after every mutation.** This round reverted each row with `git checkout --` and confirmed with `git status --porcelain`. Wreckage left behind by an audit is worse than not auditing.
- When you add to this, do not add sections — add rows to the table for that risk class. Add a section only when a new class appears.

Everything here was run on 2026-08-12, on `fix/stamp-completion-round`.

---

## 1. Authorization judgment — get this wrong and an oracle opens

What R40 stops is asking twice about one identifier to learn what it points at. This class is quietly dangerous **because every response is a refusal.** Whether 403 or 404 comes back, the caller is refused; the only thing that differs is the status code.

| # | Test | Defect planted | Result |
|---|---|---|---|
| 1.1 | `internal/runtime/oracle_test.go` `TestAStrangerReadsOneAnswerWhateverTheDecisionIsDoing` | `internal/api/approvals.go` `approvalError` splits `ErrNotTarget` and `ErrNotAuthorized` apart again, back to 403 `not_an_approver` (the pre-#38 state) | **red** |
| 1.2 | `internal/api/cancel_test.go` `TestCancellationByANonAuthorityIsIndistinguishableFromAMissingDecision` | same as above | **red** |
| 1.3 | `internal/decision/service_test.go` `TestStandingIsSettledBeforeStateOnTheSubmitPath` | in `decision.Service.Submit`, move `stillCollecting` **ahead of** `mayActOn` | **red** |
| 1.4 | `internal/runtime/oracle_test.go` (same test, under 1.3's defect) | same as above | **red** |

**1.1 / 1.2 observed output**

```
--- FAIL: TestAStrangerReadsOneAnswerWhateverTheDecisionIsDoing/the_submission
    oracle_test.go:162: the submission answers 404 {"error":"not_found","message":"no such decision or challenge"} for a decision that does not exist and 403 {"error":"not_an_approver","message":"you are not an approver for this challenge"} for a pending decision.
            the difference is an existence oracle: one identifier, two requests, and a caller with no standing learns that the decision is real and when it stopped being open. every refusal on this route has to be the same bytes.
```

```
--- FAIL: TestCancellationByANonAuthorityIsIndistinguishableFromAMissingDecision
    cancel_test.go:210: a non-authority = 403, a missing decision = 404
    cancel_test.go:213: body
         got "{\"error\":\"not_an_approver\",...}"
        want "{\"error\":\"not_found\",\"message\":\"no such decision or challenge\"}"
```

All three routes — submit, the approval screen, cancel — went red. `approvalError` is one place, so red appearing once per surface is itself evidence that the mapping is shared.

**1.3 / 1.4 observed output** — this defect does not touch the mapping. The mapping still reads `ErrNotTarget → 404`; what changes is that **a caller with no standing never reaches `ErrNotTarget` in the first place.** That makes it a different layer from 1.1's mutation, and the two tests each catch it at their own layer.

```
--- FAIL: TestStandingIsSettledBeforeStateOnTheSubmitPath
    service_test.go:478: a stranger submitting to a resolved decision returned ... decision is no longer pending, want ErrNotAuthorized: a state sentinel here is a 409 at the surface, and a 409 where a stranger would otherwise read 404 is how they learn the decision is real
    service_test.go:493: a stranger submitting to an expired decision returned ... store: decision has expired, want ErrNotAuthorized: ...
```

```
--- FAIL: TestAStrangerReadsOneAnswerWhateverTheDecisionIsDoing/the_submission
    oracle_test.go:162: the submission answers 404 {"error":"not_found",...} for a decision that does not exist and 409 {"error":"not_collecting",...} for a resolved decision.
    oracle_test.go:162: the submission answers 404 {...} for a decision that does not exist and 409 {"error":"expired",...} for an expired decision.
```

The comment in `approvals.go` says "Moving either check back behind a state check reopens it; internal/runtime/oracle_test.go is what notices". 1.4 is the confirmation that the sentence is true.

---

## 2. Rate limits — get them wrong and the limit is a pretence

All five of R43's surfaces are here. A rate limit fails **quietly**: when the limit does not bind the response is still normal, and a green test says "there is a limit". The particularly dangerous case is **a limit that does bind, but late** — after the cost it was there to prevent has already been paid in full.

| # | Test | Defect planted | Result |
|---|---|---|---|
| 2.1 | `internal/api/cancel_test.go` `TestACancellationOverTheBudgetNeverReachesTheLifecycle` | move `cancel.go`'s budget charge **behind** `decisions.Submit` | **red** |
| 2.2 | same test | move the charge **behind** `challengeRef` (still ahead of Submit) | **survived → fixed** (§5 fix A) |
| 2.3 | `internal/api/cancel_test.go` `TestARefusedCancellationIsAuditedUnderItsOwnGround` | change `CancellationRateLimitedReason` to `"approval_rate_limited"` | **red** |
| 2.4 | `internal/api/cancel_test.go` `TestTheCancellationBudgetIsPerAuthorityAndRefills` | drop the caller identifier from the limiter key (fixed `"canceller"`) | **red** |
| 2.5 | `internal/api/approvals_test.go` `TestSubmissionsAreRefusedOverTheApproverBudget` | move `approvals.go`'s budget charge **behind** `decisions.Submit` | **red** |
| 2.6 | same test | move the charge **behind** `challengeRef` and `readApprovalBody` (still ahead of Submit) | **survived → fixed** (§5 fix B) |
| 2.7 | `internal/api/ratelimit_test.go` `TestDecideSubjectPressureDoesNotCrowdOutCallers`, `TestDecideRateLimiterTablesAreBounded` | have `newDecideLimiter` merge the caller table and the subject table back into one and prefix subject keys with `\x1f` (the pre-#47 state) | **red** |
| 2.8 | `internal/api/ratelimit_test.go` `TestTheCallerBudgetRefusalCarriesItsOwnInterval` | have `refuseRate`'s `Retry-After` always carry the subject budget's interval | **red** |
| 2.9 | `internal/api/ratelimit_test.go` `TestARateLimitedDecideEvaluatesNothing` | move the subject budget charge **behind** `d.schemas.Schema()` | **red** |
| 2.10 | `internal/challenge/mfa/delegated_test.go` `TestOneCallerCannotSpendAnotherCallersShareOfASubject` | remove `allowIssue`'s short circuit, so the ceiling is charged even when the per-caller budget refuses | **red** |

**2.1 observed output** — reproduces this unit's (U1's) red exactly.

```
--- FAIL: TestACancellationOverTheBudgetNeverReachesTheLifecycle
    cancel_test.go:355: 10 of 10 attempts reached the lifecycle, want 2: each one past the budget is a synchronous audit-chain append a console user got for free
```

**2.3**

```
--- FAIL: TestARefusedCancellationIsAuditedUnderItsOwnGround
    cancel_test.go:312: the cancellation refusal is indistinguishable from the approval surface's
```

**2.4**

```
--- FAIL: TestTheCancellationBudgetIsPerAuthorityAndRefills
    cancel_test.go:380: a second authority's first attempt = 429: one authority spent another's budget
```

**2.5**

```
--- FAIL: TestSubmissionsAreRefusedOverTheApproverBudget
    approvals_test.go:526: 4 submissions reached the lifecycle, want 3: the refusal happened behind the row lock
```

**2.7** — this is exactly the shape #47 fixed. When two budgets share one table, you can fill the table with invented subjects and get **a caller that has spent none of its own budget** refused.

```
--- FAIL: TestDecideSubjectPressureDoesNotCrowdOutCallers
    ratelimit_test.go:461: a caller that had spent nothing = 200 {"state":"denied","reason":"rate_limited","obligations":[]}
        , want the request admitted: subject pressure is being paid for out of the caller budget's table
--- FAIL: TestDecideRateLimiterTablesAreBounded/the_subject_table
        ratelimit_test.go:379: subject 1 = 200 {"state":"denied","reason":"rate_limited","obligations":[]}
```

**2.8**

```
--- FAIL: TestTheCallerBudgetRefusalCarriesItsOwnInterval
    ratelimit_test.go:627: Retry-After = "1", want "4" — the caller budget's interval, not the subject's
```

**2.9** — the caller budget side does not move under this defect, so only one subtest goes red. That is correct: the two charge points guard different things.

```
--- FAIL: TestARateLimitedDecideEvaluatesNothing/the_subject's_budget
        ratelimit_test.go:319: the policy schema was read 1 times over the limit, want none
```

**2.10** — this is the place `allowIssue`'s comment calls out with "The order is load-bearing and the short circuit is the fix". Remove the short circuit and a caller that has spent its own budget goes on emptying somebody else's ceiling **with requests that are refused.**

```
--- FAIL: TestOneCallerCannotSpendAnotherCallersShareOfASubject
    delegated_test.go:1283: a second caller's first step-up for the same subject = "failed", want pending: one caller emptied another caller's share of one person's prompts
```

---

## 3. Idempotency — get it wrong and an authorization nobody evaluated answers allow

This is the quietest class in the table. Wrong idempotency **does not produce an error** — it produces `201 allowed`. `decision.Result` carries no subject, no resource and no action, so there is no field in which a PEP could notice the substitution.

| # | Test | Defect planted | Result |
|---|---|---|---|
| 3.1 | `internal/decision/service_test.go` `TestAKeyReusedForADifferentRequestIsRefused` | `sameRequest` returns `true` unconditionally instead of comparing fingerprints | **red** |
| 3.2 | `internal/decision/service_test.go` `TestTheSameKeyFromADifferentCallerIsADifferentDecision` | drop the `caller_id` predicate from the idempotency lookup's `WHERE` | **red** |
| 3.3 | `internal/decision/service_test.go` `TestConcurrentDecidesUnderOneKeyConvergeOnOneDecision`, `TestASecondDecisionUnderOneKeyIsAConflict` | change migration `000009`'s `CREATE UNIQUE INDEX` to `CREATE INDEX` | **red** |

**3.1** — reproduces the actual incident the `ErrIdempotencyKeyReused` comment describes: a PEP that reused `job-91` for a different person gets the first decision back.

```
--- FAIL: TestAKeyReusedForADifferentRequestIsRefused
    service_test.go:1163: a key reused for a different subject returned ({ID:dfaa9e32-... State:pending Outcome:challenge Reason:challenge_required ...}, <nil>), want decision.ErrIdempotencyKeyReused
```

**3.2** — the shape where a key leaks between callers. If two PEPs happen to use the same key string, one receives the other's decision.

```
--- FAIL: TestTheSameKeyFromADifferentCallerIsADifferentDecision
    service_test.go:1240: two callers sharing the key "retry-1" got one decision "d809e1f1-..."
    service_test.go:1243: challenges issued = 1, want 2: two callers are two decisions
    service_test.go:1246: the decisions table holds 1 rows, want 2
```

**3.3** — the application-layer lookup does not stop the race. The index does, and mutating the schema is how we checked that this is actually tested.

```
--- FAIL: TestConcurrentDecidesUnderOneKeyConvergeOnOneDecision
    service_test.go:1335: racing decides answered [7f1c0344-... 4862b153-... 64de0d41-... b1925a36-...], want one decision
--- FAIL: TestASecondDecisionUnderOneKeyIsAConflict
    service_test.go:1386: a second decision under one key returned <nil>, want store.ErrConflict
```

---

## 4. Drift checks — get them wrong and all that is left is the word "they agree"

A drift check's **normal state is always-green**, so it never gets an opportunity to prove its own integrity. That is how #46 got through: the hand-written expectation map was wrong in the same direction the chart was, and the check was green. So here we **mutate the real documents and the real chart.**

| # | Test | Defect planted | Result |
|---|---|---|---|
| 4.1 | `internal/release/routes_test.go` `TestTheContractDocumentAndTheMountedRoutesAreTheSameSet` | delete the cancellation endpoint's row from `docs/contracts/decision-api.md` | **red** |
| 4.2 | same test | change that row's surface and authentication to `pep`/`workload` (endpoint unchanged) | **red** |
| 4.3 | `internal/runtime/wiring_test.go` `TestTheMountTableFileIsUpToDate` + 4.1's test | change `CancellationPattern`'s path from `/cancellation` to `/cancel` | **red** (both) |
| 4.4 | `internal/release/chart_test.go` `TestSplitIsNotAllInOneUnderFiveNames` | remove `pep` from the `decide` role's surface list in `_helpers.tpl`, then re-render the snapshot (#46 reproduced) | **red** |
| 4.5 | `internal/api/contract_test.go` `TestConsoleContractFileIsUpToDate` | delete `delay-cancel` from `console/contract/public-endpoints.json` | **red** |
| 4.6 | `internal/runtime/config_test.go` `TestAFeatureThatCompletesOnTheCallbackSurfaceNeedsItBound` and 2 others | disable the ingest-credentials condition in `Config.surfaceRequirements` | **red** |
| 4.7 | `internal/runtime/config_test.go` `TestARoleThatMountsNoCallbackRouteIsNotRefused` | remove the `roles.Has(RoleDecide)` gating from the same function | **red** |

**4.1 / 4.2** — these catch the two directions separately. A row that disappears is "mounted and undocumented"; a row that is wrong is "drifted". This is where you can see that the check is a set comparison and not a string comparison.

```
--- FAIL: TestTheContractDocumentAndTheMountedRoutesAreTheSameSet
    routes_test.go:316: the decision API contract and the mounted routes disagree:
          mounted and undocumented: POST /decisions/{id}/challenges/{ordinal}/cancellation (console / user / decide) is served and the contract document does not list it
```

```
    routes_test.go:316: ...
          drifted: POST /decisions/{id}/challenges/{ordinal}/cancellation is documented as pep / workload / decide and mounted as console / user / decide
```

**4.3** — the direction where the code moves first. `mounted-routes.json` is derived from the code, so it goes stale first, and updating it then puts it at odds with the contract document. **Both stages catching** is the point of this arrangement.

```
--- FAIL: TestTheMountTableFileIsUpToDate
    wiring_test.go:1519: ../release/testdata/mounted-routes.json was stale and has been rewritten; review the diff, commit it, and expect internal/release to name whatever the contract document or the chart no longer agrees with
```

```
--- FAIL: TestTheContractDocumentAndTheMountedRoutesAreTheSameSet
    routes_test.go:316: ...
          documented and unmounted: POST /decisions/{id}/challenges/{ordinal}/cancellation (console / user / decide) is in the contract document and no component mounts it
          mounted and undocumented: POST /decisions/{id}/challenges/{ordinal}/cancel (console / user / decide) is served and the contract document does not list it
```

**4.4** — this is #46 itself. We edited the real chart, rebuilt the snapshot with `deploy/helm/render.sh`, and then ran. That is, the snapshot was not touched by hand — **the chart was made to actually render that way.**

```
--- FAIL: TestSplitIsNotAllInOneUnderFiveNames/each_tier_binds_exactly_the_surfaces_its_role's_routes_are_on
        chart_test.go:381: stamp-decide: the decide role mounts [GET /decisions/{id} POST /decisions] on the pep surface and this tier does not bind it: those routes are not refused there, they are unreachable
```

**4.6** — the axis U2 added. Removing any one of the three conditions turns three tests red, each from a different angle. The last one matters most — it is the oracle for **whether the chart's refusal and the binary's refusal catch the same configuration**, so a state where only one of them catches it is exposed.

```
--- FAIL: TestAFeatureThatCompletesOnTheCallbackSurfaceNeedsItBound/http_velocity_ingest
        config_test.go:618: http velocity ingest with no callback listener was accepted: the route it completes on is mounted on a surface nothing binds
--- FAIL: TestTheRefusalNamesEveryStrandedSetting
    config_test.go:652: the refusal stops before naming STAMP_INGEST_CREDENTIALS: ...
--- FAIL: TestTheBinaryAndTheChartRefuseTheSameStrandedRelease
    config_test.go:823: the binary's refusal does not name STAMP_INGEST_CREDENTIALS: ...
    config_test.go:833: the binary's refusal does not name /ingest/v1/events, which is mounted on the callback surface and is therefore one of the things this process would have lost: ...
```

**4.7** — the opposite direction. Remove the gating and even roles that mount no callback route get refused, so red also appears when the check is wrong **in the over-catching direction.**

```
--- FAIL: TestARoleThatMountsNoCallbackRouteIsNotRefused/console
        config_test.go:698: --roles=console mounts no callback route and was refused anyway: ...
--- FAIL: TestARoleThatMountsNoCallbackRouteIsNotRefused/consumer
        config_test.go:724: the consumer role was refused for STAMP_MFA_AUTHORIZATION_ENDPOINT, whose route only the decide role mounts: ...
```

---

## 5. The console — where a stub stands in for the truth

The last round's actual incident happened here. A console test was green while exercising against a stub **a code the server does not send** (`not_an_approver`, and a 409 alongside it). When a fixture stands in for the server, the server can change and the test says nothing.

| # | Test | Defect planted | Result |
|---|---|---|---|
| 5.1 | `console/src/inbox/inbox.test.tsx`, the two 429 cases | remove `cause.isRateLimited \|\|` from `ApprovalScreen.failureOf` (decide on the body code alone) | **survived → fixed** (§5 fix C) |
| 5.2 | the same two cases | remove `\|\| body?.error === RATE_LIMITED` (decide on the status alone) | **survived → not a meaningful mutation** (§6.2) |
| 5.3 | `console/src/inbox/inbox.test.tsx`, the two `Retry-After` cases | make `client.ts`'s `retryAfterOf` always return `undefined` | **red** |
| 5.4 | `console/src/audit/audit.test.tsx`, the two auditor-refusal cases | change `AuditScreen`'s `setRefused(... isForbidden)` to `setRefused(false)` | **red** |
| 5.5 | `internal/api/contract_test.go` (the same row as 4.5) | delete one endpoint from the console contract JSON | **red** |

**The console output below is quoted unchanged from the run, and its test names
and rendered strings are Korean because the console was Korean when this audit
was performed.** It was translated to English afterwards, so these names no
longer exist — grepping for them finds nothing, and the strings the assertions
compare are now their English equivalents. The observation is kept verbatim
rather than retro-translated: writing English into a block labelled "observed
output" would be inventing output no run ever produced, which is the failure
this whole document exists to catch. Read them as a dated record; the tests they
name are still there under English names, in the same files and asserting the
same things.

**5.3**

```
FAIL  src/inbox/inbox.test.tsx > 제출 실패 > 429 rate_limited는 기다리라고 말하지, 운영자에게 가라고 하지 않는다
Expected element to have text content:
  30초
Received:
  승인 제출이 너무 잦아 이번 제출이 거부되었습니다. ... 잠시 기다린 뒤 승인 버튼을 다시 누르십시오. ...
```

**5.4**

```
× 감사 목록 > 감사자 자격이 없으면 거부 화면을 보여주고 남은 경로를 알려준다
  → Unable to find an element by: [data-testid="audit-refused"]
× 감사 콘솔 접근성 > 거부 화면에도 axe 위반이 없다
  → Unable to find an element by: [data-testid="audit-refused"]
```

### The console stubs against the server — as of 2026-08-12

Separately from the mutations, we checked by hand whether the shapes the console stubs are the same as **what today's Go handlers actually emit**. The result:

- **The response fields agree.** The JSON tags of `challenge.InboxItem`, `api.InboxResponse`, `challenge.QuorumReview`, `challenge.QuorumReviewDecision`, `decision.Result`, `decision.ChallengeView`, `api.AuditDecisionRow`/`Detail`/`ListResponse`/`AuditQueryEcho`/`AuditChallenge`/`AuditApproval` were matched one by one against `console/src/inbox/api-types.ts` and `console/src/audit/api-types.ts`, and no name disagrees. `DECISION_STATES` is also the same five as `store.DecisionState`.
- **The error codes agree too.** The codes the console branches on or stubs are `not_found`, `expired`, `not_collecting`, `material_changed`, `rate_limited`, `not_an_auditor`, `invalid_policy` and `revision_pending`, and every one of them is a code today's Go handlers emit (`approvals.go` `approvalError`, `auditconsole.go`, `dryrun.go`, `policies.go`). The `not_an_approver` the last round killed is not left in the console either. `oidc.test.ts`'s `access_denied` is an OAuth error response rather than a server code, so it is not in scope for this comparison.
- **There is one surface the console never calls at all — cancellation.** `delay-cancel` is in `console/contract/public-endpoints.json`, but nowhere in `src/` calls `api.request('delay-cancel')`. **U1 added a 429 on that surface and the console has no screen to render it on.** This is not a stub disagreeing with the server — there is no screen. It is a finding of this unit rather than a defect to fix, so it is recorded in §7.
- **Keep straight what is held automatically and what is held by hand.** An endpoint's **name, method and path** are held by machine (generation from `internal/api` into `console/contract/public-endpoints.json`, plus `check-contract.mjs`'s boundary check, confirmed by 4.5). **There is no machine holding the field names and the error-code vocabulary** — the comparison above was done by a person and is a fact of today's date. That is the first item in §7.

### How the three survivors were fixed

**Fix A — the cancellation surface (row 2.2)** — added one more assertion to `TestACancellationOverTheBudgetNeverReachesTheLifecycle` in `internal/api/cancel_test.go`. An unparseable ordinal sent while over the budget must answer 429, not 400. If the charge slides behind `challengeRef`, that request and only that request answers differently.

> U1's report recorded this place as "not a meaningful mutation, nothing observable changes". That is half right — the number of times the lifecycle is reached really is unchanged. But `challengeRef` can fail (a non-integer ordinal), and when it does, the answer a caller over its budget gets splits into 400 versus 429. The handler's comment promises that answer, so the promise was moved into an assertion.

The same mutation after the fix:

```
--- FAIL: TestACancellationOverTheBudgetNeverReachesTheLifecycle
    cancel_test.go:371: an unparseable path from an authority over its budget answered 400, want 429: the budget is charged before the path is parsed, so nothing about the request can buy a different answer
```

**Fix B — approval submission (row 2.6)** — added two assertions to `TestSubmissionsAreRefusedOverTheApproverBudget` in `internal/api/approvals_test.go`. An unparseable path answers 429 rather than 400, and a body over `DefaultMaxApprovalBytes` answers 429 rather than 413. The handler comment's "before the path is parsed and before the body is read" now has one assertion for each half. Unlike cancellation, approval submission reads a body, so the latter is a real cost.

The same mutation after the fix:

```
--- FAIL: TestSubmissionsAreRefusedOverTheApproverBudget
    approvals_test.go:596: an unparseable path from an approver over its budget answered 400, want 429: the budget is charged before the path is parsed
    approvals_test.go:601: an oversized body from an approver over its budget answered 413, want 429: the budget is charged before the body is read, so the surface never reads 8193 bytes for a caller it has already refused
```

**Fix C — the console's 429 (row 5.1)** — the two existing 429 tests stub **the status and the body code at the same time.** That is why leaving either half of `cause.isRateLimited || body?.error === RATE_LIMITED` was still green. There was no test for the case where the status side is actually needed — **a 429 emitted by a middlebox between the console and the engine.** That case was added to `inbox.test.tsx`: a 429 whose body is HTML rather than this API's error vocabulary.

The same mutation after the fix:

```
FAIL  src/inbox/inbox.test.tsx > 제출 실패 > 코드를 읽을 수 없는 429도 기다림으로 읽힌다 — 중간자가 흘린 경우
Expected element to have text content:
  기록되지 않았습니다
Received:
  요청이 429로 실패했습니다.문제가 계속되면 운영자에게 이 화면의 결정 식별자를 전달하십시오.
```

The string that came back is the whole reason this branch exists: copy that sends an approver to an operator in the face of a limit that clears on its own.

---

## 6. Where no meaningful mutation could be constructed

What is recorded here is not "the test is weak" — it is **"a mutation at this place says nothing in either direction".** Inventing a weak mutation to fill the table produces a row that misleads the next person.

### 6.1 The prefix on the cancellation limiter key

`cancel.go` charges under `"canceller\x1f"+caller.CallerID()`. Change the prefix to `"k:"` and run `go test ./internal/api/` and it is **green.**

Why that is not a defect: this limiter is cancellation-only and no other namespace enters its table. The prefix is for a future in which the table is shared; it is not stopping anything today. Since it makes no difference to today's behaviour, **it is correct that no test catches it.** (The `\x1f` on the `decide` path is different — there, two namespaces really were in one table, and 2.7 catches that place.)

### 6.2 The console's `body?.error === RATE_LIMITED` half (5.2)

Remove this half alone and the console suite is green, and **it cannot honestly be made red.** Doing so would require stubbing a response that carries a `rate_limited` body on a status other than 429, and today's server sends no such response (`approvals.go`, `cancel.go`, `ingest.go` and `authoring.go` all emit it with a 429). Writing that stub would be **exercising a shape the server does not emit** — precisely the failure mode this unit exists because of.

So the branch stays (it is a defence against a middlebox forwarding the code, and it costs nothing) and is not pinned by a test. Better to record here what is not covered.

### 6.3 The `d <= 0` branch in `retryAfterSecondsFor`

`ratelimit.go` already says it in a comment: "Not reachable from a refusal — an unlimited budget refuses nothing". Change an unreachable branch and no test moves. That is correct.

### 6.4 U4 (CI diagnostics) and U5 (deleting `CIBA.Poll`)

U4 touches only `.github/workflows/ci.yml`. It is a layer with no unit tests, so there is no defect to plant here — that unit's verification is, as planned, **watching one deliberately broken run.** U5 deleted code, so there is nothing to plant in, and `go build` / `go vet` catch any remaining reference.

---

## 7. The boot race — the record of turning a probabilistic guard into a deterministic one

This section **has been written twice.** The first draft measured a probabilistic guard by mutation and recorded "red confirmed". Code review showed that record to be **false confidence.** The first draft is kept rather than deleted, because that is exactly the kind of thing this table exists for.

### 7.1 Where the first draft was wrong (kept on the record)

The first draft attached a barrier to `TestMigrateSurvivesConcurrentBoot`, measured the peak **number of boots simultaneously inside `Migrate`**, and failed if it was 1. Then it recorded that this "closed the case of a serialized run passing silently".

**It did not close it.** `Lock()` polls for up to 90 seconds, so the boots that lose the migration lock **structurally** stay inside `Migrate` until the winner's migration finishes. The peak is effectively always `concurrentBoots` — **including across the 143 runs that were green on unmodified code.** So that assertion **would never once have fired** on the runs it claimed to catch.

The window in which the race happens is not the whole of `Migrate` — it is the microseconds inside `CREATE TABLE IF NOT EXISTS`. Overlap measured outside that window is overlap, not a race.

**And the run counts of the paired mutation were already saying so**: 1 red in 130 runs means "one CI run catches doubly broken code about 1% of the time". That number was written down and the conclusion was still recorded as "red confirmed". **Recording the run count is not enough; you have to read what the run count means.**

### 7.2 The guard as it stands — stop measuring the race and **catch the lock and the branch directly**

It does not try to measure the race. It measures whether the machinery that removes the race **is there.**

| Where planted | Mutation | Test that catches it | Result | Runs |
|---|---|---|---|---|
| `migrate.go` (real) | delete the `pg_advisory_xact_lock` line | `TestVersionTableCreateWaitsForTheAdvisoryLock` | **red** | **1 of 1** (0.05s) |
| `migrate.go` (real) | let the duplicate-tolerance branch fall through to `Commit` | `TestVersionTableToleratesAPeerThatDidNotTakeTheLock` | **red** | **1 of 1** (0.07s) |
| `migrate.go` (real) | remove `42710` from `isDuplicateObject` | `TestIsDuplicateObjectAcceptsEveryConcurrentCreateCode/42710` | **red** | **1 of 1** (immediate) |

All three are **deterministic.** There is no luck in them.

How: the lock is measured by whether the create **waits** while another session holds the same key. The tolerance branch is measured by queueing behind an uncommitted peer's create, **confirming through `pg_stat_activity` that it actually queued**, and only then committing the peer. The ordering is observed rather than hoped for with a sleep.

What that round asked for was "a guard that does not lean on luck". The first draft tried to **measure** the luck; this one **removes** it.

### 7.3 The probabilistic test stays, but it is named for what it is

`TestMigrateSurvivesConcurrentBoot` stays. On unmodified code it failed **2 times in 145** (about 1.4%), so **its green says nothing about 98.6% of cases.** Its comment now records that it is an end-to-end smoke test, and points at where the deterministic guards are.

One round declared the boot race solved on the strength of that green. The answer is not to delete the probabilistic test — the answer is **to make the document say what it does not prove.**

### 7.4 Why answering falsely on `42501` is in this table

"Simplifying" `isDuplicateObject` into a SQLSTATE **class** match looks like an improvement in a diff. Class 42 contains `42501 insufficient_privilege`, so that change would **read a permission denial as "already exists" and let the boot succeed on a least-privilege deployment.**

`TestIsDuplicateObjectRefusesCodes` goes red on that change. It is not a record of catching a defect — it is **a record of blocking a plausible change still to come.**

---

## 8. What this table does not cover

- **There is no machine binding the console's response types and error vocabulary to the server.** The comparison in §5 was done by a person on 2026-08-12. Endpoint names, methods and paths are held by generation and a boundary check, but the field names in `api-types.ts` and the `error` codes the screens branch on are a mirror aligned by hand. The last round's incident happened at exactly this layer, so **it is the first place the next round should look.**
- **The cancellation surface has no console screen.** `delay-cancel` is in the public contract and the server has the 429, the `Retry-After` and the audit, and no screen calls it. When the console opens that surface it has to bring the 429 rendering with it, and at that point whether `failureOf`'s copy may be the same as approval submission's is a judgement call (for a cancellation, "this approval was not recorded" is not the right sentence).
- ~~**One mutation at a time.**~~ §7 filled this gap — the case of two changes masking each other **is real** (the widened `isDuplicateObject` absorbed the lock removal). The remaining sections (§1–§6) are still one at a time, so whether pairs mask each other there is still unknown.
- **A mutation going red is not enough on its own.** §7.1 is that lesson. A probabilistic test has to be recorded with its run count, and that count has to be read as "the probability that one CI run catches this". 1/130 is not red — it is **very nearly green.**
- **Performance and contention are out of scope.** A budget that binds *late* is caught by 2.1, 2.5 and 2.9, but this table says nothing about what that cost actually is.
- **The audit chain itself outside `internal/api`** (gap markers, checkpoint signatures) was left out of this round. It is not somewhere PR #51 touched heavily.
