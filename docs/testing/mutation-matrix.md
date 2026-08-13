# 뮤테이션 행렬 — 테스트가 자기가 테스트임을 증명한 기록

계획: `docs/plans/2026-08-12-001-fix-stamp-completion-round-plan.md` (U3, KTD5).
대상: PR #51이 들여온 1500줄 남짓의 새 테스트와, 같은 브랜치의 U1·U2가 더한 것.

## 이 문서가 있는 이유

PR #51의 코드 리뷰에서 여덟 렌즈 중 일곱이 결과를 잃었고, **testing 렌즈만 회수되지도 재실행되지도 않았다.** 그 라운드가 들여온 테스트를 아무도 보지 않았다는 뜻이다.

같은 렌즈를 다시 돌리는 것은 같은 실패 양식에 다시 거는 일이다. 그리고 이 프로젝트의 상습 결함은 리뷰가 잘 못 잡는 종류다 — **지키는 대상이 무너져도 초록인 테스트.** 지난 라운드에만 두 번 나왔다: 콘솔이 서버가 보내지 않는 코드를 스텁으로 시험하며 초록이었고(`not_an_approver`), 차트의 손으로 쓴 기대 map은 차트와 함께 틀렸다(#46).

그래서 리뷰 대신 **결함을 심고 빨개지는지 본다.** 산출물은 사람이 읽는 보고가 아니라 이 표이고, 다음 라운드가 같은 방식으로 이어 쓸 수 있다.

## 읽는 법과 이어 쓰는 법

- **행 하나 = 뮤테이션 하나.** "이 프로덕션 코드를 한 줄 바꾸면 이 테스트가 여전히 초록인가"에 대한 답이다.
- **관찰된 결과는 실제 출력을 인용한다.** 요약하지 않는다 — 요약된 실패는 다음 사람이 재현했는지 확인할 수 없다.
- **살아남은 뮤테이션이 이 문서의 산출물이다.** 초록으로 남은 테스트는 그것이 지킨다고 주장하는 것을 지키지 않는다. 고쳤으면 어떻게 고쳤는지, 안 고쳤으면 무엇을 덮지 않는지 적는다.
- **뜻이 없는 뮤테이션은 만들어 채우지 않는다.** 관찰 가능한 것이 아무것도 바뀌지 않는 변형은 테스트에 대해 어느 쪽으로도 말하지 않는다. 그런 자리는 표를 채우는 대신 §6에 이유와 함께 적는다.
- **트리는 매 뮤테이션 뒤에 복원한다.** 이 라운드는 각 행 뒤에 `git checkout --`로 되돌리고 `git status --porcelain`으로 확인했다. 감사가 남긴 잔해는 감사를 안 한 것보다 나쁘다.
- 이어 쓸 때는 절을 늘리지 말고 해당 위험 부류의 표에 행을 더한다. 새 부류가 생기면 절을 하나 더한다.

전부 2026-08-12, `fix/stamp-completion-round` (`6d647e3` 기준) 에서 실행했다.

---

## 1. 인가 판정 — 틀리면 오라클이 열린다

R40이 막으려는 것은 "식별자 하나로 두 번 물어 그것이 무엇을 가리키는지 알아내는" 일이다. 이 부류가 조용히 위험한 이유는 **응답이 전부 거부이기 때문**이다. 403과 404 중 어느 쪽이 오든 호출자는 거부당하고, 다른 것은 상태 코드뿐이다.

| # | 테스트 | 심은 결함 | 결과 |
|---|---|---|---|
| 1.1 | `internal/runtime/oracle_test.go` `TestAStrangerReadsOneAnswerWhateverTheDecisionIsDoing` | `internal/api/approvals.go` `approvalError`가 `ErrNotTarget`·`ErrNotAuthorized`를 다시 403 `not_an_approver`로 가른다 (#38 이전 상태) | **red** |
| 1.2 | `internal/api/cancel_test.go` `TestCancellationByANonAuthorityIsIndistinguishableFromAMissingDecision` | 위와 같음 | **red** |
| 1.3 | `internal/decision/service_test.go` `TestStandingIsSettledBeforeStateOnTheSubmitPath` | `decision.Service.Submit`에서 `stillCollecting`을 `mayActOn` **앞으로** 옮긴다 | **red** |
| 1.4 | `internal/runtime/oracle_test.go` (같은 테스트, 1.3의 결함으로) | 위와 같음 | **red** |

**1.1 / 1.2 관찰된 출력**

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

세 라우트(제출·승인 화면·취소) 모두에서 red였다. `approvalError`가 한 곳이므로 표면 수만큼 red가 난다는 것 자체가 그 표가 공유되고 있다는 증거다.

**1.3 / 1.4 관찰된 출력** — 이 결함은 표를 건드리지 않는다. 표는 그대로 `ErrNotTarget → 404`인데, **자격 없는 호출자가 애초에 `ErrNotTarget`에 닿지 못하게** 만든다. 그래서 1.1의 뮤테이션과 다른 층이고, 두 테스트가 각각 자기 층에서 잡는다.

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

`approvals.go`의 주석은 "Moving either check back behind a state check reopens it; internal/runtime/oracle_test.go is what notices"라고 적어 두었다. 그 문장이 참임을 확인한 것이 1.4다.

---

## 2. 속도 제한 — 틀리면 한도가 있는 척한다

R43의 다섯 표면 전부가 여기 있다. 속도 제한의 실패는 **조용하다**: 한도가 안 걸려도 응답은 정상이고, 초록인 테스트가 "한도가 있다"고 말한다. 특히 위험한 것은 **한도가 걸리기는 하는데 늦게 걸리는 것** — 보호하려던 비용을 이미 다 치른 뒤다.

| # | 테스트 | 심은 결함 | 결과 |
|---|---|---|---|
| 2.1 | `internal/api/cancel_test.go` `TestACancellationOverTheBudgetNeverReachesTheLifecycle` | `cancel.go`의 예산 부과를 `decisions.Submit` **뒤로** 옮긴다 | **red** |
| 2.2 | 같은 테스트 | 부과를 `challengeRef` **뒤로**(Submit 앞) 옮긴다 | **살아남음 → 고침** (§5 고침 A) |
| 2.3 | `internal/api/cancel_test.go` `TestARefusedCancellationIsAuditedUnderItsOwnGround` | `CancellationRateLimitedReason`을 `"approval_rate_limited"`로 바꾼다 | **red** |
| 2.4 | `internal/api/cancel_test.go` `TestTheCancellationBudgetIsPerAuthorityAndRefills` | 제한기 키에서 호출자 식별자를 뺀다 (`"canceller"` 고정) | **red** |
| 2.5 | `internal/api/approvals_test.go` `TestSubmissionsAreRefusedOverTheApproverBudget` | `approvals.go`의 예산 부과를 `decisions.Submit` **뒤로** 옮긴다 | **red** |
| 2.6 | 같은 테스트 | 부과를 `challengeRef`·`readApprovalBody` **뒤로**(Submit 앞) 옮긴다 | **살아남음 → 고침** (§5 고침 B) |
| 2.7 | `internal/api/ratelimit_test.go` `TestDecideSubjectPressureDoesNotCrowdOutCallers`, `TestDecideRateLimiterTablesAreBounded` | `newDecideLimiter`가 호출자 표와 주체 표를 다시 하나로 합치고 주체 키에 `\x1f` 접두사를 붙인다 (#47 이전 상태) | **red** |
| 2.8 | `internal/api/ratelimit_test.go` `TestTheCallerBudgetRefusalCarriesItsOwnInterval` | `refuseRate`의 `Retry-After`가 언제나 주체 예산의 간격을 싣는다 | **red** |
| 2.9 | `internal/api/ratelimit_test.go` `TestARateLimitedDecideEvaluatesNothing` | 주체 예산 부과를 `d.schemas.Schema()` **뒤로** 옮긴다 | **red** |
| 2.10 | `internal/challenge/mfa/delegated_test.go` `TestOneCallerCannotSpendAnotherCallersShareOfASubject` | `allowIssue`의 단락(short circuit)을 없애고 per-caller 예산이 거부해도 천장을 부과한다 | **red** |

**2.1 관찰된 출력** — 이 유닛(U1)의 red를 그대로 재현한다.

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

**2.7** — #47이 고친 것이 정확히 이 모양이다. 두 예산이 한 표를 나눠 쓰면 지어낸 주체로 표를 채워 **자기 예산을 한 톨도 쓰지 않은 호출자**를 거부시킬 수 있다.

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

**2.9** — 호출자 예산 쪽은 이 결함으로 움직이지 않으므로 하위 테스트 하나만 red다. 그것이 맞다: 두 부과 지점은 서로 다른 것을 지킨다.

```
--- FAIL: TestARateLimitedDecideEvaluatesNothing/the_subject's_budget
        ratelimit_test.go:319: the policy schema was read 1 times over the limit, want none
```

**2.10** — `allowIssue`의 주석이 "The order is load-bearing and the short circuit is the fix"라고 적은 그 자리다. 단락을 없애면 자기 예산을 다 쓴 호출자가 **거부당한 요청으로** 남의 천장을 계속 비운다.

```
--- FAIL: TestOneCallerCannotSpendAnotherCallersShareOfASubject
    delegated_test.go:1283: a second caller's first step-up for the same subject = "failed", want pending: one caller emptied another caller's share of one person's prompts
```

---

## 3. 멱등성 — 틀리면 평가하지 않은 인가를 허용으로 답한다

이 부류가 이 표에서 가장 조용하다. 잘못된 멱등성은 **에러를 내지 않는다** — `201 allowed`를 낸다. `decision.Result`에는 주체도 자원도 행위도 없으므로 PEP가 바꿔치기를 알아챌 필드가 없다.

| # | 테스트 | 심은 결함 | 결과 |
|---|---|---|---|
| 3.1 | `internal/decision/service_test.go` `TestAKeyReusedForADifferentRequestIsRefused` | `sameRequest`가 지문을 비교하지 않고 언제나 `true` | **red** |
| 3.2 | `internal/decision/service_test.go` `TestTheSameKeyFromADifferentCallerIsADifferentDecision` | 멱등성 조회의 `WHERE`에서 `caller_id` 제약을 없앤다 | **red** |
| 3.3 | `internal/decision/service_test.go` `TestConcurrentDecidesUnderOneKeyConvergeOnOneDecision`, `TestASecondDecisionUnderOneKeyIsAConflict` | 마이그레이션 `000009`의 `CREATE UNIQUE INDEX`를 `CREATE INDEX`로 바꾼다 | **red** |

**3.1** — `ErrIdempotencyKeyReused` 주석이 서술한 실제 사고를 그대로 재현한다: `job-91`을 다른 사람에 대해 재사용한 PEP가 첫 결정을 돌려받는다.

```
--- FAIL: TestAKeyReusedForADifferentRequestIsRefused
    service_test.go:1163: a key reused for a different subject returned ({ID:dfaa9e32-... State:pending Outcome:challenge Reason:challenge_required ...}, <nil>), want decision.ErrIdempotencyKeyReused
```

**3.2** — 호출자 사이로 키가 새는 모양. 두 PEP가 우연히 같은 키 문자열을 쓰면 한쪽이 다른 쪽의 결정을 받는다.

```
--- FAIL: TestTheSameKeyFromADifferentCallerIsADifferentDecision
    service_test.go:1240: two callers sharing the key "retry-1" got one decision "d809e1f1-..."
    service_test.go:1243: challenges issued = 1, want 2: two callers are two decisions
    service_test.go:1246: the decisions table holds 1 rows, want 2
```

**3.3** — 애플리케이션 층의 조회는 경합을 막지 못한다. 막는 것은 인덱스이고, 그 사실이 실제로 테스트되는지를 스키마를 변형해 확인했다.

```
--- FAIL: TestConcurrentDecidesUnderOneKeyConvergeOnOneDecision
    service_test.go:1335: racing decides answered [7f1c0344-... 4862b153-... 64de0d41-... b1925a36-...], want one decision
--- FAIL: TestASecondDecisionUnderOneKeyIsAConflict
    service_test.go:1386: a second decision under one key returned <nil>, want store.ErrConflict
```

---

## 4. 드리프트 검사 — 틀리면 "일치한다"는 말만 남는다

드리프트 검사는 **언제나 초록인 것이 정상 상태**라서 자기 무결성을 증명할 기회가 없다. #46이 그렇게 지나갔다: 손으로 쓴 기대 map이 차트와 함께 틀렸고, 검사는 초록이었다. 그래서 여기서는 **실물 문서와 실물 차트를 변형**한다.

| # | 테스트 | 심은 결함 | 결과 |
|---|---|---|---|
| 4.1 | `internal/release/routes_test.go` `TestTheContractDocumentAndTheMountedRoutesAreTheSameSet` | `docs/contracts/decision-api.md`에서 취소 엔드포인트 행을 지운다 | **red** |
| 4.2 | 같은 테스트 | 같은 행의 표면·인증을 `pep`/`workload`로 바꾼다 (엔드포인트는 그대로) | **red** |
| 4.3 | `internal/runtime/wiring_test.go` `TestTheMountTableFileIsUpToDate` + 4.1의 테스트 | `CancellationPattern`의 경로를 `/cancellation` → `/cancel`로 바꾼다 | **red** (양쪽 다) |
| 4.4 | `internal/release/chart_test.go` `TestSplitIsNotAllInOneUnderFiveNames` | `_helpers.tpl`에서 `decide` 역할의 표면 목록에서 `pep`을 뺀 뒤 스냅샷을 다시 렌더한다 (#46 재현) | **red** |
| 4.5 | `internal/api/contract_test.go` `TestConsoleContractFileIsUpToDate` | `console/contract/public-endpoints.json`에서 `delay-cancel`을 지운다 | **red** |
| 4.6 | `internal/runtime/config_test.go` `TestAFeatureThatCompletesOnTheCallbackSurfaceNeedsItBound` 외 2건 | `Config.surfaceRequirements`에서 인제스트 자격증명 조건을 무력화한다 | **red** |
| 4.7 | `internal/runtime/config_test.go` `TestARoleThatMountsNoCallbackRouteIsNotRefused` | 같은 함수의 `roles.Has(RoleDecide)` 게이팅을 없앤다 | **red** |

**4.1 / 4.2** — 두 방향을 각각 잡는다. 행이 사라지면 "mounted and undocumented", 행이 틀리면 "drifted". 검사가 집합 비교이지 문자열 비교가 아니라는 것이 여기서 보인다.

```
--- FAIL: TestTheContractDocumentAndTheMountedRoutesAreTheSameSet
    routes_test.go:316: the decision API contract and the mounted routes disagree:
          mounted and undocumented: POST /decisions/{id}/challenges/{ordinal}/cancellation (console / user / decide) is served and the contract document does not list it
```

```
    routes_test.go:316: ...
          drifted: POST /decisions/{id}/challenges/{ordinal}/cancellation is documented as pep / workload / decide and mounted as console / user / decide
```

**4.3** — 코드가 먼저 바뀌는 방향. `mounted-routes.json`은 코드에서 유도되므로 먼저 stale이 되고, 그것을 갱신하면 계약 문서와 어긋난다. **두 단계가 다 걸리는 것**이 이 배치의 요점이다.

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

**4.4** — #46 그 자체다. 실물 차트를 고치고 `deploy/helm/render.sh`로 스냅샷을 다시 만든 뒤 실행했다. 즉 스냅샷을 손으로 건드린 것이 아니라 **차트가 실제로 그렇게 렌더되게** 했다.

```
--- FAIL: TestSplitIsNotAllInOneUnderFiveNames/each_tier_binds_exactly_the_surfaces_its_role's_routes_are_on
        chart_test.go:381: stamp-decide: the decide role mounts [GET /decisions/{id} POST /decisions] on the pep surface and this tier does not bind it: those routes are not refused there, they are unreachable
```

**4.6** — U2가 더한 축. 세 조건 중 하나만 빼도 세 테스트가 각각 다른 각도에서 red다. 마지막 것이 특히 중요하다 — **차트의 거부와 바이너리의 거부가 같은 설정을 잡는지**를 보는 오라클이라, 한쪽만 잡는 상태를 만들면 그것이 드러난다.

```
--- FAIL: TestAFeatureThatCompletesOnTheCallbackSurfaceNeedsItBound/http_velocity_ingest
        config_test.go:618: http velocity ingest with no callback listener was accepted: the route it completes on is mounted on a surface nothing binds
--- FAIL: TestTheRefusalNamesEveryStrandedSetting
    config_test.go:652: the refusal stops before naming STAMP_INGEST_CREDENTIALS: ...
--- FAIL: TestTheBinaryAndTheChartRefuseTheSameStrandedRelease
    config_test.go:823: the binary's refusal does not name STAMP_INGEST_CREDENTIALS: ...
    config_test.go:833: the binary's refusal does not name /ingest/v1/events, which is mounted on the callback surface and is therefore one of the things this process would have lost: ...
```

**4.7** — 반대 방향. 게이팅을 없애면 콜백 라우트를 마운트하지 않는 역할까지 거부되어, 검사가 **과하게 잡는 쪽으로** 틀렸을 때도 red가 난다.

```
--- FAIL: TestARoleThatMountsNoCallbackRouteIsNotRefused/console
        config_test.go:698: --roles=console mounts no callback route and was refused anyway: ...
--- FAIL: TestARoleThatMountsNoCallbackRouteIsNotRefused/consumer
        config_test.go:724: the consumer role was refused for STAMP_MFA_AUTHORIZATION_ENDPOINT, whose route only the decide role mounts: ...
```

---

## 5. 콘솔 — 스텁이 진실을 대신하는 자리

지난 라운드의 실제 사고가 여기서 났다. 콘솔 테스트가 **서버가 보내지 않는 코드**(`not_an_approver`, 그리고 409)를 스텁으로 시험하며 초록이었다. 픽스처가 서버를 대신하면 서버가 바뀌어도 테스트는 아무 말도 하지 않는다.

| # | 테스트 | 심은 결함 | 결과 |
|---|---|---|---|
| 5.1 | `console/src/inbox/inbox.test.tsx` 429 두 건 | `ApprovalScreen.failureOf`에서 `cause.isRateLimited \|\|`를 뺀다 (본문 코드로만 판정) | **살아남음 → 고침** (§5 고침 C) |
| 5.2 | 같은 두 건 | `\|\| body?.error === RATE_LIMITED`를 뺀다 (상태로만 판정) | **살아남음 → 뜻 있는 변형이 아님** (§6.2) |
| 5.3 | `console/src/inbox/inbox.test.tsx` `Retry-After` 두 건 | `client.ts`의 `retryAfterOf`가 언제나 `undefined` | **red** |
| 5.4 | `console/src/audit/audit.test.tsx` 감사자 거부 2건 | `AuditScreen`의 `setRefused(... isForbidden)`를 `setRefused(false)`로 | **red** |
| 5.5 | `internal/api/contract_test.go` (4.5와 같은 행) | 콘솔 계약 JSON에서 엔드포인트 하나를 지운다 | **red** |

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

### 콘솔 스텁과 서버의 대조 — 2026-08-12 시점

뮤테이션과 별개로, 콘솔이 스텁하는 모양이 **지금의 Go 핸들러가 실제로 내는 것**과 같은지 손으로 대조했다. 결과:

- **응답 필드는 일치한다.** `challenge.InboxItem`·`api.InboxResponse`·`challenge.QuorumReview`·`challenge.QuorumReviewDecision`·`decision.Result`·`decision.ChallengeView`·`api.AuditDecisionRow`/`Detail`/`ListResponse`/`AuditQueryEcho`/`AuditChallenge`/`AuditApproval`의 JSON 태그를 `console/src/inbox/api-types.ts`·`console/src/audit/api-types.ts`와 하나씩 맞췄고 어긋난 이름은 없다. `DECISION_STATES`도 `store.DecisionState` 다섯과 같다.
- **오류 코드도 일치한다.** 콘솔이 분기하거나 스텁하는 코드는 `not_found`·`expired`·`not_collecting`·`material_changed`·`rate_limited`·`not_an_auditor`·`invalid_policy`·`revision_pending`이고, 전부 오늘의 Go 핸들러가 내는 코드다(`approvals.go` `approvalError`, `auditconsole.go`, `dryrun.go`, `policies.go`). 지난 라운드가 죽인 `not_an_approver`는 콘솔에도 남아 있지 않다. `oidc.test.ts`의 `access_denied`는 서버 코드가 아니라 OAuth 오류 응답이므로 이 대조의 대상이 아니다.
- **콘솔이 아예 부르지 않는 표면이 하나 있다 — 취소.** `delay-cancel`은 `console/contract/public-endpoints.json`에 있지만 `src/` 어디에서도 `api.request('delay-cancel')`를 부르지 않는다. **U1이 이 표면에 429를 더했는데 콘솔에는 그것을 렌더할 화면이 없다.** 스텁이 서버와 어긋난 것은 아니다 — 화면이 없다. 이것은 이 유닛의 발견이지 결함 수정 대상이 아니므로 §7에 남긴다.
- **자동으로 지켜지는 것과 손으로 지켜지는 것을 구분해 둔다.** 엔드포인트의 **이름·메서드·경로**는 기계가 지킨다(`internal/api` → `console/contract/public-endpoints.json` 생성 + `check-contract.mjs`의 경계 검사, 4.5가 확인). **필드 이름과 오류 코드 어휘는 지키는 기계가 없다** — 위 대조는 사람이 한 것이고 오늘 날짜의 사실이다. 그것이 §7의 첫 항목이다.

### 살아남은 셋을 어떻게 고쳤는가

**고침 A — 취소 표면 (행 2.2)** — `internal/api/cancel_test.go`의 `TestACancellationOverTheBudgetNeverReachesTheLifecycle`에 단언을 하나 더했다. 파싱할 수 없는 ordinal을 예산 초과 상태에서 보내면 400이 아니라 429여야 한다. 부과가 `challengeRef` 뒤로 내려가면 이 요청만 답이 달라진다.

> U1의 보고는 이 자리를 "관찰 가능한 것이 바뀌지 않아 뜻 있는 변형이 아니다"로 적었다. 그것은 절반만 맞다 — 리프사이클에 닿는 횟수는 실제로 그대로다. 하지만 `challengeRef`는 실패할 수 있고(정수가 아닌 ordinal), 그때 예산 초과 호출자가 받는 답이 400과 429로 갈린다. 핸들러 주석이 약속한 것이 그 답이므로, 약속을 단언으로 옮겼다.

고친 뒤 같은 뮤테이션:

```
--- FAIL: TestACancellationOverTheBudgetNeverReachesTheLifecycle
    cancel_test.go:371: an unparseable path from an authority over its budget answered 400, want 429: the budget is charged before the path is parsed, so nothing about the request can buy a different answer
```

**고침 B — 승인 제출 (행 2.6)** — `internal/api/approvals_test.go`의 `TestSubmissionsAreRefusedOverTheApproverBudget`에 두 단언을 더했다. 파싱 불가 경로는 400이 아니라 429, `DefaultMaxApprovalBytes`를 넘는 본문은 413이 아니라 429. 핸들러 주석의 "before the path is parsed and before the body is read"가 이제 각각 하나씩 대응한다. 승인 제출은 취소와 달리 본문을 읽으므로 후자가 실재하는 비용이다.

고친 뒤 같은 뮤테이션:

```
--- FAIL: TestSubmissionsAreRefusedOverTheApproverBudget
    approvals_test.go:596: an unparseable path from an approver over its budget answered 400, want 429: the budget is charged before the path is parsed
    approvals_test.go:601: an oversized body from an approver over its budget answered 413, want 429: the budget is charged before the body is read, so the surface never reads 8193 bytes for a caller it has already refused
```

**고침 C — 콘솔의 429 (행 5.1)** — 기존 429 테스트 두 건은 **상태와 본문 코드를 동시에** 스텁한다. 그래서 `cause.isRateLimited || body?.error === RATE_LIMITED`의 어느 한쪽만 남겨도 초록이었다. 상태 쪽이 실제로 필요한 경우 — **콘솔과 엔진 사이의 중간자가 낸 429** — 를 시험하는 테스트가 없었다. `inbox.test.tsx`에 그 경우를 더했다: 본문이 이 API의 오류 어휘가 아닌 HTML인 429.

고친 뒤 같은 뮤테이션:

```
FAIL  src/inbox/inbox.test.tsx > 제출 실패 > 코드를 읽을 수 없는 429도 기다림으로 읽힌다 — 중간자가 흘린 경우
Expected element to have text content:
  기록되지 않았습니다
Received:
  요청이 429로 실패했습니다.문제가 계속되면 운영자에게 이 화면의 결정 식별자를 전달하십시오.
```

받은 문자열이 이 분기가 존재하는 이유 그 자체다: 시간이 지나면 풀리는 한도 앞에서 승인자를 운영자에게 보내는 문구.

---

## 6. 뜻 있는 변형을 만들 수 없었던 자리

여기 적는 것은 "테스트가 약하다"가 아니라 **"이 자리에서는 뮤테이션이 어느 쪽으로도 말하지 않는다"**이다. 표를 채우려고 약한 변형을 지어내면 그 행은 다음 사람을 속인다.

### 6.1 취소 제한기 키의 접두사

`cancel.go`는 `"canceller\x1f"+caller.CallerID()`로 부과한다. 접두사를 `"k:"`로 바꿔 `go test ./internal/api/`를 돌리면 **초록이다.**

그것이 결함이 아닌 이유: 이 제한기는 취소 전용이고 표에 다른 이름 공간이 들어오지 않는다. 접두사는 미래에 이 표를 공유하게 될 때를 위한 것이지 오늘 무엇을 막고 있지 않다. 오늘의 동작에 아무 차이가 없으므로 **테스트가 잡지 못하는 것이 맞다.** (`decide` 경로의 `\x1f`는 다르다 — 거기서는 두 이름 공간이 실제로 한 표에 있었고, 2.7이 그 자리를 잡는다.)

### 6.2 콘솔의 `body?.error === RATE_LIMITED` 절반 (5.2)

이 절반만 빼도 콘솔 스위트는 초록이고, **정직하게 red로 만들 수 없다.** 그러려면 429가 아닌 상태에 `rate_limited` 본문을 실은 응답을 스텁해야 하는데, 오늘의 서버는 그런 응답을 보내지 않는다(`approvals.go`·`cancel.go`·`ingest.go`·`authoring.go` 모두 429와 함께 낸다). 그 스텁을 쓰는 것은 **서버가 내지 않는 모양을 시험하는 일** — 이 유닛이 존재하는 이유인 바로 그 실패 양식이다.

그래서 그 분기는 남기되(중간자가 코드를 실어 보낼 가능성에 대한 방어이고 비용이 없다) 테스트로 고정하지 않는다. 덮지 않는 것을 여기 적는 편이 낫다.

### 6.3 `retryAfterSecondsFor`의 `d <= 0` 가지

`ratelimit.go`가 주석으로 "Not reachable from a refusal — an unlimited budget refuses nothing"이라고 이미 적었다. 도달할 수 없는 가지를 바꾸면 아무 테스트도 움직이지 않는다. 그것이 정상이다.

### 6.4 U4(CI 진단)와 U5(`CIBA.Poll` 삭제)

U4는 `.github/workflows/ci.yml`만 만진다. 유닛 테스트가 없는 층이라 여기서 심을 결함이 없다 — 그 유닛의 검증은 계획대로 **일부러 깨뜨린 실행을 한 번 보는 것**이다. U5는 코드를 지운 것이라 심을 자리가 없고, `go build`/`go vet`이 남은 참조를 잡는다.

---

## 7. 부팅 경합 — 확률적인 가드를 뮤테이션으로 재는 법

앞의 여섯 절과 성격이 다르다. 여기서 지키는 테스트(`TestMigrateSurvivesConcurrentBoot`)는 **확률적으로만 실패한다.** 그래서 "뮤테이션 후 red"라는 단언 자체를 회수와 함께 적어야 뜻이 있다.

### 7.1 짝지은 뮤테이션: advisory lock 제거 + SQLSTATE 셋 좁히기

| | |
|---|---|
| 심은 곳 | `internal/store/migrate.go` (실물) |
| 변형 A | `ensureVersionTable`의 `pg_advisory_xact_lock` 트랜잭션 제거 → 맨 `Exec` + 옛 재시도 |
| 변형 B | `isDuplicateObject`를 `42P07`/`23505`로 좁힘(`42710` 제거) |
| 결과 | **red** — `create schema_migrations: ERROR: type "schema_migrations" already exists (SQLSTATE 42710)` |
| 회수 | 130회 중 1회 실패 |

**두 변형을 함께 되돌려야 한다는 것이 이 행의 요점이다.** 락만 제거하면 넓혀 둔 `isDuplicateObject`가 `42710`을 흡수하고 재시도가 수렴해서 **빌드가 초록으로 남는다** — 뮤테이션이 아무것도 증명하지 못한다. 문서 리뷰가 이것을 잡았고, 잡히지 않았다면 이 표에 "확인함"이라고 적힌 거짓말이 남았을 것이다.

§8이 "뮤테이션은 한 번에 하나"라고 적어 둔 자리가 여기서 처음 문제가 됐다. 두 변경이 **서로를 가리는** 경우가 실재한다.

### 7.2 확률: 초록이 말하지 않는 것

미수정 동작으로 이 테스트를 **145회** 돌려 **2회** 실패했다(약 1.4%). 즉 고쳐지기 전에도 **이 테스트의 초록은 약 98.6%의 경우 아무 말도 하지 않았다.** 라운드 하나가 그 초록을 근거로 "부팅 경합 해결"이라고 선언했다.

그래서 이 라운드는 가드를 둘로 나눴다:

| 부분 | 무엇이 지키나 | 운에 기대나 |
|---|---|---|
| 어느 SQLSTATE를 견디는가 | `duplicateobject_test.go` — 실물 함수에 실물 `*pgconn.PgError` | 아니오 |
| 경합에서 부팅이 살아남는가 | `TestMigrateSurvivesConcurrentBoot` | 예 — 그래서 배리어를 붙였다 |

배리어는 동시에 `Migrate` 안에 있던 부트 수의 최고치를 재고, **1이면 실패한다.** 직렬화된 실행이 조용히 통과하던 것이 이 라운드가 닫은 자리다.

### 7.3 `42501`을 거짓으로 답하는 것이 왜 이 표에 있나

`isDuplicateObject`를 SQLSTATE **클래스** 매칭으로 "단순화"하는 것은 diff로 보면 개선처럼 보인다. 클래스 42에는 `42501 insufficient_privilege`가 있으므로, 그 변경은 **최소 권한 배포에서 권한 거부를 "이미 있다"로 읽고 부팅을 성공시킨다.**

`TestIsDuplicateObjectRefusesCodes`가 그 변경에서 red가 된다. 이 행은 결함을 잡은 기록이 아니라 **앞으로 올 그럴듯한 변경을 막는 기록**이다.

---

## 8. 이 표가 덮지 않는 것

- **콘솔의 응답 타입과 오류 어휘를 서버에 묶는 기계가 없다.** §5의 대조는 사람이 2026-08-12에 한 것이다. 엔드포인트 이름·메서드·경로는 생성과 경계 검사로 지켜지지만, `api-types.ts`의 필드 이름과 화면이 분기하는 `error` 코드는 손으로 맞춰 둔 거울이다. 지난 라운드의 사고가 정확히 이 층에서 났으므로 **다음 라운드가 가장 먼저 볼 자리다.**
- **취소 표면에 콘솔 화면이 없다.** `delay-cancel`은 공개 계약에 있고 서버는 429·`Retry-After`·감사까지 갖췄는데 부르는 화면이 없다. 콘솔이 그 표면을 열 때 429 렌더링을 함께 가져와야 하고, 그때 `failureOf`의 문구가 승인 제출과 같아도 되는지가 판단할 거리다(취소는 "이 승인은 기록되지 않았습니다"가 맞는 문장이 아니다).
- ~~**뮤테이션은 한 번에 하나다.**~~ §7.1이 이 공백을 처음 메웠다 — 두 변경이 서로를 가리는 경우가 **실재한다**. 나머지 절(§1–§6)은 여전히 한 번에 하나이므로, 거기서도 짝이 서로를 가리는지는 아직 모른다.
- **성능·경합은 대상이 아니다.** 예산이 *늦게* 걸리는 것은 2.1·2.5·2.9가 잡지만, 그 비용이 실제로 얼마인지는 이 표가 말하지 않는다.
- **`internal/api` 밖의 감사 체인 자체**(gap marker, 체크포인트 서명)는 이번 대상에 넣지 않았다. PR #51이 크게 건드린 곳이 아니다.
