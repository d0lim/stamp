---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
type: fix
title: "fix: 서버가 낼 수 있는 코드와 콘솔이 분기하는 코드를 기계가 대조한다"
date: 2026-08-12
origin: docs/testing/mutation-matrix.md
product_contract_source: legacy-requirements
decisions: docs/decisions/stamp-decision-log.md
---

# fix: 서버가 낼 수 있는 코드와 콘솔이 분기하는 코드를 기계가 대조한다

> **정본 관계.** 제품 요구(R-ID)의 정본은 `docs/plans/2026-08-07-001-feat-stamp-feature-map-plan.md`. 이 문서는 새 요구를 만들지 않는다 — 이미 있는 계약을 강제할 뿐이다.

---

## Goal Capsule

**엔드포인트는 기계가 강제하고 `error` 코드 어휘는 강제하지 않는다.** 그 비강제 층에서 실제 사고가 났다: PR #51이 `403 not_an_approver`를 없앴는데 콘솔은 그 코드를 계속 분기했고, **콘솔 테스트가 응답을 스텁하기 때문에 초록이었다.**

정확히 말하면 문제는 타입이 아니다. 사고 당시 콘솔의 TypeScript는 **자기 안에서는 정합했다** — 서버가 더 이상 내지 않는 코드를 분기했을 뿐이다. 타입 생성은 이것을 잡지 못한다. 잡는 것은 **집합 차이**다:

- 콘솔이 분기하는데 **서버가 낼 수 없는** 코드 → 죽은 분기(이번 사고)
- 서버가 내는데 **콘솔에 처리가 없는** 코드 → 일반 문구로 떨어짐(U1의 새 429가 정확히 이랬다)

닫는 것 하나: **두 방향의 차이가 CI에서 빨개진다.**

---

## Problem Frame

### 기존 관례는 라우트에만 적용돼 있다

이 리포는 이미 자기만의 계약 강제 관례를 갖는다. `internal/runtime/wiring_test.go`가 조립된 레지스트리에서 마운트된 라우트를 **추적되는 JSON 아티팩트**(`internal/release/testdata/mounted-routes.json`)로 렌더하고, `internal/release/routes_test.go`가 그것을 계약 문서의 엔드포인트 표와 대조한다. 드리프트가 나면 CI가 빨개진다.

**그 관례가 `error` 코드에는 적용돼 있지 않다.**

### 방출 표면이 한곳에 열거돼 있지 않다

`writeError(...)` 호출만 세어도 `internal/api/`에 **서로 다른 코드 28개**가 있다. 그런데 그것이 전부가 아니다 — `approvalError`·`auditReadError`·`decisionError`·`mfaError`는 코드를 **반환값**으로 돌려주므로 호출 지점의 리터럴로는 보이지 않는다.

즉 "이 서버가 낼 수 있는 코드"를 지금 아무도 한 곳에서 말할 수 없다. 그것이 대조가 불가능한 이유다.

### 사람이 한 번 대조했고, 그것으로는 부족하다

직전 라운드의 U3 뮤테이션 감사가 양쪽을 **손으로** 대조해 2026-08-12 기준 일치를 확인했다. 그 보고 자신이 한계를 적었다: *"엔드포인트 이름·메서드·경로는 기계가 강제한다. 필드명과 error 코드 어휘는 아니다."* 사람의 대조는 그 날짜에만 참이다.

---

## Requirements

| R-ID | 요구 | 닫는 유닛 |
|---|---|---|
| **R11** | 공개 계약 3종이 semver로 관리되고 릴리즈가 검사한다 | U1, U2 |
| **R2** | 결정 객체가 상태·challenge 수집 현황·만료·obligation을 노출한다 | U3 |

새 요구는 없다.

---

## Key Technical Decisions

### KTD1. 타입 생성이 아니라 집합 대조다

사고 당시 콘솔의 타입은 정합했다. 생성된 타입은 **필드의 모양**을 맞추지 코드 **어휘의 존재**를 맞추지 않는다. 실제로 어긋난 축을 강제하지 않는 도구를 들이는 것은 가드가 있다는 착각만 산다.

**기각**: `tygo`/`openapi-typescript` 등 타입 생성. 이 사고를 잡지 못하고, 빌드 파이프라인에 도구를 하나 더한다.
**기각**: Pact 계열 consumer-driven contract testing. 실행 중인 양쪽이 필요하고, 이 리포가 이미 갖고 있는 것보다 훨씬 무겁다.

### KTD2. 방출 표면은 손으로 적지 않고 코드에서 유도한다

손으로 적은 목록은 **자기가 지키려는 것과 함께 틀린다** — 이 세션이 `chart_test.go`의 손으로 쓴 역할→표면 map에서 정확히 그것을 봤다(차트와 함께 틀려 있었다).

그래서 Go 쪽 목록은 상수 선언에서 유도하거나 테스트가 렌더한다. `mounted-routes.json`이 조립된 레지스트리에서 나오는 것과 같은 이유다.

### KTD3. 양방향을 다르게 취급한다

- **콘솔이 분기하는데 서버가 못 냄** → 실패. 죽은 분기이고 이번 사고다.
- **서버가 내는데 콘솔에 처리 없음** → 실패하되 **명시적 면제 목록**을 갖는다. 콘솔이 닿지 않는 표면(인제스트, 부트스트랩)의 코드까지 콘솔이 처리할 이유는 없다. 면제는 파일에 이름과 이유를 적고, 그 목록 자체가 리뷰 대상이 된다.

면제 없이 만들면 개발자가 검사를 끄게 되고, 그러면 가드가 아니라 소음이다.

---

## Implementation Units

### U1. 서버가 낼 수 있는 코드가 한 곳에서 말해진다

- **Goal:** `error` 코드 방출 표면을 추적되는 아티팩트로 만든다. `mounted-routes.json`의 자매.
- **Requirements:** R11.
- **Dependencies:** 없음.
- **Files:** `internal/api/` (코드 상수 정리), `internal/api/errorcodes_test.go`(신규), `internal/release/testdata/error-codes.json`(신규, 생성물), `internal/release/errorcodes_test.go`(신규).
- **Approach:**
  1. **먼저 실제 방출 표면을 찾아라.** `writeError` 호출의 리터럴만으로는 부족하다 — `approvalError`·`auditReadError`·`decisionError`·`mfaError`는 코드를 반환한다. 네 테이블을 모두 읽어라.
  2. 코드를 **명명된 상수**로 만들고(이미 `CodeNotInstalled`·`ApprovalRateLimitedCode` 선례가 있다), 표면·HTTP 상태와 함께 아티팩트로 렌더한다.
  3. 렌더는 `internal/runtime/wiring_test.go`가 `mounted-routes.json`을 쓰는 방식을 따른다 — **stale하면 다시 쓰고 실패한다.**
  4. **tripwire를 넣어라.** 아티팩트가 비거나 어느 표면이 코드를 전부 잃으면 실패한다. 생성기가 조용히 꺼지는 것이 이 부류의 실패 양식이다.
- **Execution note:** 아티팩트를 만든 뒤 **현재 트리에서 무엇이 드러나는지 보라.** 손으로 센 28개와 다르면 그 차이가 이 유닛의 첫 발견이다.
- **Test scenarios:**
  - 아티팩트가 stale하면 재생성되고 테스트가 한 번 실패한다.
  - 재생성이 바이트 동일하게 복원된다.
  - 코드를 하나 더하면 아티팩트가 바뀐다.
  - 어느 표면이 코드를 전부 잃으면 tripwire가 실패한다.
- **Verification:** `go test ./internal/api/ ./internal/release/` 통과. 아티팩트가 커밋돼 있다.

### U2. 콘솔이 분기하는 코드가 서버의 것과 대조된다

- **Goal:** 두 방향의 집합 차이가 CI에서 빨개진다. **자기 검사를 갖는다.**
- **Requirements:** R11.
- **Dependencies:** U1.
- **Files:** `console/contract/error-codes.json`(U1의 아티팩트에서 복사되거나 참조), `console/scripts/check-contract.*`(기존 `check:contract` 확장), `console/src/**`(코드 어휘를 한 곳에 모아야 한다면), 대응 테스트.
- **Approach:**
  1. 콘솔이 분기하는 코드를 **한 곳에서 열거 가능하게** 만든다. 지금은 `FAILURES` map과 `ApiError` 분기에 흩어져 있다. 흩어진 채로 두면 검사가 grep이 되고, grep은 문자열 리터럴과 주석에서 오탐한다.
  2. `npm run check:contract`를 확장해 양방향 차이를 낸다(KTD3의 비대칭 규칙대로).
  3. **면제 목록**은 파일에 이름과 이유를 적는다. 면제가 늘어나는 것 자체가 신호가 되도록.
  4. **자기 검사**: 콘솔에 죽은 코드를 심으면 실패하고, 서버에 콘솔이 모르는 코드를 더해도 실패한다. 픽스처가 아니라 **실물**에 심어서 확인하라 — 이 세션이 모든 새 검사를 그렇게 확인했다.
- **Execution note:** 검사를 세운 뒤 **현재 트리에서 무엇이 잡히는지 먼저 보라.** U3의 손 대조가 일치를 주장했으므로 아무것도 안 잡히는 것이 정상이다. 그런데 잡히면 그것이 발견이다.
- **Test scenarios:**
  - 콘솔에만 있는 코드를 심으면 실패하고 그 코드를 이름한다.
  - 서버에만 있는 코드를 더하면 실패한다(면제 목록에 없는 한).
  - 면제 목록의 코드는 실패시키지 않는다.
  - 현행 트리에서 검사가 통과한다.
  - **자기 검사 둘이 심어둔 드리프트에서 실제로 실패한다.**
- **Verification:** `npm --prefix console test` 통과, `make land` 그린. CI가 이 검사를 포함한다.

### U3. `delay-cancel`의 계약과 구현을 일치시킨다

- **Goal:** 공개 계약에 있는데 콘솔 화면이 전혀 없는 상태를 끝낸다.
- **Requirements:** R2.
- **Dependencies:** 없음.
- **Files:** `docs/contracts/decision-api.md`, 그리고 선택에 따라 `console/src/`.
- **Approach:**
  1. **판단은 최소 목표 기준이다.** 화면을 만드는 것은 새 기능이고 이 라운드의 목표가 아니다. **계약 문서가 그 표면에 콘솔 구현이 없음을 명시하는 것**이 최소 답이다 — 계약에서 빼는 것은 API를 바꾸는 일이라 범위 밖이고, 화면을 만드는 것은 gold-plating이다.
  2. 다만 **U1이 만든 429가 렌더될 곳이 없다는 사실**은 문서에 남아야 한다. 그것이 다음 라운드의 입력이다.
  3. U2의 면제 목록과 일관되게: 콘솔이 닿지 않는 표면임을 두 곳이 같은 이유로 말해야 한다.
- **Execution note:** 이 유닛은 코드보다 판단이다. 화면을 만들고 싶어지면 그것이 gold-plating 신호다.
- **Test scenarios:**
  - 계약 문서가 이 표면의 콘솔 미구현을 명시한다.
  - U2의 면제 목록과 문서가 어긋나지 않는다.
  - `Test expectation: none` — 동작 변경이 없다(문서와 면제 목록만).
- **Verification:** `scripts/check-contract-versions.sh` 통과. 버전이 문서 자신의 규칙대로 오른다.

---

## Verification Contract

| 게이트 | 적용 |
|---|---|
| `make land` | 전 유닛 |
| `npm --prefix console test` · `run build` · `check:contract` | U2, U3 |
| **양방향 코드 대조가 심어둔 드리프트에서 실패** | U2 |
| 계약 버전 게이트 | U3 |

---

## Definition of Done

1. **서버가 낼 수 있는 `error` 코드가 코드에서 유도된 추적 아티팩트로 존재한다.**
2. **콘솔이 분기하는 코드와 그 아티팩트의 차이가 양방향으로 CI에서 빨개진다.**
3. **두 검사 모두 자기 검사를 갖고, 실물에 심은 드리프트에서 실제로 실패하는 것이 확인됐다.**
4. `delay-cancel`의 콘솔 미구현이 계약 문서에 명시돼 있다.
5. `make land`와 콘솔 스위트가 그린.

2번과 3번이 실질적 완료 조건이다.

---

## Scope Boundaries

### 하지 않는 것

- **타입 생성 도구를 들이지 않는다**(KTD1) — 이 사고를 잡지 못한다.
- **API를 바꾸지 않는다.** 코드 어휘를 정리하되 와이어에 나가는 문자열은 그대로다.
- **`delay-cancel` 화면을 만들지 않는다** — 새 기능이고 최소 목표 밖이다.
- **필드명 대조는 이번 범위가 아니다.** 사고가 난 축은 코드 어휘다. 필드명까지 넓히면 이 라운드가 타입 생성 논의로 되돌아간다.

### 이연

- **필드명(JSON 태그) 대조** — 다음 라운드의 후보. U3의 손 대조가 지금은 일치한다고 확인했다.
- **`delay-cancel` 화면** — 계약에 있는 표면이므로 언젠가는 필요하다.
