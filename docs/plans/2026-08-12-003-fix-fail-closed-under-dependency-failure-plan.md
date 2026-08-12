---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
type: fix
title: "fix: 의존성이 죽었을 때 fail-closed임을 증명한다"
date: 2026-08-12
origin: docs/testing/mutation-matrix.md
product_contract_source: legacy-requirements
decisions: docs/decisions/stamp-decision-log.md
---

# fix: 의존성이 죽었을 때 fail-closed임을 증명한다

---

## Goal Capsule

인가 엔진의 신뢰도는 **동작할 때**가 아니라 **의존성이 죽었을 때** 결정된다. 데이터베이스가 사라지거나 IdP가 응답하지 않을 때 이 시스템이 **거부**하는지 **허용**하는지가 제품의 전부다.

지금 그것을 증명하는 테스트가 없다.

이 세션은 부팅 경합 둘을 찾았지만 **CI가 우연히 실패했기 때문에** 찾았다 — 로컬 재현 세 번이 실패했다. 그 부류가 더 있는지 아무도 모른다. 그리고 U8이 남긴 공백: 제한기 표 둘이 동시에 충전될 때를 확인하는 테스트가 없고, `-race`가 우연히 스친 것이 전부다.

닫는 것 하나: **의존성 실패마다 관찰된 답이 있고, 그 답이 "거부"임이 테스트로 고정된다.**

---

## Problem Frame

### 부팅은 이제 검증됐지만 런타임은 아니다

직전 라운드가 부팅 경합을 고쳤다 — `apply grants`의 role 생성 경합과 `Driver.Lock`이 패자를 죽이던 것. 둘 다 실제 결함이었고 둘 다 **테스트가 아니라 CI 사고로** 드러났다.

부팅 이후는 여전히 미검증이다. `decide`는 데이터베이스에 쓰고, step-up은 IdP를 부르고, 감사는 체인에 append한다. **그중 하나가 사라지면 무슨 일이 나는가**를 단언하는 테스트가 없다.

### 인가 엔진에서 이것은 부차적이지 않다

`check()`가 데이터베이스를 잃었을 때 **마지막으로 알던 정책으로 허용**한다면 그것은 가용성이 아니라 **보안 결함**이다. 반대로 감사가 실패했을 때 결정을 거부하는지 아닌지는 R32·R42가 이미 입장을 갖고 있다(`STAMP_AUDIT_FAIL_CLOSED` 기본 on).

즉 **정책은 이미 있다.** 없는 것은 그 정책이 실제로 지켜진다는 증거다.

### U8이 남긴 구체적 공백

> 두 표 사이의 동시성은 `-race`가 우연히 스친 것 말고 전용 테스트가 없다.

제한기는 R43의 집행 지점이다. 두 표가 동시 충전에서 어긋나면 예산이 새고, 예산이 새면 R43이 문서상으로만 참이 된다.

---

## Requirements

| R-ID | 요구 | 닫는 유닛 |
|---|---|---|
| **R43** | 속도 제한과 미결 상한, 초과는 deny와 감사 | U2 |
| **R32** | 감사 유실 구간 마커와 운영자 경보 | U1 |
| **R42** | 비밀은 필요 없는 곳에 존재하지 않는다 | U1(회귀 방지) |

새 요구는 없다. **이미 선언된 fail-closed 정책을 증명한다.**

---

## Key Technical Decisions

### KTD1. 의존성을 죽이는 방법은 실물이다

testcontainers가 이미 실제 PostgreSQL을 띄운다. **컨테이너를 멈추는 것**이 목 객체보다 정직하다 — 목은 우리가 상상한 실패를 재현하고, 실물은 실제로 일어나는 실패를 재현한다.

**기각**: 데이터베이스 인터페이스에 실패 주입 목을 넣는 안. 연결 풀·재시도·컨텍스트 만료의 실제 상호작용을 건너뛴다.

### KTD2. 각 실패는 "무엇을 답했는가"로 단언한다

"에러가 났다"가 아니라 **"거부했다"** 여야 한다. 인가 엔진에서 예외와 허용은 다르지만, 예외가 상위에서 허용으로 번역되면 같아진다. 그래서 단언은 **호출자가 실제로 받은 답**에 건다.

### KTD3. 이 라운드는 동작을 바꾸지 않는다 — 발견하면 보고한다

목표는 증명이지 수정이 아니다. **fail-open이 발견되면 그것이 이 라운드의 산출물**이고, 고치는 것은 그 발견의 크기를 보고 판단한다. 미리 고칠 계획을 세우면 발견을 수정에 맞추게 된다.

---

## Implementation Units

### U1. 데이터베이스가 사라지면 거부한다

- **Goal:** 런타임 중 PostgreSQL 상실에 대한 각 표면의 답을 관찰하고 고정한다.
- **Requirements:** R32, R42.
- **Dependencies:** 없음.
- **Files:** `internal/runtime/failure_test.go`(신규), 필요 시 `docs/` 기록.
- **Approach:**
  1. `internal/runtime`의 기존 하니스(`freshDB`, `newHarness`)로 프로세스를 조립한 뒤 **컨테이너를 멈춘다**(KTD1).
  2. 각 표면에 대해 **호출자가 받은 답**을 기록한다: `check()`, `POST /decisions`, 승인 제출, 감사 조회, `/healthz`, `/readyz`.
  3. **기대를 미리 적지 말고 관찰부터 하라.** 관찰한 것을 표로 만들고, 그 표에서 fail-open이 하나라도 보이면 그것이 발견이다.
  4. `STAMP_AUDIT_FAIL_CLOSED`가 기본 on이므로 감사 포화 시 deny가 이미 정책이다 — 그것이 실제로 그런지 확인한다.
- **Execution note:** 단언을 먼저 쓰지 말고 **관찰을 먼저 하라.** 이 유닛의 가치는 우리가 믿는 것이 아니라 실제로 일어나는 것을 적는 데 있다.
- **Test scenarios:**
  - 데이터베이스 상실 중 `check()`가 허용을 내지 않는다.
  - `POST /decisions`가 결정을 만들지 않고 거부한다.
  - `/readyz`가 503이 된다(`/healthz`와의 차이도 함께 고정).
  - 데이터베이스가 돌아오면 각 표면이 회복된다 — 영구 고장이 아니다.
  - 관찰된 답의 표가 문서로 커밋된다.
- **Verification:** `go test -race ./internal/runtime/` 통과. 표가 커밋돼 있다.

### U2. 제한기 두 표가 동시 충전에서 어긋나지 않는다

- **Goal:** U8이 명시한 공백을 닫는다. R43의 집행 지점이 동시성에서 정확한지 고정한다.
- **Requirements:** R43.
- **Dependencies:** 없음.
- **Files:** `internal/api/ratelimit_test.go`, `internal/stream/ingest_test.go`.
- **Approach:**
  1. 호출자 표와 주체 표를 **동시에** 충전하는 테스트를 쓴다. `-race`로 돈다.
  2. 예산의 **정확성**을 단언한다: N개의 동시 충전 뒤 허용된 수가 정확히 예산과 같다(초과도, 미달도 아니다).
  3. `stream.Limiter`의 `AllowAt`가 여러 고루틴에서 서로 다른 `now`로 불릴 때 버킷이 손상되지 않는 것을 확인한다 — 직전 라운드가 `ClockedLimiter`를 지우고 시각을 인자로 옮겼으므로 그 경로가 새롭다.
- **Execution note:** 동시성 테스트는 우연히 통과하기 쉽다. **경합이 실제로 일어나는지** 확인하라 — 순차 실행으로도 통과하는 테스트는 동시성을 시험하지 않는다.
- **Test scenarios:**
  - 두 표를 동시에 채워도 각자의 예산이 정확하다.
  - 같은 키에 대한 동시 충전이 예산을 초과 허용하지 않는다.
  - 서로 다른 `now`로 동시 호출해도 버킷이 손상되지 않는다.
  - `-race`가 깨끗하다.
- **Verification:** `go test -race -count=10 ./internal/api/ ./internal/stream/` 통과.

### U3. 관찰된 실패 동작이 문서가 된다

- **Goal:** U1이 관찰한 것을 운영자가 읽을 수 있는 곳에 둔다.
- **Requirements:** R32.
- **Dependencies:** U1, U2.
- **Files:** `docs/operations/failure-modes.md`(신규 또는 기존 문서에 절 추가).
- **Approach:**
  1. U1의 표를 운영자 언어로 옮긴다 — 무엇이 죽으면 무엇이 거부되는가.
  2. **테스트가 문서의 근거임을 적는다.** 문서가 주장하고 테스트가 지키는 관계를 명시해야 다음에 어긋나면 알 수 있다.
  3. 발견된 fail-open이 있으면 **그것도 적는다.** 고치지 않기로 했다면 이유와 함께.
- **Test scenarios:** `Test expectation: none` — 문서만.
- **Verification:** 문서의 각 주장이 U1의 테스트 이름을 인용한다.

---

## Verification Contract

| 게이트 | 적용 |
|---|---|
| `make land` | 전 유닛 |
| `go test -race -count=10` (동시성) | U2 |
| 관찰 표가 커밋됨 | U1, U3 |

---

## Definition of Done

1. **의존성 실패마다 관찰된 답이 테스트로 고정돼 있다.**
2. 제한기 두 표의 동시성이 전용 테스트를 갖는다.
3. 운영자가 읽을 수 있는 실패 모드 문서가 있고, 각 주장이 테스트를 인용한다.
4. **fail-open이 발견됐다면 보고돼 있다** — 고쳤든 안 고쳤든.

---

## Scope Boundaries

### 하지 않는 것

- **동작을 바꾸지 않는다**(KTD3). 발견이 목표다.
- **IdP 실패는 이번 범위가 아니다** — step-up은 이미 fail-closed로 설계됐고(`acr` 검증), 그 경로는 U2/U3이 데모로 검증했다. 데이터베이스가 더 근본적이다.
- **혼돈 공학 도구를 들이지 않는다.** testcontainers를 멈추는 것으로 충분하다.

### 이연

- IdP·Kafka 실패 경로
- 부분 네트워크 분할
- 감사 체인 손상 시 복구 절차
