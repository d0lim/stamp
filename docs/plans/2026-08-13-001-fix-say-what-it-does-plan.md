---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
type: fix
title: "fix: 시스템이 하는 말과 하는 일을 일치시킨다"
date: 2026-08-13
origin: docs/operations/failure-modes.md
product_contract_source: legacy-requirements
decisions: docs/decisions/stamp-decision-log.md
---

# fix: 시스템이 하는 말과 하는 일을 일치시킨다

---

## Goal Capsule

라운드 2가 fail-open 둘을 **측정**했다. 둘 다 같은 부류다 — **시스템이 자기에 대해 하는 말과 실제로 하는 일이 어긋나 있다.**

그런데 고치는 방향이 서로 **반대**다. 그것이 이 라운드의 핵심 판단이다.

| 발견 | 의도 | 실제 | 무엇을 고치나 |
|---|---|---|---|
| `/readyz`가 DB 없이 200 | `readiness.go` 주석: "닿을 수 없는 DB는 unready" | latch 후 영원히 ready | **코드** — 의도가 옳다 |
| check가 flush 간격 동안 감사 없는 allow | `STAMP_AUDIT_FAIL_CLOSED` 기본 on | ~1초어치 allow가 체인에 없음 | **약속** — 거래가 옳다 |

첫째는 **파드가 서빙할 수 없는데 Service에 남는다.** 인가 엔진에서 이것은 가용성 문제가 아니라 트래픽이 죽은 파드로 계속 가는 문제다.

둘째는 R32가 **의도적으로** 처리량과 맞바꾼 것이다. 판정마다 동기 append를 넣는 것은 그 거래를 뒤집는 일이고, 이 라운드의 범위가 아니다. 대신 **약속을 측정된 실제에 맞춘다.**

닫는 것 하나: **`docs/operations/failure-modes.md`의 모든 주장이 참이고, 참임을 지키는 테스트가 있다.**

---

## Problem Frame

### `/readyz`는 한 번만 참이다

게이트가 **첫 성공에서 latch**한다. 라운드 2의 테스트 첫 판이 503을 단언했다가 실패했고 — 프로세스가 살아있는 동안 `/readyz`를 한 번도 찌르지 않았기 때문이다. kubelet이 하는 대로 baseline probe(`initialDelaySeconds: 2, periodSeconds: 5`)를 넣자 **200으로 뒤집혔다.**

`readiness.go`의 닫는 문단은 *"닿을 수 없는 데이터베이스는 ready가 아니라 unready로 보고된다"* 고 말한다. 그 문장은 게이트가 열리기 **전에만** 참이다.

latch에는 이유가 있었다 — 스키마가 도착했는지를 파드 수명 내내 초당 질의하지 않기 위해서다. **그래서 latch를 그냥 걷어내는 것은 답이 아니다.** 힘들어하는 데이터베이스를 readiness probe가 두들기면 그 자체가 장애다.

**진짜 질문은 "latch를 없앨까"가 아니라 "무엇을 근거로 unready로 되돌아갈 것인가"다.**

### 감사 창은 실재하고, 측정됐고, 거래된 것이다

감사 버퍼가 비동기라 체인이 사라진 것을 **flush가 실패할 때** 안다. 50 ms 간격에서 6–48 ms 동안 2~56개의 allow가 측정됐다. `DefaultAuditFlushInterval`이 1초이므로 배포는 약 1초어치를 낸다.

조용하지는 않다 — gap 마커가 남고 `Alerting:true`이며 복구 후 `Gaps:1`이다. 그러나 **"fail closed"라는 이름은 "체인에 없는 allow는 나가지 않는다"로 읽힌다.** 그 읽기가 틀렸다는 것이 이제 측정됐다.

---

## Requirements

| R-ID | 요구 | 닫는 유닛 |
|---|---|---|
| **R32** | 감사 유실 구간 마커와 운영자 경보 | U2 |
| **R39** | 표면 분리 — 어느 프로세스가 트래픽을 받을지 | U1 |

새 요구는 없다.

---

## Key Technical Decisions

### KTD1. latch를 없애지 않고 **되돌아갈 근거**를 만든다

`/readyz`가 매 probe마다 데이터베이스를 질의하면, 데이터베이스가 힘들 때 readiness가 부하를 더한다. 그것은 지금 문제를 다른 문제로 바꾸는 것이다.

대신 **이미 관찰된 실패를 근거로 삼는다.** 프로세스는 요청을 처리하다가 데이터베이스 실패를 이미 본다 — 그 관찰이 게이트를 다시 닫게 한다. 관찰이 없으면 질의도 없다.

**기각**: 매 probe마다 질의 — 아픈 데이터베이스를 두들긴다.
**기각**: latch 유지 + 주석만 수정 — 파드가 서빙 못 하면서 Service에 남는 것이 실제 문제이고, 주석은 증상이 아니라 기록일 뿐이다.

### KTD2. 감사 창은 **약속을 고친다**, 코드가 아니라

R32가 비동기 버퍼를 고른 것은 판정 경로의 비용 때문이다. 동기 append는 그 거래를 뒤집고, `check()`는 이 시스템에서 가장 뜨거운 경로다.

**측정된 창을 문서와 이름이 정직하게 말하게 한다.** "fail closed"가 무엇을 보장하고 무엇을 보장하지 않는지를 적고, **그 창의 크기를 테스트가 고정한다** — 창이 조용히 넓어지면 빨개지도록.

**기각**: 판정마다 동기 append — R32의 거래를 이 라운드가 일방적으로 뒤집는다.
**기각**: 그냥 두기 — 이름이 약속하는 것과 하는 일이 다른 채로 남는다.

---

## Implementation Units

### U1. 데이터베이스를 잃은 파드가 Service에서 빠진다

- **Goal:** `/readyz`가 latch 이후에도 관찰된 데이터베이스 실패에 반응한다.
- **Requirements:** R39.
- **Dependencies:** 없음.
- **Files:** `internal/runtime/readiness.go`, `internal/runtime/readiness_test.go`, `internal/runtime/failure_test.go`(기존 관찰 테스트 갱신), `docs/operations/failure-modes.md`.
- **Approach:**
  1. **먼저 `readiness.go`를 통째로 읽어라.** latch의 이유가 주석에 있다 — 그것을 없애는 것이 아니라 되돌아갈 경로를 더하는 것이다(KTD1).
  2. 프로세스가 요청 처리 중 이미 보는 데이터베이스 실패를 게이트가 **알 수 있게** 한다. 새 폴링을 만들지 마라.
  3. **되돌아간 뒤 회복도 되어야 한다.** 라운드 2가 데이터베이스 복귀 후 각 표면이 132 ms/29 ms 안에 회복하는 것을 측정했다 — `/readyz`도 그래야 한다. 영구 unready는 그 자체로 장애다.
  4. **플래핑을 판단하라.** 한 번의 일시적 실패가 파드를 Service에서 빼는 것이 맞는지, 임계가 필요한지. 판단하고 근거를 주석에 적어라.
  5. `readiness.go`의 닫는 문단을 **이제 참인 문장**으로 고친다.
- **Execution note:** 라운드 2의 `failure_test.go`가 지금 `/readyz` → 200을 단언한다. **그 단언이 빨개지는 것**이 이 유닛의 red다 — 관찰을 기록한 테스트가 의도로 바뀌는 순간이다.
- **Test scenarios:**
  - baseline probe로 게이트를 연 뒤 데이터베이스를 멈추면 `/readyz`가 503이 된다.
  - 데이터베이스가 돌아오면 `/readyz`가 다시 200이 된다.
  - `/healthz`는 두 경우 모두 200이다 — liveness가 파드를 재시작시키면 안 된다.
  - 스키마가 아직 안 왔을 때의 기존 동작(롤아웃 순서 보호)이 바뀌지 않는다.
  - 데이터베이스가 건강한 동안에는 게이트가 추가 질의를 하지 않는다.
- **Verification:** `go test -race ./internal/runtime/` 통과. `make land` 그린.

### U2. "fail closed"가 무엇을 보장하는지 정확히 말한다

- **Goal:** 측정된 감사 창을 이름과 문서가 정직하게 말하고, 창의 크기를 테스트가 고정한다.
- **Requirements:** R32.
- **Dependencies:** 없음.
- **Files:** `internal/api/audit.go`(주석), `internal/runtime/failure_test.go`, `docs/operations/failure-modes.md`, `README.md`(`STAMP_AUDIT_FAIL_CLOSED` 행).
- **Approach:**
  1. `STAMP_AUDIT_FAIL_CLOSED`가 보장하는 것과 **보장하지 않는 것**을 적는다: 체인이 사라진 것을 **감지한 뒤**로는 거부한다. 감지 이전의 한 flush 간격은 통과하고, 그것은 gap 마커로 남는다.
  2. **창의 크기를 테스트가 고정한다.** 지금 측정된 것은 flush 간격에 비례한다. 그 관계가 깨지면(창이 간격보다 길어지면) 빨개져야 한다.
  3. 이름을 바꿀지 판단하라. `FAIL_CLOSED`가 오해를 부른다면 무엇이 정확한지 — 다만 **환경 변수 이름 변경은 배포 호환성 문제**이므로 문서로 충분한지 먼저 판단하고, 바꾸지 않기로 했다면 이유를 적어라.
  4. 라운드 2가 1초 프로덕션 간격에서는 측정하지 않았다고 적었다. **가능하면 측정해서 선형 예측을 확인하라.** 못 하면 그대로 남긴다.
- **Execution note:** 이 유닛은 코드가 아니라 주장을 고친다. **문서가 코드보다 강한 약속을 하고 있지 않은지**가 판정 기준이다.
- **Test scenarios:**
  - 감사 체인 상실 후 감지되면 이후 판정이 거부된다(기존 정책 확인).
  - 감지 이전 창의 크기가 flush 간격에 비례한다 — 넘으면 실패.
  - gap 마커와 `Alerting`이 창 이후에 실제로 선다.
  - 문서의 각 주장이 테스트 이름을 인용한다.
- **Verification:** `go test -race ./internal/runtime/ ./internal/api/` 통과.

### U3. 실패 모드 문서가 두 수정을 반영한다

- **Goal:** `docs/operations/failure-modes.md`의 모든 행이 다시 참이 된다.
- **Requirements:** R32, R39.
- **Dependencies:** U1, U2.
- **Files:** `docs/operations/failure-modes.md`.
- **Approach:**
  1. U1이 `/readyz` 행을 바꾼다 — 200(fail-open)에서 503으로.
  2. U2가 check 행의 문구를 정확하게 만든다.
  3. **각 행이 그것을 지키는 테스트를 인용한다**(라운드 2가 세운 규칙). 인용이 끊기면 그 행은 소설이다.
- **Test scenarios:** `Test expectation: none` — 문서만. 다만 인용된 테스트 이름이 실재하는지 확인하라.
- **Verification:** 문서의 테스트 이름이 전부 실재한다.

---

## Verification Contract

| 게이트 | 적용 |
|---|---|
| `make land` | 전 유닛 |
| 라운드 2의 `failure_test.go`가 갱신되고 통과 | U1, U2 |
| 문서의 인용된 테스트 이름이 실재 | U3 |

---

## Definition of Done

1. **데이터베이스를 잃은 파드가 `/readyz` 503으로 Service에서 빠지고, 복귀하면 돌아온다.**
2. `/healthz`는 두 경우 모두 200 — liveness가 재시작시키지 않는다.
3. **`STAMP_AUDIT_FAIL_CLOSED`가 보장하는 것과 안 하는 것이 문서에 있고, 창의 크기가 테스트로 고정돼 있다.**
4. `docs/operations/failure-modes.md`의 모든 주장이 참이고 각각 테스트를 인용한다.

---

## Scope Boundaries

### 하지 않는 것

- **판정마다 동기 감사 append를 넣지 않는다**(KTD2) — R32의 거래를 뒤집는 일이다.
- **매 probe마다 데이터베이스를 질의하지 않는다**(KTD1) — 아픈 데이터베이스를 두들긴다.
- **환경 변수 이름을 가볍게 바꾸지 않는다** — 배포 호환성 문제다.

### 이연

- IdP·Kafka 실패 경로
- 손상된 감사 체인의 복구 절차
- 1초 프로덕션 flush 간격의 실측(U2가 가능하면 하되, 못 해도 막지 않는다)
