---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
type: fix
title: "fix: 마지막 무예산 표면, 유일한 가드, 그리고 스스로를 증명하지 않는 검사들"
date: 2026-08-12
origin: docs/residual-review-findings/fix-stamp-open-issues-tail.md
product_contract_source: legacy-requirements
decisions: docs/decisions/stamp-decision-log.md
---

# fix: 마지막 무예산 표면, 유일한 가드, 그리고 스스로를 증명하지 않는 검사들

> **정본 관계.** 제품 요구(R-ID)의 정본은 `docs/plans/2026-08-07-001-feat-stamp-feature-map-plan.md`, 결정(D-ID)의 정본은 `docs/decisions/stamp-decision-log.md`. 이 문서는 새 요구를 만들지 않는다 — PR #51이 남긴 durable record(`docs/residual-review-findings/fix-stamp-open-issues-tail.md`)의 "남긴 것"을 닫는 실행 계획이다.

---

## Goal Capsule

열린 이슈는 0이고 `make land`는 그린이다. 남은 것은 **이슈가 아니라 결손**이고, 세 부류다.

1. **예산이 없는 마지막 표면** — R43은 네 축(decide 생성·challenge 발급·webhook 발신·승인 제출)에 속도 제한을 요구했고 넷 다 있다. 그런데 **위임 취소**는 같은 lifecycle에 같은 비용으로 닿으면서 예산이 없다. PR #51이 이것을 **더 나쁘게** 만들었다.
2. **가드가 하나뿐인 것** — "구현됐지만 도달할 수 없다"가 이 세션에서 여섯 번 나왔다. PR #51이 helm에 렌더 시점 거부를 넣어 그중 마지막을 닫았지만, **차트가 유일한 가드다.** 데모는 docker-compose로 돌고 바이너리를 직접 띄우는 경로에는 아무것도 없다.
3. **자기가 검사임을 증명하지 않는 검사** — 이 세션의 지배적 결함이다. PR #51은 1500줄 넘는 테스트를 들여왔는데 **testing 렌즈가 그것을 보지 못했다.** 그리고 CI의 한 잡은 자기가 왜 실패했는지 말하지 못한다.

닫는 것 하나: **모든 쓰기 표면이 예산을 갖고, 도달 불가는 helm 밖에서도 거부되며, 새 테스트가 자기가 테스트임을 증명한다.**

---

## Problem Frame

### 위임 취소만 예산이 없고, 지난 PR이 그 비용을 키웠다

`internal/api/cancel.go`의 `CancellationsConfig`는 필드가 **하나**다 — `Decisions`. 제한기도, 감사 기록기도, 시계도 없다. 같은 파일의 이웃인 `internal/api/approvals.go`는 U4 이후 `Rate`·`MaxTrackedApprovers`·`Audit`·`Now`를 갖는다.

그 차이가 이번에 비용을 낳았다. PR #51이 자격 판정을 상태 판정 앞으로 옮기면서, **존재하는 결정에 대한 거부가 동기 감사 체인 append를 쓰는 범위가 미결에서 해소·만료까지 넓어졌다.** 인증된 콘솔 사용자가 결정 식별자 하나로 예산 없이 체인 append를 유발할 수 있다. 감사 체인은 직렬화된 쓰기라 이것은 단순한 낭비가 아니라 **경합 지점에 대한 무료 접근**이다.

취소는 `approvalError`를 공유하고 `decision.Service.Submit`을 호출한다 — 승인 제출과 **같은 lifecycle, 같은 행 잠금, 같은 핸들러 검증**이다. 예산이 있어야 할 이유가 승인 제출과 동일하고, 없을 이유는 없다.

### helm이 유일한 가드다

`internal/runtime/config.go:1133`의 `Config.validate`는 표면 주소가 **하나라도** 있으면 통과시킨다. `Addresses map[api.Surface]string`(:105)와 `MFAConfig`(:1203 validate)·`ExternalTargets`(:358)·`CallbackBaseURL`(:362)·`IngestCredentials`(:138)를 **대조하지 않는다.**

그래서 PR #51의 `_helpers.tpl` 거부는 helm으로 배포하는 사람만 보호한다. `stamp --roles=all`을 직접 띄우면서 step-up MFA를 설정하고 콜백 리스너를 비워 두면 **아무도 막지 않는다** — IdP가 주체를 돌려보낼 곳이 없는 배포가 부팅하고 healthy를 보고한다.

데모가 docker-compose로 돈다는 사실이 이것을 이론에서 실무로 옮긴다. D26이 step-up을 데모의 기본 경로로 만들었다.

### 테스트가 1500줄 늘었고 아무도 그것을 보지 않았다

PR #51의 코드 리뷰에서 여덟 렌즈 중 일곱이 결과를 잃었고, 넷은 죽기 전에 물어서 회수했다. **testing 렌즈만 아무것도 내놓지 못했고 재실행하지 않았다.** 그 라운드가 들여온 테스트가 1500줄이 넘는다.

이 프로젝트의 상습 결함이 정확히 그 자리에 있다: 이번 라운드만 해도 **콘솔 테스트가 서버가 보내지 않는 코드를 스텁으로 시험하며 초록이었다.** 픽스처가 진실을 대신하면 테스트는 자기가 지키는 것이 무너져도 초록이다.

### CI의 한 잡이 자기 실패를 설명하지 못한다

`.github/workflows/ci.yml`의 `docker build` 잡에서 "the console role serves the embedded bundle, the api role does not" 스텝은:

- api 티어가 30초 안에 안 뜨면 **대기 루프가 조용히 포기하고 그냥 진행한다.**
- `expect()`가 `got=$(status "$2")`로 값을 받는데, `bash -e` 아래에서 curl이 연결 실패(exit 7)하면 **그 할당이 스텝을 exit 7로 죽인다** — 메시지 한 줄 없이.
- 실패 핸들러는 `docker logs stamp-ci-console`만 덤프한다. **정작 실패한 `stamp-ci-apionly`의 로그는 아무도 못 본다.**

실제로 이번에 한 번 빨개졌고, 재실행으로 통과했으며, 로컬 재현 세 번이 실패했다. 원인을 아직 모르는데 **다음에 같은 일이 나도 여전히 모를 것이다.**

---

## Requirements

전부 원 계획서의 R-ID를 인용한다. 새 요구는 없다.

| R-ID | 요구 | 닫는 유닛 |
|---|---|---|
| **R43** | decide 생성·challenge 발급·webhook 발신·승인 제출이 속도 제한과 미결 상한을 갖고, 초과는 deny와 감사 | U1 |
| **R39** | 콜백 수신 표면을 PEP·콘솔과 분리해 노출한다 | U2 |
| **R22** | 감사 열람 자격은 결정 단위가 아니라 컬렉션 단위로 판정된다 | U1 |
| **R32** | 감사 유실 구간 마커와 운영자 경보 | U1 |
| **R11** | 공개 계약 3종이 semver로 관리되고 릴리즈가 검사한다 | U1 |
| **R28** | 위임 MFA는 IdP에 위임하고 응답의 `acr`를 검증한다 (D26) | U2 |

---

## Key Technical Decisions

### KTD1. 취소는 승인 제출의 예산을 **공유하지 않고** 자기 것을 갖는다

둘 다 `decision.Service.Submit`에 닿지만 **다른 사람이 다른 이유로 부른다.** 승인은 쿼럼의 대상자가 판단을 내리는 행위이고, 취소는 지연 challenge의 권한자가 진행을 멈추는 행위다. 한 예산을 공유하면 승인 폭주가 취소를 막는데, **취소는 진행 중인 것을 세우는 안전 장치**라 그 방향의 결합이 특히 나쁘다.

**기각**: `Approvals`의 제한기를 재사용하는 안. 코드는 짧아지지만 위 결합을 산다.
**기각**: 취소를 무제한으로 두는 안 — 이 유닛이 존재하는 이유다.

### KTD2. 거부의 모양은 승인 제출을 따른다 — 429다

취소도 콘솔이 사람의 요청으로 부르는 경로다. `approvals.go`의 헤더가 그 선택의 근거를 이미 적었다: HTTP 응답이 있는 경로이고, 대상이 사람이며, 재시도가 자연스럽다. **decide의 200 + denied 결정 객체는 여기 맞지 않는다** — 취소는 결정을 만들지 않는다.

`Retry-After`도 승인 제출과 같이 붙는다. 거기서는 규격이 의도한 자리이므로 클라이언트가 실제로 지킨다.

### KTD3. 기동 검증은 **표면과 설정의 대조**이지 설정의 재검증이 아니다

`Config.validate`는 이미 각 설정의 내적 정합성을 본다(`MFAConfig.validate`가 네 변수의 동반 필수를 강제하는 식). 이 유닛이 더하는 것은 **다른 축**이다: 그 설정이 요구하는 라우트가 **바인드된 표면 위에 있는가.**

그래서 검사는 `Addresses`와 각 기능의 표면 요구를 대조하는 한 곳에 살고, 개별 설정 validate에 흩어지지 않는다. 흩어지면 다섯 번째 기능이 생겼을 때 아무도 이 축을 기억하지 못한다.

**기각**: helm에만 두는 현 상태 — 데모와 직접 실행 경로가 무방비다.
**기각**: 기동을 통과시키고 `/readyz`로만 알리는 안. 이것은 롤아웃 타이밍이 아니라 **설정 오류**다. 스키마는 곧 도착하지만 없는 리스너는 저절로 생기지 않으므로, 기다릴 것이 없는 상태에서 unready로 서 있는 것은 오류를 침묵시키는 것이다.

### KTD4. CIBA는 폴링을 배선하지 않고 `Poll`을 지운다

`internal/challenge/mfa/ciba.go`의 `Poll`은 프로덕션 호출자가 없다(직접 확인). CIBA의 판정은 콜백 POST로 돌아오므로 **CIBA 자체는 동작한다.**

폴링을 배선하는 것은 새 기능이고, 새 실패 모드(폴 간격·백오프·`auth_req_id` 수명)를 들여오며, 원 계획의 Scope Boundaries가 "CIBA 경로를 손보지 않는다"고 적었다. **계약이 약속하는 것과 바이너리가 하는 것을 일치시키는 가장 싼 방법은 약속을 줄이는 것이다.**

**기각**: 폴링 배선 — 범위 밖이고, 모의 OP 검증만 있는 경로에 실 기능을 더한다.
**기각**: 그대로 두기 — 데드 코드가 계약 문서의 주장을 뒷받침하는 것처럼 보인다.

### KTD5. 테스트 감사는 리뷰가 아니라 **뮤테이션 행렬**이다

"테스트를 리뷰한다"는 이 프로젝트에서 이미 실패했다 — 렌즈가 결과를 잃었고, 잃은 줄도 늦게 알았다. 대신 **각 고위험 테스트에 결함을 심어 빨개지는지 확인하고 그 표를 커밋한다.**

이것은 이 세션이 반복해서 쓴 방법이고(모든 새 검사를 실물 변형으로 확인했다), 리뷰와 달리 **산출물이 재실행 가능하다.**

**기각**: testing 렌즈 재실행 — 같은 실패 모드에 다시 건다. 뮤테이션은 사람이 읽는 보고가 아니라 커밋된 증거다.

---

## High-Level Technical Design

### 표면과 그 예산 (U1 이후)

| 표면 | 부르는 사람 | 거부의 모양 | 예산 |
|---|---|---|---|
| `POST /decisions` (decide) | PEP(워크로드) | **200 + denied 결정**, `Retry-After` | 호출자 + 주체 (표 둘) |
| challenge 발급 | (내부, lifecycle) | 재시도 가능한 거부, 결정 행 없음 | (호출자,주체) + 주체 천장 |
| webhook 발신 | (내부, lifecycle) | challenge 상태 | 주체 |
| `POST …/approvals` | 승인자(사람) | **429**, `Retry-After` | 승인자 |
| `POST …/cancellation` | 권한자(사람) | **429**, `Retry-After` ← **U1이 더한다** | 취소 권한자 |

### 기동 시점 대조 (U2)

```
Config.validate
  └── surfaceRequirements()          ← 새로 더하는 축
        ├── step-up MFA 설정됨?      → callback 표면 필요
        ├── external 타깃 있음?       → callback 표면 필요
        ├── 인제스트 자격증명 있음?   → callback 표면 필요
        └── 각각을 Addresses와 대조 → 없으면 부팅 실패 (원인·결과·두 출구를 이름)
```

`_helpers.tpl`의 거부 문구가 이미 그 세 가지를 같은 방식으로 판단한다 — **같은 규칙을 Go 쪽에도 둔다.** 차트는 렌더 시점에, 바이너리는 기동 시점에 같은 답을 낸다.

---

## Implementation Units

### U1. 위임 취소에 예산이 생긴다

- **Goal:** R43의 네 축이 덮지 못한 다섯 번째 쓰기 표면을 닫는다. PR #51이 키운 무료 감사 append 비용을 되돌린다.
- **Requirements:** R43, R22, R32, R11.
- **Dependencies:** 없음.
- **Files:** `internal/api/cancel.go`, `internal/api/cancel_test.go`, `internal/runtime/config.go`, `internal/runtime/config_test.go`, `internal/runtime/wiring.go`, `docs/contracts/decision-api.md`, `README.md`.
- **Approach:**
  1. `CancellationsConfig`에 `Rate`·`MaxTrackedCancellers`·`Audit`·`Now`를 더한다. **`internal/api/approvals.go`의 같은 네 필드가 정확한 선례다** — 이름·기본값 채우기(`WithZeroDefault`)·검증까지 그대로 따른다.
  2. 거부는 **429 + `Retry-After`**(KTD2). 코드 어휘는 승인 제출의 `rate_limited`와 구분되는 자기 단어를 쓴다 — 운영자가 감사 체인에서 어느 표면이 흘렸는지 알아야 한다(`ApprovalRateLimitedReason`이 같은 이유로 자기 단어를 쓴 선례).
  3. 감사는 승인 제출과 같은 버퍼로 간다. **동기 체인 append가 아니다** — 이 유닛이 줄이려는 것이 정확히 그 비용이다.
  4. 기본값은 승인 제출보다 **타이트하게** 잡는다. 취소는 한 결정에 한 번 하는 행위이고 사람이 연타할 이유가 없다. 숫자의 근거를 주석에 적는다.
  5. 설정은 `STAMP_CANCELLATION_RATE_*`로 노출하고 `checkRate`의 검증 대상에 넣는다.
  6. 계약 문서에 429와 `Retry-After`를 기술하고 버전을 자기 규칙대로 올린다.
- **Execution note:** 예산 없이 한 사람이 N번 취소를 시도해 **감사 행이 N개 생기는 것**을 red로 먼저 고정하라 — 그것이 PR #51이 키운 비용이고 이 유닛의 요점이다.
- **Test scenarios:**
  - 한 권한자의 반복 취소 시도가 한도에서 429로 멈춘다.
  - 그 429가 `Retry-After`를 싣고 값이 재충전 간격과 일치한다.
  - 초과가 감사에 남고 그 reason이 **승인 제출의 것과 구분된다**.
  - 한도를 넘은 요청이 lifecycle에 닿지 않는다 — 감사 행이 더 늘지 않는 것으로 단언한다(이 유닛의 red와 짝이다).
  - 다른 권한자의 예산은 영향받지 않는다.
  - 창이 지나면 회복된다.
  - 설정 미지정 시 기본값, 잘못된 값은 기동 실패.
- **Verification:** `go test -race ./internal/api/ ./internal/runtime/` 통과. `make land` 그린.

### U2. 도달할 수 없는 설정을 바이너리도 거부한다

- **Goal:** helm이 유일한 가드인 상태를 끝낸다. "구현됐지만 도달할 수 없다"의 마지막 미봉 지점.
- **Requirements:** R39, R28.
- **Dependencies:** 없음.
- **Files:** `internal/runtime/config.go`, `internal/runtime/config_test.go`, `README.md`, `deploy/demo/README.md`.
- **Approach:**
  1. `Config.validate`(`internal/runtime/config.go:1133`)에 **표면 대조 축**을 더한다(KTD3). 개별 설정 validate에 흩지 않는다.
  2. 세 조건은 `deploy/helm/stamp/templates/_helpers.tpl`의 거부가 이미 판단하는 것과 **같아야 한다**: step-up MFA 설정됨 / external 타깃 있음 / 인제스트 자격증명 있음 → 각각 `callback` 표면 필요. 그 템플릿을 먼저 읽고 조건을 맞춘다.
  3. **CIBA는 트리거가 아니다** — 브라우저 리다이렉트가 없다. 다만 `MFAConfig.validate`가 어떤 MFA든 설정되면 step-up 4종을 요구하므로 CIBA 전용 배포도 결과적으로 걸린다. 그 사실을 주석에 적는다(PR #51의 U9가 확인한 것).
  4. **역할을 고려한다.** `--roles=check`만 도는 프로세스는 콜백 라우트를 마운트하지 않으므로 거부 대상이 아니다. 차트의 거부가 `decide`/`consumer` 역할로 게이팅한 것과 같은 판단이다.
  5. 메시지는 차트의 것과 같은 격을 갖는다 — **원인, 그 라우트, 결과, 그리고 두 출구**를 한 줄로 이름한다. "아무도 안 잡는다"가 아니라 "여기서 잡는다"가 되게.
- **Execution note:** step-up MFA를 설정하고 `STAMP_CALLBACK_ADDR`를 비운 설정이 **지금은 부팅에 성공하는 것**을 red로 고정하라. 그것이 차트 밖의 구멍이다.
- **Test scenarios:**
  - step-up MFA 설정 + 콜백 미바인딩 → 기동 실패, 메시지가 변수 이름을 담는다.
  - external 타깃 있음 + 콜백 미바인딩 → 기동 실패.
  - 인제스트 자격증명 있음 + 콜백 미바인딩 → 기동 실패.
  - 셋 다 있고 콜백 바인딩됨 → 통과.
  - 셋 다 없고 콜백 미바인딩 → 통과(기본 배포가 깨지지 않는다).
  - **콜백 라우트를 마운트하지 않는 역할만 도는 프로세스는 거부되지 않는다.**
  - 거부 조건이 차트의 거부 조건과 일치한다 — 한쪽만 잡는 설정이 없다.
- **Verification:** `go test ./internal/runtime/` 통과. 데모(`scripts/quickstart.sh`)가 여전히 뜬다 — 이 검사가 데모를 깨면 데모가 실제로 그 상태였다는 뜻이므로 데모를 고친다.

### U3. 새 테스트가 자기가 테스트임을 증명한다

- **Goal:** PR #51이 들여온 1500줄의 테스트 중 고위험분에 대해 **뮤테이션으로 결속을 고정한다.** testing 렌즈가 잃은 커버리지를 사람이 읽는 보고가 아니라 커밋된 증거로 대체한다.
- **Requirements:** 없음(품질 게이트). 원 계획의 Verification Contract를 강화한다.
- **Dependencies:** U1, U2(그 유닛들의 새 테스트도 대상에 포함된다).
- **Files:** `docs/testing/mutation-matrix.md`(신규), 그리고 감사에서 결속이 약한 것으로 드러난 테스트 파일.
- **Approach:**
  1. **대상을 고른다.** PR #51의 새 테스트 중 (a) 인가 판정, (b) 속도 제한, (c) 멱등성, (d) 드리프트 검사, (e) 콘솔의 서버 계약 가정에 닿는 것. 전부가 아니라 **틀리면 조용히 위험한 것**이다.
  2. 각 대상에 대해 **결함을 하나 심고 빨개지는 것을 확인한다.** 이 세션이 이미 쓴 방법이다 — 실물 차트 스냅샷과 실물 계약 문서를 변형해 U5의 두 검사를 확인했고, `mayActOn`을 항상 통과시켜 오라클 테스트를 확인했다.
  3. **살아남는 테스트가 이 유닛의 산출물이다.** 뮤테이션에도 초록인 테스트는 그것이 지킨다고 주장하는 것을 지키지 않는다 — 고치거나, 무엇을 덮지 않는지 명시적으로 적는다.
  4. `docs/testing/mutation-matrix.md`에 표를 커밋한다: 테스트, 심은 결함, 관찰된 실패, 날짜. **다음 라운드가 이어 쓸 수 있는 형식으로.**
  5. **콘솔을 빠뜨리지 않는다.** 이번 라운드의 실제 사고가 거기서 났다 — 스텁이 서버가 보내지 않는 코드를 시험했다. 콘솔 테스트는 스텁이 지금의 Go 핸들러가 내는 것과 일치하는지 별도로 확인한다.
- **Execution note:** 각 테스트에 대해 "이 프로덕션 코드를 한 줄 바꾸면 이 테스트가 여전히 초록인가"를 물어라. 답이 예면 그 테스트가 발견이다.
- **Test scenarios:**
  - 대상 각각에 대해 심은 결함이 실제 실패 출력을 낸다(표에 인용된다).
  - 뮤테이션 후 트리가 **깨끗하게 복원된다** — 표를 만드는 과정이 리포를 더럽히지 않는다.
  - 살아남은 테스트가 있으면 고쳐지거나 한계가 문서화된다.
  - `make land`가 감사 전후로 동일하게 그린이다.
- **Verification:** `docs/testing/mutation-matrix.md`가 존재하고 각 행이 실제 실패 출력을 인용한다. 살아남은 테스트 0개, 또는 각각에 대한 조치가 기록됨.

### U4. CI가 왜 실패했는지 말한다

- **Goal:** `docker build` 잡이 조용히 exit 7로 죽지 않게 한다. 실패한 컨테이너의 로그가 보이게 한다.
- **Requirements:** 없음(개발 기반).
- **Dependencies:** 없음.
- **Files:** `.github/workflows/ci.yml`.
- **Approach:**
  1. **대기 루프가 포기하면 그것을 말한다.** 지금은 30번 돌고 조용히 진행한다. 예산을 다 쓰면 어느 티어가 안 떴는지 이름하고 실패한다.
  2. **실패 핸들러가 두 컨테이너 로그를 모두 덤프한다.** 지금은 `stamp-ci-console`만 — 정작 실패한 쪽이 안 보인다.
  3. `expect()`의 연결 실패가 맨 exit 7이 되지 않게 한다. curl의 연결 실패와 "응답했지만 코드가 다름"을 **다른 메시지로** 가른다.
  4. **관대함이 아니라 진단이다.** 대기 예산을 늘리는 것은 증상을 늦출 뿐이다 — 진짜 산출물은 다음에 같은 일이 났을 때 **원인이 로그에 있는 것**이다.
- **Execution note:** 존재하지 않는 포트를 향하게 해서 스텝이 지금 무엇을 출력하는지 먼저 보라. 그 침묵이 고치려는 것이다.
- **Test scenarios:**
  - 티어가 뜨지 않는 상황을 흉내내면 스텝이 **어느 티어인지 이름하고** 실패한다.
  - 실패 시 두 컨테이너의 로그가 모두 출력에 있다.
  - 정상 경로는 동작이 바뀌지 않는다.
- **Verification:** PR의 `docker build` 잡이 그린. 일부러 깨뜨린 브랜치에서 메시지가 원인을 담는 것을 한 번 확인한다(로컬 `act` 또는 임시 커밋).

### U5. 계약이 약속하는 것과 바이너리가 하는 것을 맞춘다

- **Goal:** `CIBA.Poll`의 데드 코드를 없앤다(KTD4).
- **Requirements:** R28.
- **Dependencies:** 없음.
- **Files:** `internal/challenge/mfa/ciba.go`, `internal/challenge/mfa/ciba_test.go`, `docs/contracts/challenge-interface.md`(필요 시).
- **Approach:**
  1. `Poll`과 그 전용 테스트를 지운다. 호출자가 없음을 먼저 재확인한다(`rg` 한 번).
  2. **계약 문서가 폴링을 약속하는지 확인한다.** 약속한다면 문서를 고치고 버전을 올린다 — 그것이 이 유닛의 실제 가치다.
  3. CIBA의 판정이 콜백 POST로 돌아온다는 것을 `ciba.go` 주석이 말하게 한다. 다음 사람이 "폴링은 어디 있지"를 묻지 않도록.
- **Execution note:** 지우기 전에 `rg 'Poll\('`로 호출자를 다시 확인하라 — 계획이 틀렸다면 지우는 것이 아니라 배선하는 것이 맞다.
- **Test scenarios:**
  - `go build ./...`와 `go vet ./...`가 통과한다(지운 것에 숨은 참조가 없다).
  - CIBA의 기존 왕복 테스트가 그대로 통과한다.
  - 계약 문서가 폴링을 약속하지 않는다.
- **Verification:** `make land` 그린. `rg 'func \(c \*CIBA\) Poll'`이 아무것도 찾지 못한다.

---

## Verification Contract

원 계획서의 게이트를 물려받고 이 계획이 더하는 것만 적는다.

| 게이트 | 적용 |
|---|---|
| `make land` (fmt · vet · golangci-lint · `go test -race ./...` · govulncheck · chart-check · contracts) | 전 유닛 |
| demo smoke 두 프로파일 | U2 (기동 검증이 데모를 깨지 않는지) |
| 콘솔 `npm test` · `build` · 계약 경계 | U3 |
| 계약 버전 게이트 | U1, U5 |
| **뮤테이션 행렬이 존재하고 실제 실패 출력을 인용한다** | U3 |
| CI `docker build` 잡 | U4 |

---

## Definition of Done

1. **쓰기 표면 다섯이 모두 예산을 갖는다** — decide, challenge 발급, webhook 발신, 승인 제출, 그리고 취소.
2. **도달할 수 없는 설정이 helm 밖에서도 거부된다** — 바이너리를 직접 띄우는 경로와 데모가 같은 답을 받는다.
3. **`docs/testing/mutation-matrix.md`가 존재하고, 고위험 테스트마다 심은 결함과 관찰된 실패를 인용한다.** 살아남은 테스트가 없거나 각각에 조치가 기록돼 있다.
4. CI의 `docker build` 잡이 실패할 때 **어느 티어가 왜 실패했는지 출력에 있다.**
5. `CIBA.Poll`이 없고 계약 문서가 그것을 약속하지 않는다.
6. `gh issue list --state open`이 비어 있고 `main`의 CI·conformance·bench가 전량 그린이다.

2번과 3번이 실질적 완료 조건이다. 나머지는 그것이 성립하기 위한 조건이거나, 성립한 뒤에도 남아야 하는 보장이다.

---

## Landing 전략

D25를 그대로 따른다. **구현 유닛 하나 = PR 하나, squash.**

의존: U3 ← U1·U2. 나머지는 서로 독립.

병렬 안전한 층: **① U1 · U2 · U4 · U5** → **② U3**.

U1과 U2는 둘 다 `internal/runtime/config.go`를 만지므로 **같은 층이지만 순서를 둔다**(U1 먼저, U2가 rebase). U4는 `.github/`만, U5는 `internal/challenge/mfa/`만 만져 충돌이 없다.

---

## Scope Boundaries

### 하지 않는 것

- **새 제품 요구를 만들지 않는다.** R-ID는 전부 원 계획서의 것이다.
- **CIBA 폴링을 배선하지 않는다**(KTD4).
- **`Retry-After`를 200 위에서 재설계하지 않는다.** 거부의 상태 코드는 R43이 "초과는 deny"라고 못 박은 확정 설계다. 그 한계는 이미 계약 문서에 정직하게 적혀 있다.

### 이연 — 근거와 함께

- **타이밍 부채널.** 응답 바이트는 같고 시간은 다르다. 상수 시간으로 만들려면 접근 판정을 앞으로 끌어올리거나 거부 경로를 패딩해야 하고, 둘 다 lifecycle의 모양을 바꾼다. **자기 라운드가 필요하다.**
- **인제스트 rate 정규화 갈라짐.** 고치면 그것에 맞춰 설정한 배포의 의미가 밑에서 바뀐다. 동작 변경이라 사용자 판단이 필요하고, 주석은 이미 갈라짐을 명시한다.
- **손상된 challenge detail의 500.** 닫으려면 "읽을 수 없는 detail = 대상 아님"으로 정하는 fail-closed 판단이 필요하다. 선재하고 손상된 행으로만 도달한다.
- **주체별 천장이 여전히 공유라 소진 가능한 것.** 쓸 수 없는 천장은 천장이 아니다. **해악은 이미 제거됐다** — 셰딩된 발급이 기록을 남기지 않는다. 남은 것은 지연이고, 이것을 없애려면 분산 예산(DB 또는 Redis)이 필요해 아키텍처 결정이다.

---

## 핸드오프 — 사용자가 직접 해야 하는 것

**릴리즈 워크플로 리허설.** `release.yml`의 `workflow_dispatch` 경로는 아직 한 번도 실행되지 않았다. 나는 이것을 실행할 수 없다(권한 분류기가 막는다). 다음을 직접 돌려 보시면 된다:

```
! gh workflow run release.yml --ref main -f version=0.1.0 -f unreleased=true
```

**왜 중요한가:** 실행된 적 없는 릴리즈 경로는 이 세션이 여섯 번 만난 부류와 같다 — 구현됐지만 도달이 확인되지 않았다. 첫 실제 릴리즈가 그 경로의 첫 실행이 되면 안 된다.
