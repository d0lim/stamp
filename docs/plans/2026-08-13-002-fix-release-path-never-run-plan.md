---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
type: fix
title: "fix: 한 번도 실행된 적 없는 릴리즈 경로를 실행 없이 증명한다"
date: 2026-08-13
origin: docs/operations/failure-modes.md
product_contract_source: legacy-requirements
decisions: docs/decisions/stamp-decision-log.md
---

# fix: 한 번도 실행된 적 없는 릴리즈 경로를 실행 없이 증명한다

---

## Goal Capsule

`gh run list --workflow=release.yml`이 **비어 있다.** 이 워크플로는 한 번도 실행된 적이 없다.

그리고 그 안에 `if: needs.gates.outputs.publish == 'true'`가 **여덟 개** 있다. `publish`가 `'true'`가 되지 않는 경로가 있으면 **모든 발행 단계가 조용히 건너뛰고 워크플로는 초록으로 끝난다** — 아무것도 발행하지 않은 채로.

이 세션이 여섯 번 만난 부류가 정확히 이것이다. **"구현됐지만 도달할 수 없다"** 와 **"가드가 초록인데 실물이 빨갛다"** 가 한 파일에서 만난다. 그리고 실행된 적이 없으니 지금까지 아무도 알 수 없었다.

**나는 이 워크플로를 dispatch할 수 없다**(권한 분류기가 막는다). 그러니 목표는 실행이 아니라 **실행 없이 증명하는 것**이다 — 첫 실제 릴리즈가 이 경로의 첫 실행이 되지 않도록.

닫는 것 하나: **`publish`가 참이 되는 조건과 거짓이 되는 조건이 각각 테스트로 고정되고, 조용한 무발행이 불가능해진다.**

---

## Problem Frame

### 여덟 개의 조건부가 한 값에 걸려 있다

`.github/workflows/release.yml`의 `image`와 `artifacts` 잡이 `gates` 잡의 `publish` 출력에 걸린다. 여덟 스텝이 그 값에 걸리고, 216행에 `!= 'true'` 분기가 하나 있다.

**그 값이 어떻게 계산되는지, 그리고 언제 참이 되는지가 검증된 적이 없다.** `workflow_dispatch` 입력(`version`, `unreleased`)이 그 계산에 들어가는데, dispatch 경로가 실행된 적이 없다.

### 이 부류의 실패는 조용하다

CI 잡이 실패하면 빨개진다. 그러나 **스텝이 `if`로 건너뛰어지면 초록이다.** 릴리즈 워크플로가 초록으로 끝났는데 이미지가 없고 아티팩트가 없는 상태는 — 태그를 밀고 나서야 알게 된다.

이 세션은 같은 모양을 이미 넷 봤다: `quickstart.sh`의 silent-pass 가드 넷. 그때도 스크립트는 초록이었다.

### 실행할 수 없다는 것이 검증하지 않을 이유가 아니다

`gh workflow run`은 내가 부를 수 없다. 그러나 **워크플로의 게이트 로직은 데이터이고, 데이터는 테스트할 수 있다.** `gates` 잡이 `publish`를 계산하는 규칙을 추출해서 입력 조합마다 답을 고정하면, 실행 없이도 "어떤 입력에서 무엇이 발행되는가"가 참인지 알 수 있다.

이 세션이 이미 같은 것을 했다: 라운드 직전에 `ci.yml`의 스텝 본문을 YAML 파서로 뽑아 GitHub의 실제 셸로 돌려 실패를 재현했다.

---

## Requirements

| R-ID | 요구 | 닫는 유닛 |
|---|---|---|
| **R11** | 공개 계약 3종이 semver로 관리되고 릴리즈가 검사한다 | U1, U2 |

새 요구는 없다. **이미 있는 릴리즈 경로가 하는 일을 증명한다.**

---

## Key Technical Decisions

### KTD1. 게이트 로직을 추출해서 테스트한다 — 워크플로를 실행하지 않는다

`act`로 워크플로를 돌리는 것은 GitHub과 다른 환경을 시험하는 것이고, dispatch는 내가 부를 수 없다.

대신 **`gates` 잡이 `publish`를 정하는 규칙을 뽑아내 입력 조합마다 답을 단언한다.** 추출은 YAML 파서로 하고, **추출된 것이 실제 워크플로와 같은지도 검사한다** — 그러지 않으면 사본을 시험하는 것이고, 사본은 드리프트한다.

**기각**: `act`로 전체 실행 — 환경이 다르고, 비밀이 없고, 무엇보다 **초록이 무엇을 증명하는지가 불분명하다.**
**기각**: 사람이 한 번 dispatch하고 끝 — 다음에 로직이 바뀌면 다시 아무도 모른다.

### KTD2. 조용한 무발행을 **구조적으로** 불가능하게 만든다

조건부 여덟 개를 검사로 지키는 것보다, **발행이 일어났어야 하는데 일어나지 않으면 잡이 실패하도록** 만드는 것이 강하다.

즉 `publish`가 참인 실행에서 각 산출물이 실제로 존재하는지 확인하는 스텝을 더한다. 초록인데 산출물이 없는 상태가 **불가능**해진다.

**기각**: 조건부를 검사만 하기 — 다음에 아홉 번째 조건부가 생기면 검사가 낡는다.

---

## Implementation Units

### U1. `publish`가 언제 참인지 고정한다

- **Goal:** 입력 조합마다 무엇이 발행되는지가 테스트로 고정된다. 실행 없이.
- **Requirements:** R11.
- **Dependencies:** 없음.
- **Files:** `internal/release/workflow_test.go`(신규), `.github/workflows/release.yml`(필요 시 게이트 로직을 테스트 가능하게).
- **Approach:**
  1. **먼저 `release.yml`을 통째로 읽어라.** `gates` 잡이 `publish`를 어떻게 정하는지, `workflow_dispatch`의 `version`·`unreleased` 입력이 어떻게 들어가는지, `push` 트리거와 어떻게 다른지.
  2. 게이트 규칙을 **YAML 파서로 추출**해서 입력 조합마다 답을 단언한다(KTD1). 조합은 최소한: 태그 push / dispatch+`unreleased=true` / dispatch+`unreleased=false` / 버전 불일치.
  3. **추출본이 실물과 같은지 검사한다.** 이 세션이 `mounted-routes.json`에서 쓴 것과 같은 관계 — 생성물이 낡으면 빨개진다.
  4. **여덟 개 조건부를 열거하고, 각각이 어느 조합에서 도는지 표로 만든다.** 어느 조합에서도 돌지 않는 스텝이 있으면 **그것이 이 유닛의 발견이다.**
- **Execution note:** 조합 표를 먼저 만들고 **빈 칸을 찾아라.** 이 유닛의 가치는 규칙을 확인하는 것이 아니라 **아무 입력에서도 실행되지 않는 스텝**을 찾는 데 있다.
- **Test scenarios:**
  - 태그 push에서 `publish`가 참이다.
  - dispatch + `unreleased=true`에서의 답이 고정된다.
  - dispatch + `unreleased=false`에서의 답이 고정된다.
  - **여덟 조건부 각각이 최소 한 조합에서 실행된다** — 아니면 실패하고 그 스텝을 이름한다.
  - 추출본이 `release.yml`과 어긋나면 실패한다.
- **Verification:** `go test ./internal/release/` 통과.

### U2. 초록인데 발행하지 않은 상태를 불가능하게 한다

- **Goal:** `publish`가 참인 실행이 산출물 없이 성공할 수 없다.
- **Requirements:** R11.
- **Dependencies:** U1.
- **Files:** `.github/workflows/release.yml`.
- **Approach:**
  1. U1의 표에서 **`publish == 'true'`일 때 존재해야 하는 산출물**을 뽑는다(이미지 태그, 아티팩트, 체크섬 등 — 실제 워크플로가 만드는 것).
  2. 각 잡 끝에 **산출물이 실제로 있는지 확인하는 스텝**을 더한다. 없으면 실패한다.
  3. **`if`를 쓰지 않는다.** 확인 스텝이 `if: publish == 'true'`로 걸리면 같은 함정을 반복한다 — 확인은 무조건 돌고, `publish`가 거짓이면 "발행하지 않음이 의도됨"을 확인한다.
  4. 216행의 `!= 'true'` 분기가 무엇을 하는지 확인하고, 그것도 같은 대우를 받게 한다.
- **Execution note:** 이 유닛의 red는 **확인 스텝을 넣은 뒤 발행 스텝을 하나 껐을 때 잡이 빨개지는 것**이다. 워크플로를 실행할 수 없으므로 U1의 추출 하니스로 확인하거나, 확인 스텝의 셸 로직을 직접 돌려라.
- **Test scenarios:**
  - 산출물이 없는데 `publish`가 참이면 실패한다.
  - `publish`가 거짓이면 확인 스텝이 "의도된 무발행"을 통과시킨다.
  - 확인 스텝 자체에 `if: publish == 'true'`가 없다(검사가 자기가 검사임을 증명).
- **Verification:** U1의 하니스가 새 스텝을 포함해 통과. `make land` 그린.

### U3. 첫 dispatch를 위한 핸드오프를 적는다

- **Goal:** 사용자가 실제로 돌릴 때 무엇을 기대해야 하는지 적는다.
- **Requirements:** R11.
- **Dependencies:** U1, U2.
- **Files:** `docs/operations/release.md`(신규 또는 기존에 절 추가).
- **Approach:**
  1. U1의 조합 표를 사람이 읽는 형태로 옮긴다 — 어떤 입력이 무엇을 발행하는가.
  2. **첫 실행에서 확인해야 할 것**을 적는다. 검사가 없는 부분(비밀, 레지스트리 권한, 서명)은 검사로 덮이지 않으므로 눈으로 봐야 한다.
  3. 이 라운드가 **덮지 못한 것**을 명시한다 — 게이트 로직은 고정했지만 **실제 발행이 성공하는지는 여전히 미검증**이다.
- **Test scenarios:** `Test expectation: none` — 문서.
- **Verification:** 문서의 조합 표가 U1의 테스트와 일치한다.

---

## Verification Contract

| 게이트 | 적용 |
|---|---|
| `make land` | 전 유닛 |
| 게이트 조합 표가 테스트로 고정 | U1 |
| 확인 스텝에 `if` 게이팅이 없음 | U2 |

---

## Definition of Done

1. **여덟 조건부 각각이 어느 입력 조합에서 도는지 표로 고정돼 있고, 아무 데서도 돌지 않는 스텝이 없다.**
2. `publish`가 참인 실행이 산출물 없이 초록으로 끝날 수 없다.
3. 첫 dispatch에서 무엇을 눈으로 확인해야 하는지 문서에 있다.
4. **이 라운드가 덮지 못한 것이 명시돼 있다** — 게이트는 고정됐고 실제 발행은 여전히 미검증이다.

---

## Scope Boundaries

### 하지 않는 것

- **워크플로를 dispatch하지 않는다** — 권한 분류기가 막는다. 그것이 이 라운드가 정적 증명을 택한 이유다.
- **`act`를 들이지 않는다**(KTD1).
- **릴리즈 절차를 바꾸지 않는다.** 있는 것이 하는 일을 증명한다.

### 이연

- 실제 발행 성공(레지스트리 권한·비밀·서명) — 첫 dispatch에서만 알 수 있다
- 릴리즈 아티팩트의 provenance/SBOM
