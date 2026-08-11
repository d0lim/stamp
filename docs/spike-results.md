---
title: STAMP U0 반증 스파이크 결과
date: 2026-08-10
unit: U0
plan: docs/plans/2026-08-07-001-feat-stamp-feature-map-plan.md
---

# STAMP U0 반증 스파이크 결과

계획서에서 가장 얇은 근거 위에 서 있던 세 전제를, 반증 비용이 가장 작은 시점에 실제로 돌려서 확인했다. 산출은 결정이며 스파이크 코드는 폐기했다 — 이 문서 하나만 남는다.

각 항목은 셋 중 하나로 닫힌다. **확정**(전제가 성립) · **개정**(부정 결과이며 어느 결정과 데모 번들 구성을 고쳐야 하는지 지목) · **미확정**(기한 안에 결론이 나지 않았으며 채택할 기본값과 재확인 시점을 적음).

| # | 항목 | 상태 | 영향을 받는 유닛 |
|---|---|---|---|
| S1 | self-hostable IdP의 CIBA·acr step-up 능력 | **개정** | U10, U18, R28 |
| S2 | 세그먼트 감사 체인의 동시 삽입 처리량과 check 지연 자릿수 | **확정** | U4, U5, U17 |
| S3 | AuthZEN interop 하네스의 CI 재현성과 프로파일 선택 | **확정** | U5 |

**측정 환경.** Docker 29.4.0, 컨테이너는 aarch64/linux(macOS 위 리눅스 VM), 호스트 논리 코어 10. Keycloak 26.4.7, PostgreSQL 17.10(alpine, 무튜닝 — `shared_buffers=128MB`, `fsync=on`, `synchronous_commit=on`), Node v22.21.1, `openid/authzen` 커밋 `6fb7fa85c86acda14710f9f0f161da9aaa801a45`(2026-07-27). 세 항목 모두 이미지 풀과 github.com 접근이 정상 동작했다 — 네트워크 사유로 닫지 못한 항목은 없다.

---

## S1. self-hostable IdP의 CIBA·acr step-up 능력 — **개정**

### 무엇을 확인했나

계획은 위임 MFA를 "CIBA 또는 RFC 9470 step-up을 실제 지원하는 self-hostable IdP"에 맡기고(R28, U10), 그 IdP의 존재를 U0가 확인하는 것으로 미뤄 두었다. Dex는 페더레이션 브로커라 CIBA 그랜트도 acr 기반 step-up도 구현하지 않으므로 애초에 후보가 아니다. Keycloak을 1순위로 세우고 네 가지를 물었다 — CIBA 그랜트가 실제로 서 있는가, `binding_message`가 결정 컨텍스트를 실어 나를 수 있는가, CIBA가 별도 서버를 요구하는가, `acr` step-up이 동작하고 토큰에 `acr`·`amr`·`auth_time`이 실리는가.

### 어떻게

컨테이너로 Keycloak 26.4.7을 `start-dev --features=ciba,preview`로 띄우고 전용 realm과 CIBA 그랜트를 켠 기밀 클라이언트, 사용자 하나를 만들었다. discovery 문서를 읽고, backchannel authentication 엔드포인트에 직접 요청을 보내고, ACR→LoA 매핑과 조건부 인증 하위 플로를 구성한 뒤 authorization code 플로를 스크립트로 완주해 ID 토큰 클레임을 디코드했다.

### 관측

**CIBA 표면은 실재한다.** discovery에 `urn:openid:params:grant-type:ciba` 그랜트, `backchannel_authentication_endpoint`, `backchannel_token_delivery_modes_supported: ["poll","ping"]`가 모두 나온다.

**`binding_message`에는 형식 제약이 있다.** 금액·수취인을 담은 문자열을 실었더니 요청이 거부됐다.

```
{"error":"invalid_binding_message","error_description":"the binding_message value has to be
 max 50 characters in length and must contain only basic plain-text characters without spaces"}
```

50자 상한과 **공백 금지**, 기본 평문 문자만. `TXN-4417` 같은 짧은 참조 코드는 통과한다.

**CIBA는 외부 decoupled authentication server를 요구한다.** 형식이 유효한 요청은 다음 단계에서 503으로 떨어진다.

```
{"error":"server_error","error_description":"Failed to send authentication request"}
RuntimeException: Authentication Channel Request URI not set properly.
  at HttpAuthenticationChannelProvider.checkAuthenticationChannel(...)
```

`ciba-auth-channel` SPI에 등록된 구현은 `ciba-http-auth-channel` **하나뿐**이며, 이것은 인증을 외부 HTTP 엔드포인트로 위임하는 어댑터다. Keycloak은 인증 장치(AD) 쪽 구현을 동봉하지 않는다 — CIBA를 종단으로 돌리려면 그 서버를 우리가 만들어 데모 compose에 세 번째 서비스로 넣어야 한다.

**acr step-up은 구성하면 동작한다.** realm 속성 `acr.loa.map`에 `{"gold":2,"silver":1}`을 넣고 browser 플로 복사본의 `forms` 하위에 `Condition - Level of Authentication`(`loa-condition-level=2`) 조건부 하위 플로를 달자, `acr_values=gold` 요청이 상위 인증 단계를 실행하고 ID 토큰이 `acr='gold'`, `auth_time`을 실어 돌아왔다. `acr_values=silver`는 `acr='silver'`였다.

**충족하지 못한 acr는 오류가 아니라 침묵 강등이다.** 구성 전 상태에서 `acr_values=2`도, OIDC 필수 클레임 형태(`claims={"id_token":{"acr":{"essential":true,"values":["2"]}}}`)도 모두 오류 없이 `acr='1'`을 돌려줬다. 구성 후에는 매핑에 없는 `acr_values=platinum`이 오류 없이 `acr='gold'`를 돌려줬다. 요청한 값이 반영됐는지는 **응답을 검증해야만** 알 수 있다.

**`amr`은 기본 구성에서 비어 있다.** `oidc-amr-mapper`는 존재하지만 기본 클라이언트 스코프에 없어 매퍼를 붙이기 전에는 클레임 자체가 나오지 않았고, 붙인 뒤에도 비밀번호 인증 후 값이 `[]`였다. `auth-username-password-form`과 `auth-otp-form` 어느 쪽도 AMR 값을 지정할 config 속성을 노출하지 않는다.

### 상태와 함의 — **개정**

능력 전제 자체는 성립한다. self-hostable IdP는 CIBA와 acr step-up을 모두 갖고 있고, **데모 IdP는 Keycloak으로 확정한다.** 다만 세 지점에서 계획을 고쳐야 한다.

1. **데모 번들의 CIBA 종단 시연은 성립하지 않는다(R28, U18).** compose에 IdP를 넣는 것만으로는 CIBA가 돌지 않고, 자체 제작 decoupled authentication server가 하나 더 필요하다 — 데모 편의를 위해 인증 승인 UI를 직접 짓는 셈이라 v1 범위에 맞지 않는다. **데모의 위임 MFA 기본 경로를 RFC 9470 step-up 리다이렉트로 고정하고, U18의 "위임 MFA 플로가 데모 번들에서 종단 성공한다" 시나리오를 그 경로로 읽는다.** CIBA는 U10의 계약과 클라이언트 구현으로 남기고 모의 OP 테스트로 검증한다 — U10이 이미 "IdP가 CIBA를 지원하지 않으면 step-up 리다이렉트 플로로 폴백한다"고 적어 둔 폴백이 데모의 기본값이 되는 것뿐이다.
2. **`binding_message`에 결정 컨텍스트를 직렬화한다는 U10의 접근은 그대로 쓸 수 없다.** 50자·공백 금지를 넘는 문자열은 IdP가 거부한다. 상관자에서 파생한 짧은 참조 코드만 싣고 사람이 읽을 금액·수취인은 승인 화면이 결정 조회로 가져오게 한다. 이 변경은 "`binding_message`는 표시용일 뿐 암호학적 결속이 아니며 결속은 상관자가 담당한다"는 기존 결정과 정합적이다 — 형식 제약을 명시하기만 하면 된다.
3. **`amr` 검증은 필수 조건에서 뺀다(U10, R3, AE6).** 기본 구성의 IdP가 빈 배열을 내주므로 `amr`을 충족 조건에 넣으면 위임 MFA challenge가 구조적으로 충족 불가능해진다. `acr` 허용목록·정책 요구 충족과 `auth_time` 하한을 필수로 두고, `amr`은 존재할 때만 대조하는 선택 조건으로 내린다.

반대로 계획이 이미 옳았음을 확인한 지점도 있다. **요청한 `acr`가 반영됐는지를 IdP가 알려주지 않으므로, U10이 요구하는 "`acr`가 운영자 허용목록에 속하며 정책 요구를 충족" 검증은 편의가 아니라 유일한 방어선이다.** 이 검사가 빠지면 침묵 강등된 저수준 인증이 그대로 challenge를 충족시킨다.

---

## S2. 세그먼트 감사 체인의 처리량과 check 지연 — **확정**

### 무엇을 확인했나

U4는 감사 체인을 `(writer_id, seq, prev_hash)` 세그먼트로 쪼개 인스턴스 로컬 append로 만드는 구조에 걸려 있다. 물은 것은 둘이다 — 세그먼트 분할이 실제로 자릿수를 바꾸는가, 그리고 캐시 미스를 포함한 check 경로의 저장소 왕복이 어느 자릿수인가.

**이것은 벤치마크가 아니라 자릿수 탐침이다.** 튜닝하지 않았고, 클라이언트가 DB와 같은 컨테이너 안에서 돌아 네트워크 홉이 없으며, 아래 숫자는 어떤 절대 목표의 근거로도 쓰지 않는다.

### 어떻게

`postgres:17-alpine` 컨테이너에 `audit_log(writer_id, seq, prev_hash, hash, payload, created_at)`을 PK `(writer_id, seq)`로 만들고, 자기 세그먼트의 head를 `LEFT JOIN LATERAL`로 읽어 `sha256(prev_hash || payload)`를 계산하는 단일 `INSERT ... SELECT`를 `pgbench`로 돌렸다. 각 pgbench 클라이언트가 `:client_id`로 자기 writer 세그먼트를 소유하게 해 실제 배치(인스턴스 = writer)를 흉내 냈다. 대조군은 전 클라이언트가 단일 체인 `w0`에 쓰되 `pg_advisory_xact_lock`으로 직렬화한 구성이다. check 탐침은 정책 1행과 fact 1행(20만 행 테이블)을 각각 PK로 조회하는 트랜잭션이다.

### 관측

| 구성 | 클라이언트 | TPS | 평균 지연 |
|---|---|---|---|
| 세그먼트 체인 (writer = 클라이언트) | 1 | 383 | 2.6 ms |
| 세그먼트 체인 | 8 | 4,653 | 1.7 ms |
| 세그먼트 체인 | 32 | 11,885 | 2.7 ms |
| 단일 전역 체인 (advisory lock 직렬화) | 32 | 508 | 63.0 ms |
| check 탐침 (정책 1행 + fact 1행) | 8 | 48,921 | 0.16 ms |
| check 탐침 | 32 | 40,158 | 0.80 ms |

세그먼트 append는 32 writer에서 **10⁴ 삽입/초** 자릿수이고, 같은 동시성의 단일 전역 체인은 **10²~10³** 자릿수다 — 자릿수가 하나 이상 벌어진다. 32 writer로 20초를 돌린 뒤 234,847행 · 32 세그먼트에 대해 `lag(hash)` 윈도로 재체인 검증한 결과 **끊긴 링크 0건, 해시 불일치 0건**이었다.

check 경로의 저장소 왕복은 **1 ms 미만**이다.

단일 전역 체인 대조군에서 부수적으로 하나 더 나왔다. 명시적 트랜잭션 없이 append 문만 던지면 동시 클라이언트가 즉시 `duplicate key value violates unique constraint "audit_log_pkey" ... (w0, 1)`로 죽는다. 세그먼트당 append는 그 세그먼트를 한 writer가 독점할 때만 락 없이 성립한다.

### 상태와 함의 — **확정**

세그먼트 분할이 처리량 자릿수를 바꾼다는 U4의 전제가 성립한다. 세 가지가 따라 나온다.

1. **writer_id는 인스턴스에 독점 귀속되어야 한다.** 두 프로세스가 같은 `writer_id`를 잡으면 PK 충돌로 append가 실패하며, 이것은 성능 문제가 아니라 정확성 문제다. U4의 구현은 writer 식별자 획득을 기동 시 배타적으로 처리하고, 충돌을 재시도로 덮지 말고 기동 실패로 다뤄야 한다.
2. **check 판정의 지연 예산에서 저장소는 지배 항이 아니다.** 캐시 미스 비용의 자릿수는 원격 HTTP fact source(10¹~10² ms)가 정하지 정책·fact 행 조회(10⁻¹ ms)가 정하지 않는다. U5·U6의 지연 논의는 원격 source의 타임아웃과 캐시 정책에 집중하면 된다.
3. **U4의 "삽입 처리량을 단언하지 않는다"는 판단을 유지한다.** 위 숫자는 무튜닝·같은 호스트·네트워크 홉 없음 조건이며, 공유 CI 러너에서는 재현되지 않는다. U17 벤치가 아티팩트로 기록만 하는 현재 설계가 맞다.

---

## S3. AuthZEN interop 하네스의 CI 재현성과 프로파일 선택 — **확정**

### 무엇을 확인했나

U5는 "공식 interop 적합성 통과"를 완료 증거로 삼는다. 물은 것은 둘이다 — 하네스가 CI에서 재현 가능한 형태인가, Access Evaluation 프로파일만 따로 고를 수 있는가.

### 어떻게

`openid/authzen`을 클론해 하네스의 위치와 형태를 확인하고, 의존성을 설치해 빌드한 뒤 픽스처의 기대값을 그대로 되돌려주는 폐기용 목 PDP를 세워 실제로 실행했다. 실패 경로(도달 불가 PDP)와 프로파일 변형 세 가지를 각각 돌려 종료 코드를 확인했다.

### 관측

**하네스는 리포 안의 독립 실행 스크립트다.** `interop/authzen-todo-backend/test/runner.ts` 하나와 같은 디렉터리의 JSON 픽스처가 전부다. 하네스 자체는 Todo 백엔드 애플리케이션을 띄우지 않고 `POST {PDP}/access/v1/evaluation`(과 `/evaluations`)만 때린다. `yarn install --frozen-lockfile`이 5초, `yarn build`가 2초에 끝났다 — 네이티브 빌드 없이 통과했다. 외부 서비스 의존이 없으므로 **커밋을 고정하고 픽스처를 벤더링하면 CI에서 오프라인 재현 가능하다.**

**프로파일은 스펙 변형 인자로 고른다.** `yarn test <pdp-url> <spec-version> <format>`의 두 번째 인자다.

| 변형 | `evaluation` 케이스 | `evaluations` 케이스 |
|---|---|---|
| `authorization-api-1_0-00` | 40 | 없음 |
| `authorization-api-1_0-01` (기본) | 40 | 없음 |
| `authorization-api-1_0-02` | 40 | 3 |

`-00`·`-01`은 **Access Evaluation 단건 엔드포인트만** 실행한다. 배치(`/access/v1/evaluations`)는 `-02`에만 붙는 증분이고, Subject/Resource/Action Search 프로파일은 하네스에 아예 없다. 목 PDP 상대로 `-01`을 돌려 **40/40 PASS**를 확인했고, `-02`로 돌리면 43케이스 중 배치 3건을 포함해 4건이 FAIL로 갈렸다 — 프로파일 경계가 실제로 갈린다.

**하네스는 그 자체로 CI 게이트가 되지 않는다.** `runner.ts`는 결과와 무관하게 종료 코드 0으로 끝난다. 도달 불가능한 주소를 줘서 40건 전부 ERROR가 난 실행도 종료 코드가 **0**이었다.

### 상태와 함의 — **확정**

재현 가능하고 프로파일도 선택 가능하다. U5의 적합성 범위 결정(Access Evaluation 프로파일 전량 통과)은 그대로 유지한다. 다만 U5가 구현 시 반드시 처리해야 할 것이 있다.

1. **`.github/workflows/conformance.yml`은 하네스의 종료 코드에 기대면 안 된다.** `console` 출력을 파싱해 PASS가 아닌 줄이 하나라도 있으면 실패시키는 래퍼가 필요하다. 이 래퍼 없이 잡을 물면 CI는 항상 그린이고 게이트는 조용히 비어 있게 된다 — 계획이 U1에서 `branches:` 필터를 경계한 것과 같은 종류의 실패다.
2. **적합성 목표는 `authorization-api-1_0-01`의 40케이스로 잡는다.** 배치 엔드포인트를 v1 범위에 넣지 않는다면 `-02`를 목표로 삼을 이유가 없고, 넣는다면 케이스가 3건 늘 뿐이다. 픽스처 규모는 40건이므로 U5의 `testdata/conformance/` 이식 작업량은 그 규모로 잡는다.
3. **하네스 커밋을 고정한다.** 픽스처가 리포 main에서 갱신되므로 서브모듈이나 벤더링으로 커밋을 못 박지 않으면 상류 변경이 우리 CI를 깬다. 기준 커밋은 `6fb7fa85c86acda14710f9f0f161da9aaa801a45`다.

---

## 남은 것

스파이크 코드는 폐기했다 — 이 문서 밖에 남은 산출물은 없다. 위 세 항목이 지목한 계획 변경(S1의 세 가지)은 계획서와 결정 로그의 소유자가 적용한다.

S1은 능력을 확인한 것이지 운영 적합성을 확인한 것이 아니다. 데모 IdP의 컨테이너 이미지 크기와 기동 시간은 U18의 퀵스타트 소요 시간 예산에 직접 들어가므로, U18 착수 시점에 compose 전체 기동 시간을 한 번 재고 예산을 초과하면 그때 다시 연다.

### 2026-08-11 — S1의 남은 항목 종결 (U6)

**측정했고, 예산 안이다. 다시 열지 않는다.**

데모 번들(`deploy/demo/`)이 서고 `scripts/quickstart.sh`가 완주한 실측이다. 측정 환경은 위와 같은 기계(macOS 위 리눅스 VM, Docker, 호스트 논리 코어 10)이고, Keycloak 26.4.7 · PostgreSQL 17 alpine · Apache Kafka 3.9.1이다.

| 조건 | 스크립트 시작 → 첫 판정(check) | 스크립트 시작 → 전부 완료 |
|---|---|---|
| 기본 프로파일, 데모 이미지 전부 삭제 후(모든 pull 포함) | 42s | **45s** |
| Kafka 오버레이, 같은 조건 | 38s | **43s** |
| 기본 프로파일, 이미지 캐시 상태 | 24s | 27s |

이미지 pull이 지배적이고, 컨테이너가 다 서는 데까지가 45s 중 대부분이다. `docker build --no-cache`는 별도로 29s였다(Go 모듈·npm의 `--mount=type=cache`는 설계상 유지되므로 그만큼은 따뜻한 상태다). 최악의 조합을 더해도 100초 미만이다.

AE9의 초기 목표는 15분이므로 **여유가 두 자릿수 배**다. Keycloak 이미지가 458MB로 번들에서 가장 큰 항목이지만, 그것이 예산을 위협하는 규모가 아니라는 것이 이 측정의 결론이다. 더 가벼운 IdP로 바꾸는 선택지는 열어 둘 이유가 없어졌다.

CI는 매 PR마다 두 프로파일 각각을 진짜 깨끗한 러너에서 돌리고 `deploy/demo/.run/quickstart-timings-<profile>.txt`를 아티팩트로 올린다 — 위 숫자가 회귀하면 그 아티팩트에서 보인다.
