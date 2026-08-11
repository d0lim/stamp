---
contract: decision-api
version: 1.3.0
source: internal/api
---

# 결정 API 계약

엔진이 HTTP로 노출하는 표면이다. 공개 계약 3종 중 하나이며 semver로 버전 관리한다(R11). 정본은 `internal/api`의 라우트 선언이고, 콘솔이 부르는 부분집합은 `internal/api/contract.go`에서 기계가 읽는 형태로 따로 내보내진다 — 콘솔은 이 계약 밖의 엔드포인트를 갖지 않으며 CI가 검사한다(D19).

경로의 `v1`은 이 계약의 메이저와 같다.

## 버전 규칙

| 변경 | 등급 |
|---|---|
| 엔드포인트 제거, 경로·메서드·인증 요건 변경, 응답 필드 제거나 의미 변경, 요청 필드의 필수화 | major |
| 엔드포인트 추가, 선택 요청 필드 추가, 응답 필드 추가 | minor |
| 의미를 바꾸지 않는 수정 | patch |

## 표면은 셋이고, 경로 접두사가 아니라 리스너다

| 표면 | 기본 주소 | 허용 인증 | 호출자 |
|---|---|---|---|
| PEP | `:8080` | workload | 클라이언트 자격증명을 든 워크로드 |
| console | `:8081` | user, static | 최종 사용자 토큰을 든 운영자·승인자 |
| callback | 미바인딩 | workload, public | challenge를 완료시키는 외부 시스템 |

한 표면에 마운트된 라우트는 다른 표면으로 도달할 수 없다. 다른 리스너의 라우터는 그 라우트를 들어본 적이 없다 — 404이지 403이 아니다. 이것이 콜백 수신 표면을 PEP·콘솔 표면과 분리해 노출하라는 R39의 이행 형태다.

역할이 꺼진 프로세스도 마찬가지다. 활성이 아닌 역할의 엔드포인트는 그 프로세스에서 404다.

모든 표면이 인증 없는 `GET /healthz`를 답하고, 응답에 어느 리스너가 답했는지를 담은 `X-Stamp-Surface` 헤더가 붙는다. **이것은 살아 있음 신호일 뿐 준비 신호가 아니다** — 데이터베이스도 감사 버퍼도 조회하지 않는다.

## 엔드포인트

| 메서드·경로 | 표면 | 인증 | 역할 |
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
| `GET /console/` (하위 트리) | console | static | `console` |

두 콜백 엔드포인트가 `public`인 것은 인증이 없다는 뜻이지 통제가 없다는 뜻이 아니다. 외부 콜백은 서명(`X-Stamp-Signature`)과 서버가 발급한 nonce로, MFA 콜백은 서버가 개시한 상관자로 결속된다 — 표시용 값이 아니라 그쪽이 결속의 정본이다(D16).

## AuthZEN check

`POST /access/v1/evaluation`은 AuthZEN Access Evaluation이다(D4).

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

네 개의 네임스페이스 키는 항상 존재한다. `stamp.obligations`는 check 경로에서 **항상 비어 있다** — obligation은 결정과 함께 오며, 없는 것과 빈 것을 구별할 수 없게 만들지 않으려고 키 자체는 남긴다.

**평가 실패는 500이 아니라 deny다.** 요청 본문 상한은 1MiB이고, 감사 버퍼가 fail-closed 상태로 포화되면 본문을 읽기 전에 deny한다.

오류 응답은 `{"error": "...", "message": "..."}`다.

## 헤더

| 헤더 | 뜻 |
|---|---|
| `X-Stamp-Surface` | `/healthz`가 어느 리스너에서 답했는지 |
| `X-Stamp-Bootstrap-Token` | 잠금 전 거버넌스 요청이 일회용 부트스트랩 토큰을 싣는 자리 |
| `X-Stamp-Signature` | 외부 challenge 콜백의 서명 |
| `X-Stamp-Component` | 콘솔 서빙 응답의 표식 |

## decide

`POST /decisions`가 결정을 만든다. 요청 본문은 **check와 같은 모양**(AuthZEN Access Evaluation 요청)에 선택 필드 `ttl`(기간 문자열, 상한 `DefaultMaxDecisionTTL` = 24h)이 더해진 것이다 — PEP가 두 호출을 같은 입력으로 부를 수 있어야 하기 때문이다. **응답은 AuthZEN이 아니다.** `decision.Result`이고 R2가 요구하는 넷을 싣는다: 상태, 요구 challenge와 수집 현황(`have`/`need`), 만료 시각, obligation.

상태 코드가 **요청의 유효성이 아니라 결과**를 따른다:

| 결과 | 상태 | 본문 |
|---|---|---|
| 결정이 생성됨(pending 또는 allow) | `201` + `Location: /decisions/{id}` | `id` 있음 |
| deny | `200` | `id` 없음 — deny는 결정 행을 만들지 않는다 |

그래서 **클라이언트는 상태 코드만으로 `id`의 존재를 판단할 수 없다.** 양쪽 모두 `state`와 `id`를 읽어야 한다.

`GET /decisions/{id}`는 **생성 호출자에게만** 열린다(R40). 대상 승인자를 위한 조회는 콘솔 표면의 `GET /audit/decisions/{id}`다 — 워크로드 자격과 사용자 토큰은 하나의 라우트가 함께 서빙할 수 없다. **권한 없는 조회와 존재하지 않는 결정은 응답 바이트까지 구분되지 않는다**: 결정의 존재 여부가 새면 안 된다.

### challenge 뷰

`challenges[]`의 각 항목은 challenge 하나의 진행 상황이다.

| 필드 | 뜻 | 언제 나타나는가 |
|---|---|---|
| `ordinal` | 결정 안에서의 challenge 번호 | 항상 |
| `kind` | `quorum` · `mfa` · `delay` · `external` | 항상 |
| `state` | `pending` · `satisfied` · `failed` · `cancelled` | 항상 |
| `have` · `need` | 수집 현황 | 항상 |
| `deadline` | 그 challenge의 타이머 | 타이머가 있을 때 |
| `authorization_url` | **주체의 브라우저를 보낼 곳** | 브라우저로 완결되는 kind에서만 |

**`authorization_url`은 1.2.0에서 더해졌다**(응답 필드 추가 = minor). 위임 MFA가 step-up 리다이렉트로 완결되는데(D26) 그 주소가 challenge 행에만 있고 어떤 응답에도 실리지 않아, 호출자가 주체를 어디로 보낼지 알 수 없었다([#41](https://github.com/d0lim/stamp/issues/41)). quorum·delay·external은 이 필드를 갖지 않으며 이전과 **바이트까지 동일하게** 직렬화된다.

**뷰에 실리는 것은 challenge 핸들러가 이름으로 고른 것뿐이다.** challenge 행의 `detail`은 저장용이고 correlator·nonce·PKCE verifier를 담는다 — 그것들은 뷰로 가지 않으며, 갈 수 있는 통로 자체가 없다. 결정 레이어는 특정 challenge kind를 알지 못하므로(선택적 `challenge.Viewer` 인터페이스로만 묻는다) 저장된 값을 스스로 꺼내 실을 수 없다.

**1.2.0의 "알려진 노출"은 닫혔다.** 그때는 step-up 인가 요청이 correlator를 `state`로 실었고, URL이 응답에 실리면서 correlator가 호출자와 브라우저에 도달했다. 1.3.0의 `state`는 challenge마다 새로 만드는 CSRF 토큰이다(KTD2) — correlator는 어떤 URL에도 나타나지 않고, PKCE verifier도 마찬가지다. challenge를 식별하는 것은 콜백 **경로**다.

### step-up 콜백

`GET /decisions/{id}/challenges/{ordinal}/mfa`는 IdP가 주체의 브라우저를 되돌려 보내는 곳이다. 기존 `POST`는 그대로 남는다 — CIBA 경로와 모의 OP 검증이 그것을 쓴다.

| 쿼리 파라미터 | 뜻 |
|---|---|
| `code` | 인가 코드. STAMP가 challenge 행의 verifier로 교환한다 |
| `state` | 이 challenge가 발급한 CSRF 토큰. 다르면 토큰 교환 **이전에** 거절된다 |
| `error` · `error_description` | IdP가 거절한 경우 |

**응답은 사람이 읽는 HTML이다.** 이 라우트에 도착하는 것은 방금 비밀번호를 입력한 사람이고, 다른 콜백처럼 JSON 403을 주면 무엇이 잘못됐는지 알 수 없다. 페이지는 스크립트·스타일·외부 참조를 하나도 갖지 않으며 `default-src 'none'` CSP와 `Referrer-Policy: no-referrer`를 함께 낸다 — URL의 쿼리에 인가 코드가 들어 있으므로 리퍼러 억제가 형식이 아니라 방어다.

상태 코드는 두 구간으로 나뉜다.

| 구간 | 답 |
|---|---|
| `state`가 확인되기 **전**의 모든 실패 — 없는 결정, 없는 challenge, 틀린 `state`, 교환되지 않는 코드, 이미 닫힌 challenge | **`403` 하나, 같은 페이지 하나.** 상태 코드로 결정 식별자의 존재를 알아낼 수 없어야 한다(`POST /external`의 균일 403과 같은 이유) |
| 교환에 성공한 **뒤**의 실패 — 약한 `acr`, 오래된 `auth_time`, 어긋난 `nonce`, 이미 소비된 correlator | 무엇을 할 수 있는지 말하는 페이지. 이 지점의 상대는 `state`를 쥔 주체이지 낯선 사람이 아니다 |
| STAMP 쪽 장애 | `500`과 "아무것도 기록되지 않았다" |

**충족되지 않은 `acr`는 이 경로에서도 거절된다.** S1이 확인했듯 IdP는 충족하지 못한 `acr` 요청을 오류가 아니라 침묵 강등으로 답하므로, 교환된 `id_token`의 `acr` 검증이 유일한 방어선이다. 판정은 challenge 핸들러 한 곳에서만 일어나고 콜백 표면은 아무것도 판정하지 않는다.

**PKCE는 선택이 아니다.** 인가 요청은 `code_challenge`와 `code_challenge_method=S256`을 싣는다. 데모 realm의 `stamp-stepup`처럼 challenge method가 등록된 클라이언트에서 Keycloak은 그것을 **요구사항**으로 읽고, 없는 요청을 `error=invalid_request`로 거절한다(U2 실측). verifier는 challenge 행에 살며(KTD3) 어떤 응답에도 나가지 않는다.

### deny의 `reason`

`state: denied`는 최종 판정일 수도, 일시적 셰딩일 수도 있다. **구분자는 `reason` 하나뿐이다.**

| `reason` | 뜻 | 재시도 |
|---|---|---|
| 정책이 낸 값(`policy_matched` 등) | 정책 판정 | 아니오 |
| `outstanding_cap` | 주체의 미결 결정 상한 초과 (R43) | 미결이 해소된 뒤 |
| `rate_limited` | 호출자 또는 주체별 속도 한도 초과 (R43) | 예 — 창이 지나면 |

**속도 한도는 인스턴스별이다.** 레플리카 N개는 실효 한도가 설정값의 N배다. 절대 상한은 미결 상한이 DB 기반으로 클러스터 전역에 건다.

### 이 계약이 아직 말하지 않는 것

`rate_limited`가 전송 수준 신호(`Retry-After` 등)를 갖지 않는다 — 중간의 재시도 미들웨어·게이트웨이·대시보드는 성공한 요청만 본다. [#45](https://github.com/d0lim/stamp/issues/45).

**`error` 코드 어휘가 문서화되지 않았다.** decide는 정책 집합 부재를 `503 policy_set_stale`로 답하는데, 같은 상태를 `GET /policies`는 `503 not_installed`로 답한다. 어느 쪽이 정본인지 정해지지 않았다 — 같은 [#45](https://github.com/d0lim/stamp/issues/45).

콘솔이 부르는 부분집합의 문서 형식(`console/contract/public-endpoints.json`)에는 자체 버전 필드가 있으며, 그것은 **문서의 모양**을 세는 번호이지 이 계약의 버전이 아니다.
