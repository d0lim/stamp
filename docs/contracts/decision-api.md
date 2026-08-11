---
contract: decision-api
version: 1.4.0
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
| `/console/` (하위 트리) | console | static | `console` |
| `/console` (하위 트리로의 리다이렉트) | console | static | `console` |

**이 표는 `internal/release`가 실제 마운트 표와 대조한다.** 마운트됐는데 행이 없거나, 행이 있는데 아무 컴포넌트도 마운트하지 않거나, 표면·인증·역할이 다르면 CI가 빨개진다([#44](https://github.com/d0lim/stamp/issues/44)). 버전 문자열 비교로는 구조적으로 잡을 수 없던 것이다. **1.3.1은 그 대조가 처음 잡은 것을 반영한다** — 하위 트리 리다이렉트 `/console`이 표에 없었고, 하위 트리 라우트가 `GET`을 싣는 것처럼 적혀 있었다. 엔드포인트는 하나도 바뀌지 않았고 문서만 고쳐졌다(의미를 바꾸지 않는 수정 = patch). 인증 없는 `GET /healthz`는 이 표에 없다 — 역할과 무관하게 리스너가 직접 답하므로 네 번째 열이 가리킬 역할이 없다.

**콘솔의 두 정적 라우트는 메서드를 싣지 않는다.** net/http는 경로가 맞고 메서드가 다른 패턴에 405를 답하므로, `GET /console/` 하위 트리를 선언하면 콘솔만 서빙하는 티어가 `POST /console/v1/policies/dry-run`에 405를 답한다 — 그 엔드포인트를 서빙하지 않는 유일한 티어가 "여기 있다"고 말하는 것이다. 메서드 판정은 핸들러 안으로 옮겨져 404로 돌아온다.

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

오류 응답은 `{"error": "...", "message": "..."}`다 — 코드 어휘는 아래 "`error` 코드 어휘"가 기술한다.

## 헤더

| 헤더 | 뜻 |
|---|---|
| `X-Stamp-Surface` | `/healthz`가 어느 리스너에서 답했는지 |
| `X-Stamp-Bootstrap-Token` | 잠금 전 거버넌스 요청이 일회용 부트스트랩 토큰을 싣는 자리 |
| `X-Stamp-Signature` | 외부 challenge 콜백의 서명 |
| `X-Stamp-Component` | 콘솔 서빙 응답의 표식 |
| `Retry-After` | 속도 한도로 거부된 응답에만 붙는다. 값은 그 예산의 **재충전 간격**(초) |

**`Retry-After`는 속도 한도 거부에만 붙고, 정책 deny에는 붙지 않는다.** 정책 deny는 판정이고 판정은 타이머로 만료되지 않는다 — 재시도하면 영원히 같은 답이다. 두 deny를 전송 수준에서 가르는 것이 이 헤더이므로 양쪽에 붙이면 아무 데도 안 붙인 것보다 나쁘다.

값은 **버킷이 가득 차기까지**가 아니라 **토큰 하나가 다시 생기기까지**다. 거부된 호출자에게 필요한 것은 한 번 더 보낼 수 있는 시각이고, 그 위의 burst는 이미 쓴 여유다. 초 단위로 올림한다(하한 1초, 상한 3600초).

`decide`에서 이 헤더는 **`200` 응답에 붙는다.** RFC 9110이 명시한 자리(429·503·3xx)가 아니라는 것을 알고 그렇게 한다 — 아래 "deny의 `reason`"이 말하듯 속도 한도 거부는 **결정 객체**이고 그 성질은 바꾸지 않는다. 승인 제출의 거부는 `429`이고, 거기서는 헤더가 명세 그대로의 자리에 있다.

## decide

`POST /decisions`가 결정을 만든다. 요청 본문은 **check와 같은 모양**(AuthZEN Access Evaluation 요청)에 선택 필드 `ttl`(기간 문자열, 상한 `DefaultMaxDecisionTTL` = 24h)이 더해진 것이다 — PEP가 두 호출을 같은 입력으로 부를 수 있어야 하기 때문이다. **응답은 AuthZEN이 아니다.** `decision.Result`이고 R2가 요구하는 넷을 싣는다: 상태, 요구 challenge와 수집 현황(`have`/`need`), 만료 시각, obligation.

상태 코드가 **요청의 유효성이 아니라 결과**를 따른다:

| 결과 | 상태 | 본문 |
|---|---|---|
| 결정이 생성됨(pending 또는 allow) | `201` + `Location: /decisions/{id}` | `id` 있음 |
| deny | `200` | `id` 없음 — deny는 결정 행을 만들지 않는다 |

그래서 **클라이언트는 상태 코드만으로 `id`의 존재를 판단할 수 없다.** 양쪽 모두 `state`와 `id`를 읽어야 한다.

`GET /decisions/{id}`는 **생성 호출자에게만** 열린다(R40). 대상 승인자를 위한 조회는 콘솔 표면의 `GET /audit/decisions/{id}`다 — 워크로드 자격과 사용자 토큰은 하나의 라우트가 함께 서빙할 수 없다. **권한 없는 조회와 존재하지 않는 결정은 응답 바이트까지 구분되지 않는다**: 결정의 존재 여부가 새면 안 된다. 1.4.0부터 이것은 콘솔 쪽 네 표면에서도 같다 — 아래 "`error` 코드 어휘"를 보라.

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

| `reason` | 뜻 | 재시도 | `Retry-After` |
|---|---|---|---|
| 정책이 낸 값(`policy_matched` 등) | 정책 판정 | 아니오 | 없음 |
| `outstanding_cap` | 주체의 미결 결정 상한 초과 (R43) | 미결이 해소된 뒤 | 없음 — 기다릴 시간이 아니라 다른 결정이 닫히는 사건이 조건이다 |
| `rate_limited` | 호출자 또는 주체별 속도 한도 초과 (R43) | 예 — 창이 지나면 | 있음 (1.4.0, [#45](https://github.com/d0lim/stamp/issues/45)) |

**속도 한도는 인스턴스별이다.** 레플리카 N개는 실효 한도가 설정값의 N배다. 절대 상한은 미결 상한이 DB 기반으로 클러스터 전역에 건다.

## `error` 코드 어휘

오류 응답은 `{"error": "...", "message": "..."}`이고, **`error`는 기계가 읽는 코드, `message`는 사람이 읽는 문장**이다. 클라이언트는 `error`로 분기하고 `message`로는 분기하지 않는다 — 문장은 예고 없이 다듬어진다.

**`error`와 `reason`은 다른 어휘다.** `reason`은 **결정이 존재할 때** 그 결정이 무엇을 근거로 났는지이고(엔진의 말), `error`는 **결정이 나지 않았을 때** 표면이 하는 말이다. 같은 문자열을 양쪽에서 쓰면 "답이 없다"와 "이 근거로 답했다"가 클라이언트에게 한 사건이 된다.

**같은 서버 상태는 어느 표면에서도 같은 코드를 받는다.** 이것이 1.4.0이 고친 것이다.

| `error` | 상태 | 뜻 |
|---|---|---|
| `unauthenticated` | `401` | 이 엔드포인트가 요구하는 자격이 없다 |
| `invalid_request` | `400` | 본문·경로·쿼리가 이 엔드포인트의 모양이 아니다 |
| `invalid_property` · `invalid_submission` · `unsupported_verdict` | `400` | 값이 스키마나 challenge가 받는 모양이 아니다 |
| `not_found` | `404` | **그 결정을 가질 수 없다.** 없거나, 권한이 없거나, 대상이 아니거나 — 셋이 한 답이다 |
| `not_an_auditor` | `403` | 결정 **이력**을 읽을 자격이 없다. 특정 결정에 대해서는 아무것도 말하지 않는다 (R22) |
| `expired` · `not_collecting` · `material_changed` | `409` | 결정·challenge의 현재 상태가 그 동작을 받지 않는다 |
| `rate_limited` | `429` | 승인 제출이 승인자별 예산을 넘었다 (R43). decide의 속도 거부는 오류가 아니라 deny다 |
| `not_installed` | `503` | 이 배포에 정책 집합·스키마·거버넌스가 아직 설치되지 않았다 |
| `unsupported_challenge` | `501` | 정책이 요구하는 challenge kind를 이 빌드가 다루지 못한다 |
| `internal_error` | `500` | 서버 쪽 실패. 원인은 서술되지 않으며 감사 체인에 있다 |

**`not_found`가 넓은 것이 의도다.** R40은 결정 조회를 생성 호출자 또는 대상 승인자로 제한하는데, 거부와 부재가 다른 답을 주면 식별자 하나로 "그 결정이 존재하는가"를 물을 수 있다. 그래서 decide 표면(`GET /decisions/{id}`)뿐 아니라 **승인 제출·승인 화면 조회·위임 취소·감사 상세 조회에서도 응답 바이트까지 같다.** 1.3.1까지 콘솔 쪽 네 곳은 `403 not_an_approver`·`403 not_readable`을 답했다([#38](https://github.com/d0lim/stamp/issues/38)).

**대가는 실재한다.** 승인자 집합이 개정으로 바뀌어 자격을 잃은 사람도 "없는 결정"이라는 답을 받는다. 그 사람에게 사실을 말하는 자리는 **승인함**(`GET /decisions/inbox`)이다 — 기다리는 것만 담긴 목록은 담기지 않은 것으로 아무것도 새게 하지 않는다.

**MFA 콜백의 403은 이 통합에서 제외된다.** 그 표면은 `acr_not_allowed`·`acr_unsatisfied`·`amr_mismatch`·`stale_authentication`·`correlator_mismatch`·`credential_mismatch`·`nonce_mismatch`를 각각 다른 코드로 답한다. 독자가 공격자가 아니라 **운영자**이고, IdP 오설정과 정책 요구를 구분하지 못하면 아무도 완결시킬 수 없는 step-up 앞에서 원인을 알 수 없기 때문이다. 결정의 존재 여부는 그 코드들 이전에 이미 균일한 `403` 한 장이 가린다(위 "step-up 콜백" 참조).

### 1.4.0이 바꾼 것과 등급

- `Retry-After`가 속도 한도 거부에 붙는다 — **응답 필드 추가 = minor.**
- decide의 정책 집합 부재가 `policy_set_stale` 대신 `not_installed`을 답한다.
- 콘솔의 네 표면에서 "권한 없음"이 "없음"과 응답 바이트까지 같아진다.

뒤의 둘은 **와이어에서 보이는 답을 바꾼다.** major로 올리지 않는 근거는 하나다: **이 문서가 그 둘을 약속한 적이 없다.** `error` 어휘는 1.3.1까지 문서화되지 않았고(그 사실이 "아직 말하지 않는 것"에 적혀 있었다), 콘솔 표면의 상태 코드도 표에 없었다. 반대로 **불구분 규칙은 1.1.0부터 이 문서에 적혀 있었고** 코드가 그것을 지키지 않았다. 그래서 이것은 계약을 깨는 변경이 아니라 계약에 코드를 맞춘 변경이다.

그래도 **`403 not_an_approver`나 `policy_set_stale`을 와이어에서 하드코딩한 클라이언트는 깨진다.** 이 문단이 그 사실을 숨기지 않으려고 있다.

## 이 계약이 아직 말하지 않는 것

`Retry-After`는 **이 인스턴스의** 예산을 말한다. 레플리카가 여럿이면 다음 요청이 다른 인스턴스로 가고, 그쪽 버킷은 다른 상태다 — 헤더는 "여기서는 이만큼"이지 "클러스터가 이만큼"이 아니다.

콘솔이 부르는 부분집합의 문서 형식(`console/contract/public-endpoints.json`)에는 자체 버전 필드가 있으며, 그것은 **문서의 모양**을 세는 번호이지 이 계약의 버전이 아니다.
