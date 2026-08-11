---
contract: decision-api
version: 1.0.0
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
| `POST /decisions/{id}/challenges/{ordinal}/approvals` | console | user | `decide` |
| `GET /decisions/{id}/challenges/{ordinal}/approval` | console | user | `decide` |
| `POST /decisions/{id}/challenges/{ordinal}/cancellation` | console | user | `decide` |
| `GET /decisions/inbox` | console | user | `decide` |
| `GET /audit/decisions` | console | user | `decide` |
| `GET /audit/decisions/{id}` | console | user | `decide` |
| `POST /decisions/{id}/challenges/{ordinal}/mfa` | callback | public | `decide` |
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

## 이 버전에 없는 것

**결정을 생성하는 HTTP 엔드포인트는 1.0.0에 없다.** `decide()`는 Go 진입점(`runtime.DecisionPath`)으로 존재하고 승인·취소·조회·콜백은 위 표대로 노출되지만, 결정을 여는 호출은 아직 라우트로 마운트되지 않았다. 엔드포인트 추가는 minor 변경이므로 이 계약은 1.1.0에서 그것을 얻는다.

콘솔이 부르는 부분집합의 문서 형식(`console/contract/public-endpoints.json`)에는 자체 버전 필드가 있으며, 그것은 **문서의 모양**을 세는 번호이지 이 계약의 버전이 아니다.
