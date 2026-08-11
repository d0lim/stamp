---
contract: policy-schema
version: 1.0.0
source: internal/policy
---

# 정책 스키마 계약

정책 문서의 형식과 의미를 정하는 계약이다. 공개 계약 3종 중 하나이며 semver로 버전 관리한다(R11). 정본은 `internal/policy`의 Go 타입과 YAML 코덱이고, 이 문서는 그 정본을 사람이 읽는 형태로 옮긴 것이다 — 둘이 어긋나면 코드가 이긴다.

`apiVersion`의 메이저는 이 계약의 메이저와 같다. 문서 봉투가 `stamp/v1`인 동안 이 계약은 1.x다.

## 버전 규칙

| 변경 | 등급 |
|---|---|
| 필드·노드 종류·challenge 종류·source 종류의 제거나 의미 변경, 기존 문서를 거부하게 만드는 검증 강화 | major |
| 선택 필드 추가, 새 노드 종류·challenge 종류·source 종류 추가, 새 진단 코드 추가 | minor |
| 기존 문서의 해석을 바꾸지 않는 수정 | patch |

`apiVersion: stamp/v1`을 명시한 문서는 1.x 전체에서 계속 읽힌다. 알 수 없는 `apiVersion`은 `unknown_api_version` 진단으로 거부하며 추측하지 않는다.

## 문서 봉투

파일은 YAML 스트림이고 문서 하나가 스키마 하나 또는 정책 하나다. 모든 문서가 두 필드를 갖는다.

```yaml
apiVersion: stamp/v1
kind: Schema   # 또는 Policy
```

정책의 식별자는 문서 안의 `id`이지 파일 이름이 아니다(`docs/file-authoring.md`).

## 스키마 문서

```yaml
apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes:
      department: string
      clearance: int
actions:
  - transfer
  - name: refund
    description: 결제 취소
sources:
  - name: daily_transfer_total
    kind: event
    params:
      - {account: string}
    returns: double
    on_error: deny
```

- **`entities`** — `name`과 `attributes`(속성 이름 → 타입). 속성 이름과 엔티티 이름은 `^[a-z][a-z0-9_]*$`.
- **`actions`** — 이름만 쓰거나 `{name, description}`. 이름은 `^[a-z0-9][a-z0-9._-]*$`.
- **`sources`** — `name`, `kind`, `params`, `returns`, `on_error`. `params`는 단일 키 매핑의 목록이고 **선언 순서가 곧 호출 규약이라 정렬되지 않는다.**

**타입**: `bool`, `int`, `double`, `string`, `timestamp`, `duration`, 그리고 리스트 `list<타입>`. 순서 비교(`lt`, `le`, `gt`, `ge`)는 `bool`과 리스트에 쓸 수 없다.

**source 종류**: `static`, `http`, `event`, `idp_group`. 각 종류의 전송 설정(URL, 자격증명, TTL)은 정책 문서가 아니라 운영자 배포 설정에 있다 — 정책은 이름만 부른다(D21).

**`on_error`**: `deny`(기본) 또는 `allow`. `allow`는 운영자가 `STAMP_FACT_ALLOW_FAIL_OPEN`을 켠 배포에서만 적재된다(R36).

## 정책 문서

```yaml
apiVersion: stamp/v1
kind: Policy
id: high-value-transfer
description: 한도 초과 이체
subject: user
resource: account
context: request        # 선택
actions: [transfer]
condition:
  all:
    - {left: {field: request.amount}, op: gt, right: 10000}
    - {left: {field: user.department}, in: [finance, treasury]}
challenges:
  - type: quorum
    threshold: 2
    approvers: {claim: manager_of}
```

`subject`, `resource`, `context`는 조건식이 참조할 수 있는 세 역할이고, 선언되지 않은 역할을 참조하면 `unbound_role`로 거부된다.

정책에는 **허용·거부 필드가 없다.** 정책은 성립하거나 성립하지 않을 뿐이고, challenge를 하나라도 지닌 정책은 무상태 check 경로에서 답할 수 없는 정책이라는 뜻이다 — 그 판정이 `check`와 `decide`를 가르는 유일한 기준이다(D3).

## 조건식

노드는 세 종류뿐이고 확장 지점이 없다. 이것이 조건식이 종료성과 비용을 보장할 수 있는 이유다(D12).

| 노드 | YAML | 비고 |
|---|---|---|
| 논리 | `{all: [...]}`, `{any: [...]}`, `{not: <조건>}` | `not`은 단일 피연산자이며 목록이 아니다 |
| 비교 | `{left: <피연산자>, op: <연산자>, right: <피연산자>}` | `op`는 `eq`, `ne`, `lt`, `le`, `gt`, `ge` |
| 포함 | `{left: <피연산자>, in: <피연산자>}`, `{left: ..., not_in: ...}` | |

피연산자는 셋이다.

| 피연산자 | YAML |
|---|---|
| 필드 참조 | `{field: "<역할>.<속성>"}` |
| source 호출 | `{source: "<이름>", args: [...]}` |
| 리터럴 | 맨 스칼라·시퀀스, 또는 `{value: ..., type: "<타입>"}` |

YAML이 추론할 수 없는 타입(`timestamp`, `duration`, 빈 리스트)은 `type`을 함께 적는다. `timestamp`는 RFC3339Nano UTC로, `duration`은 Go의 기간 표기(`72h`)로 직렬화된다.

## challenge 선언

challenge 종류는 넷이고 닫혀 있다. 각 종류의 의미와 처리 규약은 [challenge 인터페이스 계약](challenge-interface.md)이 정한다.

| 종류 | 필드 |
|---|---|
| `quorum` | `threshold`, `approvers` |
| `mfa` | `mode`(`delegated` 기본, `direct`는 선언만 되고 적재 시 거부), `acr_values` |
| `delay` | `duration`, `cancellable_by`(선택) |
| `external` | `target` — 운영자 허용목록의 항목 이름이며 URL이 아니다 |

승인자 집합은 셋 중 정확히 하나다: `{members: [...]}`, `{claim: "..."}`, `{source: ..., args: [...]}`.

## 정규화와 왕복

`Set.Normalize`는 엔티티·액션·source·정책을 이름순으로, 속성을 이름순으로, challenge를 종류 순으로 정렬하고 기본값을 채운다. source의 `params`만 선언 순서를 지킨다. 내보내기 → 적용이 무변경인 것은 이 정규화의 결과다(U19).

## 검증

거부는 JSON Pointer를 지닌 진단 목록으로 반환된다. 코드는 다음과 같다.

`invalid_yaml`, `invalid_document`, `unknown_api_version`, `unknown_kind`, `unknown_key`, `missing_field`, `invalid_name`, `invalid_value`, `unknown_type`, `duplicate`, `unknown_entity`, `unknown_action`, `unknown_attribute`, `unbound_role`, `unknown_source`, `type_mismatch`, `arity_mismatch`, `invalid_operand`, `invalid_operator`, `limit_exceeded`, `unknown_challenge`, `unsupported`, `cel_compile`.

**알 수 없는 키는 무시가 아니라 거부다**(`unknown_key`). 오타 난 필드가 조용히 사라지면 의도한 통제가 없는 정책이 통과한다.

기본 상한: 문서 1MiB, 정책 1000개, 조건식 노드 512개, 조건식 깊이 32. 운영자가 `STAMP_APPLY_MAX_*`로 낮출 수 있다.
