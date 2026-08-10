---
contract: challenge-interface
version: 1.0.0
source: internal/challenge
---

# challenge 인터페이스 계약

결정이 정책 평가만으로 답할 수 없는 부분 — 모아야 할 정족수, 완료해야 할 step-up, 흘러야 할 지연, 답해야 할 외부 시스템 — 의 처리 규약이다. 공개 계약 3종 중 하나이며 semver로 버전 관리한다(R11). 정본은 `internal/challenge/contract.go`이고 그 파일의 `ContractVersion` 상수가 이 문서의 `version`과 같아야 한다 — 릴리즈 워크플로가 대조한다.

결정 수명주기는 challenge를 **언제** 열고 그 결과가 결정에 **무엇을** 하는지를 소유하고, 이 계약은 둘 사이 대화의 **모양**만 소유한다.

## 버전 규칙

정본의 서술을 그대로 옮긴다.

| 변경 | 등급 |
|---|---|
| `Handler`에 메서드 추가, 메서드 시그니처 변경, `State` 값의 의미 변경 | major |
| 요청·결과 구조체에 필드 추가, `Targeter` 같은 선택 인터페이스 추가 | minor |

## 동사는 셋이다

```go
type Handler interface {
    Kind() policy.ChallengeType
    Issue(ctx context.Context, req IssueRequest) (IssueResult, error)
    Submit(ctx context.Context, req SubmitRequest) (SubmitResult, error)
    Status(ctx context.Context, req StatusRequest) (Status, error)
}
```

네 번째 동사는 없다. 특히 **"마감이 지났다, 이제 어떻게 하나"라는 동사가 없다** — 스위퍼가 현재 시각으로 `Status`를 물으면 지연은 satisfied를, 정족수는 pending을 답한다. 마감 경과의 의미가 종류마다 정반대라 별도 콜백은 반드시 한쪽을 틀린다.

선택 인터페이스는 하나다.

```go
type Targeter interface {
    IsTarget(ctx context.Context, req TargetRequest) (bool, error)
}
```

구현하지 않은 핸들러는 대상이 없는 것으로 취급한다 — 조회 권한은 fail-closed다(R40).

## 상태

`pending`, `satisfied`, `failed`, `cancelled`. 뒤의 셋이 종결 상태다.

## 핸들러는 자기 detail을 저장한다, 선언이 아니라

`Issue`는 정책의 선언을 받아 `Detail`을 돌려주고, 수명주기는 그것을 challenge 행에 저장해 `Submit`과 `Status`에 그대로 되돌린다. 나중에 필요한 임계값이나 승인자 집합은 핸들러가 `Detail`에 넣는다. 그래야 challenge가 열린 조건이 fact 스냅샷·정책 버전과 함께 동결되고, 이 패키지가 정책 AST를 직렬화할 이유가 사라진다.

## `Submit`은 재계산 가능해야 한다

핸들러가 쓰는 증거 행과 수명주기가 쓰는 challenge 상태는 **두 개의 진술이지 하나가 아니다.** 따라서 `Submit`은 멱등이어야 하고(중복 제출은 한 번으로 센다), `Status`는 핸들러가 저장한 것만으로 진행도를 재계산할 수 있어야 한다 — 둘 사이에서 크래시가 나면 증거는 쓰였고 상태는 아직 갱신되지 않은 채로 남기 때문이다.

## 자료형

| 형 | 필드 |
|---|---|
| `Instance` | `DecisionID`, `Ordinal`, `Kind` |
| `DecisionContext` | 동결된 결정 내용 |
| `IssueRequest` | `Instance`, `Spec`, `Decision`, `Now` |
| `IssueResult` | `State`, `Detail`, `Deadline` |
| `SubmitRequest` | `Instance`, `Decision`, `Detail`, `Submitter`, `Payload`, `Now` |
| `SubmitResult` | `State`, `Have`, `Need`, `Detail` |
| `StatusRequest` | `Instance`, `Decision`, `Detail`, `Stored`, `Deadline`, `Now` |
| `Status` | `State`, `Have`, `Need`, `Deadline`, `Detail` |

## 오류

`ErrNoHandler`, `ErrDuplicateHandler`, `ErrNotSubmittable`, `ErrNotTarget`, `ErrInvalidPayload`, `ErrUnsupportedSpec`. 호출자는 `errors.Is`로 분기한다. **핸들러가 없는 종류는 만족될 수 없다** — 없음이 기본 허용으로 해석되지 않는다.

레지스트리는 한 종류에 두 핸들러를 등록하면 오류를 반환하며, 등록 해제는 없다.

## 종류별 detail

`Detail`은 저장되고 그대로 되돌려지는 값이므로 그 JSON 표현이 계약의 일부다.

| 종류 | detail 필드 | 제출 |
|---|---|---|
| `quorum` | `threshold`, `mode`, `issuer`, `members`, `claim`, `source`, `binding_hash` | `{verdict, binding_hash}` |
| `delay` | `duration`, `release_at`, `cancellable_by`, `cancelled_by`, `cancelled_at` | `{action}` |
| `external` | `target`, `nonce`, `requested_at`, `respond_by`, `acknowledged`, `failure`, `verdict`, `responded_at` | `{nonce, verdict, signature}` |
| `mfa` | `mfa.Detail`(`internal/challenge/mfa`) | `mfa.Submission` |

`mode`는 승인자 집합이 어떻게 해소되었는지다: `members`, `claim`, `source`.

외부 challenge의 발신 본문은 `ExternalNotification`이고, 수신 콜백의 서명은 `X-Stamp-Signature` 헤더로 온다. 대상 URL은 정책이 아니라 운영자 허용목록에서 온다.

MFA는 v1에서 위임 모드만 구현한다(D16). `direct`는 계약에만 정의되어 있고 적재 시 `ErrUnsupportedSpec`으로 거부된다 — 미구현을 침묵으로 두지 않는다.
