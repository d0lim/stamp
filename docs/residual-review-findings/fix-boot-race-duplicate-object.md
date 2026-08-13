# 잔여 리뷰 findings — `fix/boot-race-duplicate-object`

계획: `docs/plans/2026-08-14-001-fix-concurrency-and-saturation-plan.md` (U1, U2 = PR 1)
리뷰: 문서 리뷰 5 렌즈 + 단순화 3 렌즈 + 코드 리뷰 5 렌즈. 교차 모델 대적 패스는 **돌지 않았다**(아래 참조).

적용한 것은 커밋에 있다. 여기는 **적용하지 않기로 한 것과 그 이유**다.

---

## 적용하지 않은 것

### 1. `pg_advisory_xact_lock`의 무한 대기가 두 군데 더 있다 — P2, 이연

`ApplyGrants`(`internal/store/migrate.go:346`)와 `Checkpoint`(`internal/store/checkpoint.go:433`)가 같은 블로킹 primitive를 **경계 없이** 쓴다. 둘 다 부팅 경로다. advisory lock은 권한이 필요 없으므로, 연결할 수 있는 아무 세션이나(R39가 SELECT만 주는 check·decide 역할 포함) 키를 쥐고 모든 레플리카를 리스너 열기 전에 멈출 수 있다.

**이 PR은 새로 더한 자리에만 `lock_timeout`을 걸었다.** 나머지 둘은 이 변경이 만든 것이 아니고, 셋을 한꺼번에 고치는 것은 이 PR의 범위(빨간 CI를 되돌리는 것) 밖이다. 세 렌즈가 모두 "이 변경이 넓힌 것이 아니다"라고 명시적으로 판단했다.

**다음 사람에게**: 같은 한 줄이면 된다. 셋을 함께 고치는 것이 자연스러운 후속이다.

### 2. 차트의 liveness 예산이 `migrationLockWait`보다 짧다 — P2, 선행 문제

`deploy/helm/stamp/templates/deployment.yaml`의 liveness가 `initialDelaySeconds: 5` + `periodSeconds: 10`이라 **리스너를 열기 전의 파드는 약 35초에 죽는다.** 그런데 `migrationLockWait = 90s`다. 즉 `Lock()`이 설계된 90초 대기는 **차트 기본값에서 도달할 수 없다** — peer의 마이그레이션을 기다리는 파드는 90초를 기다리기 전에 kubelet에게 죽는다.

이 PR이 만든 문제가 아니고, 고치려면 예산 둘 중 어느 쪽이 옳은지 정해야 한다(프로브를 늘릴 것인가, 대기를 줄일 것인가). 그것은 배포 정책 판단이다.

**다음 사람에게**: 이 PR이 새로 건 `lock_timeout`도 같은 `migrationLockWait`를 쓰므로 같은 성질을 물려받는다. 예산을 정할 때 셋을 함께 봐라.

### 3. `advisoryKey`는 공개 소스에서 계산할 수 있다 — 선행, 넓어지지 않음

FNV-64a over a literal이므로 키 값이 공개다. 보안 렌즈가 **이 변경이 노출을 넓히지 않는다**고 명시적으로 판단했다(같은 성질의 락이 이미 부팅 경로에 둘 있었고, 경계 있는 90초 대기를 경계 없는 것으로 바꾸지 않았다). `lock_timeout`을 걸어 오히려 좁혔다.

고치려면 키를 배포 비밀에서 유도해야 하는데, 그러면 **같은 데이터베이스를 공유하는 두 STAMP 배포가 서로를 직렬화하지 못한다** — 락이 존재하는 이유가 사라진다. 거래가 나쁘다.

### 4. CAS 피크 추적이 테스트 패키지 셋에 복사돼 있다 — P3, 부분 해소

`internal/stream/ratelimit_test.go`와 `internal/api/ratelimit_test.go`가 같은 관용구를 각자 손으로 쓴다. 이 PR이 세 번째 복사본을 더했다가 **지웠으므로**(그 단언이 공허했다) 지금은 둘이다. 공유 헬퍼로 뽑으려면 세 외부 테스트 패키지가 임포트할 수 있는 새 패키지가 필요하고, 사용자의 명시적 **최소 목표** 제약 밖이다.

### 5. 락 키 비교가 두 키만 본다 — P3

`TestVersionTableLockIsNotTheMigrationLock`이 `stamp:migrations`와 `stamp:grants`만 대조한다. `stamp:checkpoint`와 writer별 감사 키는 안 본다. 값싸게 넓힐 수 있지만, 지금 대조하는 둘이 **같은 부팅 경로에서 같은 프로세스가 잡는** 키라서 충돌 위험이 실제로 있는 자리다. 나머지는 다른 생애주기다.

### 6. 생성이 non-duplicate 오류로 실패했을 때 부팅이 시끄럽게 죽는 것을 재는 테스트가 없다 — P3

`isDuplicateObject`가 `42501`을 거짓으로 답하는 것은 결정적으로 고정돼 있다(`TestIsDuplicateObjectRefusesCodes`). 그러나 **그 거짓이 실제로 부팅을 죽이는지**는 호출 지점에서 재지 않는다. 패키지에 제한된 역할을 만드는 기계(`assertGrantsAreRestrictive`)가 이미 있으므로 만들 수 있다. 이 PR의 범위 밖이지만 값이 있다.

---

## 이 라운드가 남긴 절반

**U3 + U4(포화 관측)가 PR 2로 남았다.** 계획의 KTD5가 그렇게 나눴다 — 빨간 CI를 마감 없는 측정 뒤에 두지 않기 위해서다. 대상은 `docs/HANDOFF.md` §4에 있고, 계획서 U3에 R43의 감사 절반과 R32의 경보 절반을 포함하도록 적혀 있다.

---

## 덮이지 않은 것: 교차 모델 독립성

`ce-code-review`의 대적 렌즈는 보통 **다른 모델 제공자**에게 같은 diff를 보내 독립적인 판단을 받는다. **이 리포는 비공개이므로 그 경로를 거절했다.** 대적 렌즈는 같은 모델의 in-process 폴백으로 돌았다.

그래서 이 리뷰의 독립성은 **렌즈 다양성에서 오지 코드 밖에서 오지 않는다.** 이번에는 그것으로 충분했다 — 세 렌즈가 독립적으로 피크 단언이 공허함을 잡았고 그것이 이 PR에서 가장 중요한 발견이었다. 그러나 같은 모델이 공유하는 사각지대는 이 방식으로 드러나지 않는다.
