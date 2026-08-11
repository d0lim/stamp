# Residual Review Findings — 완결 계획 집계 리뷰

**대상**: `main` `24570f9` → `21e6777` (69파일, +10,915줄, 실행 코드 4,913줄)
**계획**: `docs/plans/2026-08-11-001-feat-stamp-completion-plan.md`
**왜 집계로 봤나**: 여섯 유닛이 각각 독립 PR로 착지했고 각각 CI 그린 + mutation 검증을 거쳤다. **유닛 간 상호작용은 그 어느 것도 볼 수 없다.**

## 적용된 것 (이 리뷰에서 고침)

- **P0 · split 배포가 decide를 서빙하지 못했다** — `_helpers.tpl`의 decide 역할이 PEP를 바인드하지 않아 `POST /decisions`가 어디에서도 도달 불가. `21e6777`.
- **P0 · 계약 문서가 decide 엔드포인트를 명시적으로 부정** — `decision-api.md`가 "1.0.0에 없다"고 단언하는데 이미 마운트돼 있었다. `7434b8a`.
- **P1 · 퀵스타트 감사 가드가 항상 0을 읽었다** — `AUDIT_RC=$?`가 `fi` 뒤. 종료 6이 `✓ exited 0`으로 보고됐다. `21e6777`.
- **P1 · 비밀 스캔이 `LOGS` 비면 공허하게 통과** — 같은 형태. `21e6777`.
- **P3 · `Event.Kind` 주석이 닫힌 집합을 열거** — 외부 감사자가 읽는 스펙이라 하중을 받는다. `7434b8a`.
- **P1 · 데모의 R31 에코 검증이 공허했다** — jq의 `// ""`가 없는 `binding_hash`를 빈 값으로 흡수하고, 서버 비교가 `body.BindingHash != ""`로 게이팅돼 빈 에코는 검증을 건너뛴다. 이 단계는 에코가 동작하든 부재하든 동일하게 통과했다. **제품은 안전하다** — `quorum.go:351`의 재계산 검사는 선택적이 아니다. 거짓이었던 것은 데모의 주장이다. `b35ad88`.
- **P2 · egress 거부 확인이 주제어를 찾았다** — `grep -qi 'egress'`가 'egress'를 포함한 아무 기동 실패나 만족시켰다. 이제 게이트의 sentinel을 찾는다. `b35ad88`.
- **P2 · `make land`가 새 게이트 둘을 빠뜨렸다** — 브랜치 보호를 못 쓰는 리포에서 `land`가 유일한 강제 수단인데 `chart-check`·`contracts`를 안 돌렸다. `b35ad88`.
- **P2 · `render.sh`의 helm 핀이 helm 부재 시에만 적용** — 파일 주석이 주장하는 것을 바로 아래 분기가 우회했다. `b35ad88`.

## 이슈로 남긴 것

- [#44](https://github.com/d0lim/stamp/issues/44) · **P1** · 계약 버전 게이트가 엔드포인트 드리프트를 구조적으로 못 잡는다. `want_exact`가 비어 major만 비교하고, 그 major는 `EvaluationPath`에서 오므로 라우트가 늘어도 안 움직인다. 1.1.0으로 올린 뒤에도 통과하는 것을 확인했다.
- [#45](https://github.com/d0lim/stamp/issues/45) · **P2** · decide 응답의 소비자 계약 둘 — 속도 제한 거부에 전송 수준 신호(`Retry-After`)가 없어 중간의 모든 것이 눈이 멀고, `policy_set_stale`이 `error` 어휘를 침범해 같은 상태가 표면마다 다른 코드를 받는다.
- [#46](https://github.com/d0lim/stamp/issues/46) · **P1** · 역할의 라우트가 그 티어가 바인드하는 표면에 있는지 검사하는 것이 없다. 위 P0이 새어나간 이유.
- [#47](https://github.com/d0lim/stamp/issues/47) · **P1/P2** · 설계 판단이 필요한 셋 — decide 고아(타임아웃 시 이름 없는 pending이 미결 슬롯 점유, 멱등 키 없음), 호출자·주체가 공유하는 유계 제한기 표, 소비 검사가 도달 불가 읽기를 소비로 셈(적대적 리뷰어가 디스크에서 재현·복원).

## 리뷰어가 확인하고 "깨끗하다"고 판정한 것

- `stream.rateLimiter` → `stream.Limiter` 개명이 **동작 보존**. 바뀐 지점 전부 추적: 키 접두사, `Allow` 본체, `unlimited()` 단락, `withDefaults`, `sweepLocked`이 리시버 타입만 빼면 바이트 동일. decide가 자기 인스턴스를 만들어 `"caller\x1f"` 접두사가 두 경로 사이에서 충돌하지 않는다.
- `CheckAPI.inputFor` → 패키지 수준 `evaluationInput`도 동작 보존. AuthZEN R1(표준 소비자가 컨텍스트를 무시해도 판정 해석 동일)이 유지된다.
- `Event`의 `Scope`/`Limit`이 구조체 끝에 `omitempty`로 붙어 **기존 이벤트 바이트·잎 다이제스트·배치 루트가 그대로**다. 고정 다이제스트 테스트가 재계산이 아니라 하드코딩이라 옳은 구성.
- R42가 렌더링 산출물에서 성립 — PEM 0건, 비밀 이름 env가 전부 `valueFrom`, 차트가 `kind: Secret`을 만들지 않는다(오케스트레이터 직접 확인).

## 커버리지 — 정직하게

- **돌아온 렌즈**: correctness, api-contract, **adversarial**. 셋이 위 findings 전부를 냈다.
- **결과를 내지 않은 렌즈**: security, reliability, testing. 넷 다 idle 신호만 반복하고 findings를 보내지 않았다. **그만큼 커버리지가 비어 있다.** 그중 security의 세 우선순위는 오케스트레이터가 직접 확인했다(R40 두 계층 mutation, egress 핀 mutation, 렌더링 비밀 스캔) — 그러나 그것은 독립 컨텍스트가 아니므로 **독립 확증으로 세지 않는다.**
- **교차 모델 적대적 패스를 돌리지 않았다.** 이 리포는 비공개이고 외부 모델 제공자로의 코드 반출은 단독 결정할 일이 아니라고 판단했다. 인프로세스 적대적 리뷰어로 대체했고 **그것이 이 리뷰에서 가장 값진 것을 냈다**(세 번째 silent-pass, 소비 검사 재현) — 다만 같은 컨텍스트 계열이므로 교차 모델만큼의 독립성은 아니다.

## 이 리뷰가 드러낸 패턴

**"가드가 자기가 가드임을 증명하는 테스트가 없다"** 가 이번 diff의 지배적 결함이다. 발견된 silent-pass 셋이 전부 `scripts/quickstart.sh`에서 나왔고, 그것이 이 diff의 검증 장치 중 **자기 검사가 없는 유일한 것**이다:

| 장치 | 자기 검사 | 결과 |
|---|---|---|
| `consumption_test.go` | `TestConfigConsumptionCheckDetectsAnUnwiredField` | 사각지대가 유계 |
| `internal/release` 비밀 스캐너 | 심어둔 음성 대조군 | 견고 |
| `deploy/helm/render.sh` | `--check` diff + 네 substring 단언 | 견고 |
| `scripts/quickstart.sh` | **없음** | **결손 셋** |

값싼 답: 알려진 자격증명을 컨테이너 로그에 주입하거나 감사 행 하나를 변조한 CI 변종을 만들어 스크립트가 죽기를 요구한다. 그 하나가 셋을 전부 잡았을 것이다.
- **띄우지 않은 렌즈**: maintainability, performance(범위 축소), project-standards(`CLAUDE.md`/`AGENTS.md` 없음), learnings(`docs/solutions` 없음), agent-native(에이전트 표면 없음), data-migration(마이그레이션 산출물 없음).
