---
name: STAMP
last_updated: 2026-08-07
---

# STAMP Strategy

> **STAMP** — **ST**ateful **A**uthorization for **M**ulti-**P**arty approvals

## Target problem

거래 승인·어드민 액션 같은 고위험 인가를 정책으로 다루려는 핀테크 팀은, 판정 로직보다 판정에 필요한 사실을 모으고(PIP) 승인 절차를 조율하는 일(orchestrator)에서 대부분의 비용을 치른다. 기존 정책 엔진(OPA·Cedar·Cerbos)은 stateless 판정만 제품화하고 이 부분을 떠넘기기 때문에, 팀은 결국 엔진 위에 자기만의 엔진을 한 겹 더 얹게 된다.

## Our approach

결정을 boolean이 아니라 수명주기를 가진 객체로 만든다 — 쿼럼·MFA·시간 지연 같은 challenge 수집을 엔진 안으로 들여서, 팀마다 정책 엔진 위에 orchestrator를 또 짓는 구조를 없앤다. 사실 조달(PIP)은 선언적 source 바인딩으로 엔진이 책임지고, 고QPS 조회는 stateless check() 경로로 분리해 확장한다.

## Who it's for

**Primary:** 핀테크 플랫폼 엔지니어 - 결제·송금·자산 서비스 팀들이 승인·인가 로직을 각자 하드코딩하는 것을 멈추게 하려고, STAMP를 공통 인프라로 고용한다.

## Key metrics

- **Orchestrator 대체율** - 도입 팀이 자체 승인·조율 코드 없이 커버하는 유스케이스 비율; 초기에는 디자인 파트너 인터뷰로 측정
- **check() p99 지연 / 최대 QPS** - stateless 경로 성능 벤치마크; CI에서 상시 측정
- **Time-to-first-decision** - 설치부터 첫 프로덕션 판정까지 걸리는 시간; 온보딩 텔레메트리 또는 디자인 파트너 관찰로 측정

## Tracks

### Decision Kernel

결정 상태 머신 - 결정 객체 수명주기(pending → allow/deny/expired), challenge 타입 플러그인(quorum / mfa / delay / external), 정책 변경 시 재평가 규칙, obligation 실행.

_Why it serves the approach:_ approach 그 자체 - 승인 절차를 엔진 안으로 들이는 핵심.

### Fact Plane (PIP)

선언적 source 바인딩 - 동기(API/gRPC)·비동기(이벤트 스트림) source 정의, TTL·배칭·부분실패 시맨틱, fail-closed 기본값.

_Why it serves the approach:_ 결정 객체를 만들려면 사실 조달이 엔진 책임이어야 한다.

### Policy Language & Builder

타입 있는 정책 표현과 entity/action 스키마, 그리고 그 스키마에서 렌더링되는 UI 정책 빌더(source 바인딩 UX 포함).

_Why it serves the approach:_ "고정 kernel + JSON 해석기" 구조의 정면 해결이자, 정적 검증과 UI 빌더의 공통 기반.

### Scale & Self-hosted Ops

check()/decide() 경로 분리, 수평 확장, 설치 패키징(컨테이너/Helm), 감사 로그 내보내기. Postgres(+SQL/PGQ 실험)는 이 트랙의 저장 계층 선택지.

_Why it serves the approach:_ 고QPS 요구와 규제 산업의 self-host 진입 조건을 지는 트랙.

## Not working on

- SaaS 호스팅 - self-hosted 우선; 나중에 control plane SaaS 형태로 재고
- 범용 워크플로 엔진 - 인가에 필요한 상태까지만; Temporal 영역으로 확장하지 않는다
- 인증(authn) 자체 구현 - WebAuthn/TOTP는 검증 연동만, IdP가 되지 않는다

## Marketing

**One-liner:** 승인이 필요한 모든 결정을 위한 self-hosted 정책 엔진 - allow/deny가 아니라 쿼럼·MFA·지연까지, 결정의 전체 수명주기를 정책으로.
