# STAMP 콘솔

React + TypeScript(Vite) 정적 번들. `go:embed`로 엔진 바이너리에 동봉되고, 엔진의
**공개 API만** 소비한다 — 콘솔 전용 백엔드(BFF)는 없다 (D19).

```sh
npm ci
npm test          # 타입 검사 → 계약 경계 검사 → vitest
npm run build     # tsc → vite build → 번들 검사
npm run dev       # 개발 서버 (설정 문서는 실행 중인 엔진에서 프록시해야 한다)
```

## 이 셸이 지키는 것

**API 기준 주소는 서버가 내려준다.** `/console/config.json` 하나가 유일한 출처다.
질의 문자열·조각·`localStorage`는 읽지 않는다 — 셋 다 승인자에게 링크를 보낼 수 있는
사람이 쓸 수 있는 채널이고, 콘솔은 그 승인자의 토큰을 쥐고 있다 (R50).
`src/config/runtime-config.ts` 하나가 이 값을 다루고, `scripts/check-contract.mjs`가
다른 출처를 읽는 코드를 정적으로 거부한다.

**호출 대상은 공개 계약 안에 있다.** 모든 요청은 `src/api/client.ts`를 지나고,
엔드포인트는 경로가 아니라 **이름**으로 부른다. 경로 템플릿은
`contract/public-endpoints.json`에서 오는데, 이 파일은 `internal/api/contract.go`가
생성하고 Go 테스트가 실제 마운트된 라우트와 대조한다. 계약에 없는 이름은 부를 수 없고,
CI가 그것을 확인한다.

**토큰은 메모리에만 있다.** `sessionStorage`에는 PKCE verifier와 state, 복귀 경로만
들어간다 — 리다이렉트 왕복을 넘길 방법이 그것뿐이기 때문이고, 셋 다 자격증명이 아니다.
복귀 경로는 쓰기 전에 같은 오리진의 콘솔 경로인지 검증한다.

## 다음 유닛이 놓일 자리

| 자리 | 소유 | 셸이 이미 주는 것 |
|---|---|---|
| `src/builder/` | U15 정책 폼 빌더 | `/policies/*` 라우트, `author` 가드, `ErrorSummary`, `fieldErrorId` |
| `src/inbox/` | U16 승인함 | `/inbox/*` 라우트, `approver` 가드, `Disclosure`(R55의 `onFirstExpand` 포함) |
| `src/audit/` | U16 감사 콘솔 | `/audit/*` 라우트, `auditor` 가드 |

세 자리 모두 `useAuth()`에서 `api`(계약에 묶인 클라이언트), `roles`, `session`을 받는다.
401은 셸이 처리한다 — 화면은 재로그인을 구현하지 않는다.
`src/test/harness.tsx`의 `renderShell({ roles, route, fetchImpl, probe })`가 화면 테스트의
진입점이다.

## 접근성

셸이 정하고 화면이 물려받는다 (R19, R55).

- 랜드마크: `banner` / `navigation` / `main#main[tabindex=-1]` / `contentinfo`, 각 하나씩
- 라우트 전환 시 초점이 `main`으로 이동하고 `aria-live` 영역이 화면 이름을 안내한다
- 첫 초점 대상은 본문 건너뛰기 링크
- 현재 화면은 색만이 아니라 `aria-current="page"`와 밑줄·굵기로 표시한다
- 접힘은 표시 억제가 아니라 시각적 압축이다 — 접힌 내용도 DOM에 남는다
- 인라인 스타일 금지. CSP가 `style-src 'self'`이고 대비 값은 `src/styles.css`에 비율과 함께 적혀 있다

`axe-core`가 jsdom에서 셸 화면들을 검사한다. 대비 검사는 jsdom이 색을 계산하지 못하므로
꺼져 있고, U15·U16의 Playwright axe 통과가 그 부분을 맡는다.
