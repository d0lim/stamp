/**
 * The route seams U15 and U16 fill.
 *
 * Each screen here is a real route with a real heading, a real announcer, and
 * the API client already in hand — and no feature. `src/builder/`,
 * `src/inbox/` and `src/audit/` belong to those units; what the shell owes them
 * is a mounted route, a landmark to render into, and a session. Building a
 * half-feature here would give them something to delete.
 */
import { Link } from 'react-router-dom'
import { RouteAnnouncer } from '../a11y/RouteAnnouncer'
import { useAuth } from '../auth/AuthProvider'

function Placeholder({
  title,
  owner,
  description,
}: {
  readonly title: string
  readonly owner: string
  readonly description: string
}) {
  return (
    <div className="panel">
      <RouteAnnouncer title={title} />
      <h1>{title}</h1>
      <p>{description}</p>
      <p className="panel__meta">이 화면은 {owner}에서 채워집니다.</p>
    </div>
  )
}

// The policy seam is filled: `src/builder/` owns /policies/* now, and App.tsx
// mounts it. The two placeholders below are still seams.

export function InboxScreen() {
  return (
    <Placeholder
      title="승인함"
      owner="U16 (승인함 + 감사 콘솔)"
      description="자신에게 걸린 pending 결정, 수집 현황, 만료 임박 순 정렬이 여기에 놓입니다."
    />
  )
}

export function AuditScreen() {
  return (
    <Placeholder
      title="감사"
      owner="U16 (승인함 + 감사 콘솔)"
      description="감사 체인 조회와 검증 결과가 여기에 놓입니다."
    />
  )
}

/** Where a signed-in person with no recognised role lands. */
export function NoAccessScreen() {
  const { userLabel, config } = useAuth()
  return (
    <div className="panel panel--refusal">
      <RouteAnnouncer title="사용 가능한 화면 없음" />
      <h1>사용할 수 있는 화면이 없습니다</h1>
      <p>
        <strong>{userLabel}</strong> 계정의 토큰에는 콘솔 역할이 없습니다. 콘솔은{' '}
        <code>{config.oidc.roleClaim}</code> claim에서 역할을 읽습니다.
      </p>
      <p>관리자에게 정책 저작·승인·감사 중 필요한 역할 부여를 요청하십시오.</p>
    </div>
  )
}

export function NotFoundScreen() {
  const { landing } = useAuth()
  return (
    <div className="panel panel--refusal">
      <RouteAnnouncer title="화면을 찾을 수 없음" />
      <h1>화면을 찾을 수 없습니다</h1>
      <p>주소를 확인하십시오.</p>
      <p>
        <Link to={landing}>처음 화면으로 이동</Link>
      </p>
    </div>
  )
}
