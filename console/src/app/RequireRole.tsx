/**
 * The guard on a route, and what it renders when it refuses.
 *
 * It renders rather than redirects, on purpose. A redirect loses the URL the
 * person typed or was sent, so they cannot tell a colleague "this link does not
 * work for me" and they cannot retry after their access changes. The refusal
 * names the role that was needed and links to the screens they can reach.
 */
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '../auth/AuthProvider'
import { ROLE_LABELS, type ConsoleRole } from '../auth/roles'
import { RouteAnnouncer } from '../a11y/RouteAnnouncer'
import type { ReactNode } from 'react'

const REACHABLE: readonly { readonly to: string; readonly label: string; readonly role: ConsoleRole }[] = [
  { to: '/policies', label: '정책 목록', role: 'author' },
  { to: '/inbox', label: '승인함', role: 'approver' },
  { to: '/audit', label: '감사 기록', role: 'auditor' },
]

export interface RequireRoleProps {
  readonly role: ConsoleRole
  readonly children: ReactNode
}

export function RequireRole({ role, children }: RequireRoleProps) {
  const { roles } = useAuth()
  if (roles.has(role)) return <>{children}</>
  return <Forbidden required={role} />
}

export function Forbidden({ required }: { readonly required: ConsoleRole }) {
  const { roles } = useAuth()
  const routerLocation = useLocation()
  const reachable = REACHABLE.filter((item) => roles.has(item.role))

  return (
    <div className="panel panel--refusal">
      <RouteAnnouncer title="접근 권한 없음" />
      <h1>이 화면에 접근할 권한이 없습니다</h1>
      <p>
        <code>{routerLocation.pathname}</code> 화면은 <strong>{ROLE_LABELS[required]}</strong> 권한이 필요합니다.
        현재 토큰에는 그 권한이 없습니다.
      </p>
      {reachable.length > 0 ? (
        <>
          <h2>접근할 수 있는 화면</h2>
          <ul>
            {reachable.map((item) => (
              <li key={item.to}>
                <Link to={item.to}>{item.label}</Link>
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p>
          현재 토큰으로 접근할 수 있는 화면이 없습니다. 관리자에게 역할 부여를 요청하십시오.
        </p>
      )}
    </div>
  )
}
