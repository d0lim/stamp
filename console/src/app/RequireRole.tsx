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
  { to: '/policies', label: 'Policy list', role: 'author' },
  { to: '/inbox', label: 'Approval inbox', role: 'approver' },
  { to: '/audit', label: 'Audit history', role: 'auditor' },
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
      <RouteAnnouncer title="Access denied" />
      <h1>You do not have permission to open this screen</h1>
      <p>
        The <code>{routerLocation.pathname}</code> screen requires the{' '}
        <strong>{ROLE_LABELS[required]}</strong> role. Your current token does not carry it.
      </p>
      {reachable.length > 0 ? (
        <>
          <h2>Screens you can reach</h2>
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
          Your current token reaches no screen in this console. Ask an administrator to grant you a
          role.
        </p>
      )}
    </div>
  )
}
