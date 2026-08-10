/**
 * The landmark structure every screen sits inside.
 *
 * banner / navigation / main / contentinfo, in that order, with exactly one
 * main and a `tabIndex={-1}` on it so the route announcer can move focus there.
 * A screen reader user navigates a console by landmark before they navigate it
 * by heading, and a shell that gets this wrong cannot be fixed screen by screen
 * afterwards.
 */
import { NavLink, Outlet } from 'react-router-dom'
import { SkipLink } from '../a11y/SkipLink'
import { useAuth } from '../auth/AuthProvider'
import { ROLE_LABELS, type ConsoleRole } from '../auth/roles'
import { SessionExpiredNotice } from './SessionExpiredNotice'

interface NavItem {
  readonly to: string
  readonly label: string
  readonly role: ConsoleRole
}

const NAV: readonly NavItem[] = [
  { to: '/policies', label: '정책', role: 'author' },
  { to: '/inbox', label: '승인함', role: 'approver' },
  { to: '/audit', label: '감사', role: 'auditor' },
]

export function Layout() {
  const { roles, userLabel, session, signOut, api } = useAuth()
  // Navigation shows what this person can reach. It is an affordance, not a
  // control: the engine authorises every call regardless of what is rendered.
  const visible = NAV.filter((item) => roles.has(item.role))

  return (
    <div className="shell">
      <SkipLink />
      <header className="shell__header">
        <div className="shell__brand">
          <span className="shell__wordmark">STAMP</span>
          <span className="shell__tagline">정책 콘솔</span>
        </div>
        <nav className="shell__nav" aria-label="주요">
          <ul className="shell__nav-list">
            {visible.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  className={({ isActive }) =>
                    isActive ? 'shell__nav-link shell__nav-link--current' : 'shell__nav-link'
                  }
                  aria-current={undefined}
                >
                  {({ isActive }) => (
                    <span aria-current={isActive ? 'page' : undefined}>{item.label}</span>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className="shell__account">
          <span className="shell__user" data-testid="user-label">
            {userLabel}
          </span>
          <span className="shell__roles" data-testid="role-list">
            {visible.length === 0
              ? '권한 없음'
              : visible.map((item) => ROLE_LABELS[item.role]).join(' · ')}
          </span>
          {session ? (
            <button type="button" className="button button--quiet" onClick={signOut}>
              로그아웃
            </button>
          ) : null}
        </div>
      </header>

      <SessionExpiredNotice />

      <main id="main" className="shell__main" tabIndex={-1}>
        <Outlet />
      </main>

      <footer className="shell__footer">
        <p>
          API 대상: <code data-testid="api-base">{api.baseUrl}</code>
        </p>
      </footer>
    </div>
  )
}
