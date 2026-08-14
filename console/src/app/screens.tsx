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

// Every seam is filled: `src/builder/` owns /policies/*, `src/inbox/` owns
// /inbox/* and `src/audit/` owns /audit/*, and App.tsx mounts all three. What
// is left here is the shell's own two answers — no role, and no such screen.

/** Where a signed-in person with no recognised role lands. */
export function NoAccessScreen() {
  const { userLabel, config } = useAuth()
  return (
    <div className="panel panel--refusal">
      <RouteAnnouncer title="No access" />
      <h1>No screen is available to you</h1>
      <p>
        The token for <strong>{userLabel}</strong> carries no console role. The console reads
        roles from the <code>{config.oidc.roleClaim}</code> claim.
      </p>
      <p>Ask an administrator to grant the role you need: policy authoring, approval, or audit.</p>
    </div>
  )
}

export function NotFoundScreen() {
  const { landing } = useAuth()
  return (
    <div className="panel panel--refusal">
      <RouteAnnouncer title="Not found" />
      <h1>Screen not found</h1>
      <p>Check the address.</p>
      <p>
        <Link to={landing}>Go to your landing screen</Link>
      </p>
    </div>
  )
}
