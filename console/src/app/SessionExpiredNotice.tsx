/**
 * What a 401 looks like.
 *
 * The console does not silently bounce to the IdP when a token expires. An
 * approver in the middle of reading a decision would come back to a blank
 * screen with no way to tell whether their submission landed. Instead the
 * banner appears, announces itself, and offers a re-login that returns to this
 * exact location.
 */
import { useLocation } from 'react-router-dom'
import { useAuth } from '../auth/AuthProvider'

export function SessionExpiredNotice() {
  const { sessionExpired, signIn } = useAuth()
  const routerLocation = useLocation()
  if (!sessionExpired) return null

  return (
    <div className="notice notice--warning" role="alert" data-testid="session-expired">
      <p className="notice__text">
        Your session has expired. Signing in again returns you to this screen.
      </p>
      <button
        type="button"
        className="button"
        onClick={() => void signIn(`${routerLocation.pathname}${routerLocation.search}`)}
      >
        Sign in again
      </button>
    </div>
  )
}
