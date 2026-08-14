/**
 * The unauthenticated door.
 *
 * An unauthenticated visit does not silently redirect to the IdP. It renders a
 * screen with one button, and the reason is that a silent redirect on load is
 * indistinguishable from a broken deployment when the IdP is misconfigured —
 * the person sees a flash and an error page from a host they do not recognise.
 * With the button, the console has already told them where they are, and the
 * location they were headed for is preserved across the round trip.
 */
import { useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'
import { RouteAnnouncer } from '../a11y/RouteAnnouncer'
import { useAuth } from '../auth/AuthProvider'
import { isLoginConfigured } from '../config/runtime-config'
import { EnvConsoleVariables } from './config-names'

export function AuthGate({ children }: { readonly children: ReactNode }) {
  const { session, signIn, config } = useAuth()
  const routerLocation = useLocation()

  if (session) return <>{children}</>

  if (!isLoginConfigured(config)) {
    return (
      <div className="panel panel--refusal">
        <RouteAnnouncer title="Login not configured" />
        <h1>The console has no login configuration</h1>
        <p>
          This deployment did not configure an OIDC client for the console. Set these environment
          variables.
        </p>
        <ul>
          {EnvConsoleVariables.map((name) => (
            <li key={name}>
              <code>{name}</code>
            </li>
          ))}
        </ul>
      </div>
    )
  }

  const returnTo = `${routerLocation.pathname}${routerLocation.search}`
  return (
    <div className="panel panel--signin">
      <RouteAnnouncer title="Sign in" />
      <h1>Sign-in required</h1>
      <p>
        The STAMP console signs you in with an account from{' '}
        <code>{config.oidc.issuer || 'the configured IdP'}</code>.
      </p>
      <button
        type="button"
        className="button button--primary"
        onClick={() => void signIn(returnTo)}
        data-testid="sign-in"
      >
        Sign in
      </button>
    </div>
  )
}
