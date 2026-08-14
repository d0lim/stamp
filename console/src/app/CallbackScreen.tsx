/**
 * The IdP's return leg.
 *
 * This is the only module in the console that reads the query string, and it
 * reads four named parameters from it. The router's search params are the input
 * here because that is what an authorization code response *is*; nothing about
 * the deployment's configuration is taken from them.
 */
import { useEffect, useRef, useState } from 'react'
import { Navigate, useSearchParams } from 'react-router-dom'
import { RouteAnnouncer } from '../a11y/RouteAnnouncer'
import { useAuth } from '../auth/AuthProvider'
import { AuthError, completeLogin } from '../auth/oidc'

type State =
  | { readonly kind: 'working' }
  | { readonly kind: 'done'; readonly returnTo: string }
  | { readonly kind: 'failed'; readonly message: string; readonly detail?: string }

export function CallbackScreen() {
  const { config, adoptTokens } = useAuth()
  const [params] = useSearchParams()
  const [state, setState] = useState<State>({ kind: 'working' })
  // React 18+ mounts effects twice in development. The authorization code is
  // single use, so a second exchange would fail and destroy a good login.
  const started = useRef(false)

  useEffect(() => {
    if (started.current) return
    started.current = true
    void (async () => {
      try {
        const result = await completeLogin(config, {
          code: params.get('code'),
          state: params.get('state'),
          error: params.get('error'),
          errorDescription: params.get('error_description'),
        })
        adoptTokens(result.tokens)
        setState({ kind: 'done', returnTo: result.returnTo })
      } catch (cause) {
        const error = cause instanceof AuthError ? cause : null
        setState({
          kind: 'failed',
          message: error?.message ?? 'Sign-in did not complete.',
          ...(error?.detail ? { detail: error.detail } : {}),
        })
      }
    })()
  }, [config, params, adoptTokens])

  if (state.kind === 'done') return <Navigate to={state.returnTo} replace />

  if (state.kind === 'failed') {
    return (
      <div className="panel panel--refusal" role="alert">
        <RouteAnnouncer title="Sign-in failed" />
        <h1>Sign-in did not complete</h1>
        <p>{state.message}</p>
        {state.detail ? <p className="panel__meta">{state.detail}</p> : null}
        <p>
          <a href={config.basePath}>Start the sign-in again</a>
        </p>
      </div>
    )
  }

  return (
    <div className="panel">
      <RouteAnnouncer title="Signing in" />
      <h1>Completing sign-in</h1>
      <p role="status">One moment.</p>
    </div>
  )
}
