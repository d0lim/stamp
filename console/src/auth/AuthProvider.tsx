/**
 * The session as React sees it.
 *
 * The provider owns three things U15 and U16 will use without thinking about
 * them: the current session, the roles derived from it, and the single API
 * client every screen calls through. It also owns what happens when a token
 * expires — a 401 anywhere raises the same banner, so no screen has to
 * implement its own re-login.
 */
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { createApiClient, type ApiClient } from '../api/client'
import type { ConsoleRuntimeConfig } from '../config/runtime-config'
import { displayName } from './claims'
import { beginLogin, clearFlow, logoutUrl, type TokenSet } from './oidc'
import { defaultLanding, rolesFromClaims, type ConsoleRole } from './roles'
import { getAccessToken, getSession, sessionFromTokens, setSession, type Session } from './session'

export interface AuthContextValue {
  readonly config: ConsoleRuntimeConfig
  readonly session: Session | null
  readonly roles: ReadonlySet<ConsoleRole>
  readonly userLabel: string
  readonly landing: string
  readonly api: ApiClient
  /** True once a request came back 401 and the session was dropped. */
  readonly sessionExpired: boolean
  readonly signIn: (returnTo: string) => Promise<void>
  readonly signOut: () => void
  readonly adoptTokens: (tokens: TokenSet) => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export interface AuthProviderProps {
  readonly config: ConsoleRuntimeConfig
  readonly children: ReactNode
  /** Test seam: the initial session, and the fetch the API client uses. */
  readonly initialSession?: Session | null
  readonly fetchImpl?: typeof fetch
  readonly navigateAway?: (url: string) => void
}

export function AuthProvider({
  config,
  children,
  initialSession = null,
  fetchImpl,
  navigateAway = (url) => window.location.assign(url),
}: AuthProviderProps) {
  const [session, setSessionState] = useState<Session | null>(() => {
    // The session lives in a module variable, not in React state — see
    // auth/session.ts. React holds a mirror so renders react to it.
    if (initialSession !== null && getSession() === null) setSession(initialSession)
    return getSession()
  })
  const [sessionExpired, setSessionExpired] = useState(false)
  // The client is built once. Rebuilding it on every session change would make
  // every in-flight request's identity ambiguous.
  const expiredRef = useRef(false)

  const handleUnauthenticated = useCallback(() => {
    if (expiredRef.current) return
    expiredRef.current = true
    setSession(null)
    setSessionState(null)
    setSessionExpired(true)
  }, [])

  const api = useMemo(
    () =>
      createApiClient({
        config,
        getAccessToken,
        onUnauthenticated: handleUnauthenticated,
        ...(fetchImpl ? { fetchImpl } : {}),
      }),
    [config, fetchImpl, handleUnauthenticated],
  )

  const adoptTokens = useCallback((tokens: TokenSet) => {
    const next = sessionFromTokens(tokens)
    setSession(next)
    setSessionState(next)
    expiredRef.current = false
    setSessionExpired(false)
  }, [])

  const signIn = useCallback(
    async (returnTo: string) => {
      clearFlow()
      await beginLogin(config, returnTo, navigateAway)
    },
    [config, navigateAway],
  )

  const signOut = useCallback(() => {
    const idToken = getSession()?.idToken ?? null
    setSession(null)
    setSessionState(null)
    expiredRef.current = false
    setSessionExpired(false)
    const target = logoutUrl(config, idToken)
    if (target) navigateAway(target)
  }, [config, navigateAway])

  const roles = useMemo(
    () => rolesFromClaims(session?.claims ?? null, config.oidc.roleClaim),
    [session, config.oidc.roleClaim],
  )

  const value = useMemo<AuthContextValue>(
    () => ({
      config,
      session,
      roles,
      userLabel: displayName(session?.claims ?? null),
      landing: defaultLanding(roles),
      api,
      sessionExpired,
      signIn,
      signOut,
      adoptTokens,
    }),
    [config, session, roles, api, sessionExpired, signIn, signOut, adoptTokens],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth is only usable inside AuthProvider.')
  return value
}
