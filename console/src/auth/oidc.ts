/**
 * The console as an OIDC relying party: authorization code flow with PKCE, a
 * public client, and tokens that live in memory only.
 *
 * Three decisions are worth stating.
 *
 * Tokens never reach storage. The console holds an approver's credential for
 * exactly as long as the tab is open, and a token in localStorage is a token
 * any script that ever runs on this origin can read at its leisure.
 *
 * The transient flow state — the PKCE verifier, the CSRF state, and where the
 * person was going — does reach sessionStorage, because the flow crosses a full
 * page navigation to the IdP and back, and there is no in-memory anything that
 * survives that. None of the three is a credential: the verifier is worthless
 * without the code, the state is a nonce, and the return path is validated as a
 * same-origin console path before it is used, because a value that came back
 * out of storage is a value someone may have put there.
 *
 * The engine, not the console, decides what a token may do. Everything here is
 * about obtaining one.
 */
import type { ConsoleRuntimeConfig } from '../config/runtime-config'
import { createPKCEPair, randomUrlSafeString } from './pkce'

/** One key, so clearing the flow is one operation. */
const FLOW_KEY = 'stamp.console.oidc.flow'

export interface FlowState {
  readonly state: string
  readonly verifier: string
  readonly returnTo: string
  readonly startedAt: number
}

export interface TokenSet {
  readonly accessToken: string
  readonly idToken: string | null
  readonly expiresAt: number | null
}

export class AuthError extends Error {
  constructor(
    message: string,
    readonly detail?: string,
  ) {
    super(message)
    this.name = 'AuthError'
  }
}

/** Where the IdP comes back to. Same origin, under the bundle's own subtree. */
export function redirectUri(config: ConsoleRuntimeConfig): string {
  return new URL(`${trimTrailing(config.basePath)}/callback`, window.location.origin).toString()
}

export function buildAuthorizationUrl(
  config: ConsoleRuntimeConfig,
  state: string,
  challenge: string,
): string {
  const url = new URL(config.oidc.authorizationEndpoint)
  const scopes = config.oidc.scopes.length > 0 ? config.oidc.scopes : ['openid']
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', config.oidc.clientId)
  url.searchParams.set('redirect_uri', redirectUri(config))
  url.searchParams.set('scope', scopes.join(' '))
  url.searchParams.set('state', state)
  url.searchParams.set('code_challenge', challenge)
  url.searchParams.set('code_challenge_method', 'S256')
  return url.toString()
}

/**
 * Starts a login. `returnTo` is where the person was headed; it is stored and
 * validated on the way back, never trusted as it comes out.
 */
export async function beginLogin(
  config: ConsoleRuntimeConfig,
  returnTo: string,
  navigate: (url: string) => void = (url) => window.location.assign(url),
): Promise<void> {
  const { verifier, challenge } = await createPKCEPair()
  const state = randomUrlSafeString(16)
  saveFlow({ state, verifier, returnTo, startedAt: Date.now() })
  navigate(buildAuthorizationUrl(config, state, challenge))
}

export interface CallbackParams {
  readonly code?: string | null
  readonly state?: string | null
  readonly error?: string | null
  readonly errorDescription?: string | null
}

export interface CompletedLogin {
  readonly tokens: TokenSet
  readonly returnTo: string
}

/**
 * Finishes a login from the callback query parameters.
 *
 * The query string is the one browser-controlled input the console reads, and
 * it is read here alone, for these four named parameters, with the state
 * compared against a value this tab generated. It is not a configuration
 * channel: nothing in R50's list of forbidden sources is consulted for the API
 * base address, here or anywhere.
 */
export async function completeLogin(
  config: ConsoleRuntimeConfig,
  params: CallbackParams,
  fetchImpl: typeof fetch = fetch,
): Promise<CompletedLogin> {
  const flow = takeFlow()
  if (params.error) {
    throw new AuthError('Sign-in did not complete.', params.errorDescription ?? params.error)
  }
  if (!params.code || !params.state) {
    throw new AuthError('The sign-in response carries no code and no state.')
  }
  if (!flow) {
    throw new AuthError(
      'This sign-in did not start in this browser.',
      'Start the sign-in again.',
    )
  }
  if (!constantTimeEquals(flow.state, params.state)) {
    throw new AuthError('The state in the sign-in response does not match.')
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: redirectUri(config),
    client_id: config.oidc.clientId,
    code_verifier: flow.verifier,
  })

  let response: Response
  try {
    response = await fetchImpl(config.oidc.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: body.toString(),
      credentials: 'omit',
      cache: 'no-store',
    })
  } catch (cause) {
    throw new AuthError('Could not reach the token endpoint.', String(cause))
  }
  if (!response.ok) {
    throw new AuthError('The token exchange was refused.', `HTTP ${response.status}`)
  }
  const payload = (await response.json()) as Record<string, unknown>
  const accessToken = typeof payload.access_token === 'string' ? payload.access_token : ''
  if (accessToken === '') {
    throw new AuthError('The token response carries no access_token.')
  }
  const expiresIn = typeof payload.expires_in === 'number' ? payload.expires_in : null

  return {
    tokens: {
      accessToken,
      idToken: typeof payload.id_token === 'string' ? payload.id_token : null,
      expiresAt: expiresIn === null ? null : Math.floor(Date.now() / 1000) + expiresIn,
    },
    returnTo: safeReturnTo(flow.returnTo, config),
  }
}

/**
 * A stored return path is only usable if it is a path on this console.
 *
 * Without this, a login link with a crafted flow entry becomes an open
 * redirect that runs immediately after a successful authentication — the worst
 * possible moment for one.
 */
export function safeReturnTo(candidate: string, config: ConsoleRuntimeConfig): string {
  const fallback = '/'
  if (typeof candidate !== 'string' || candidate === '') return fallback
  // Anything that is not a plain rooted path is refused outright: `//host` and
  // `https://host` both navigate off-origin, and `\` is normalised to `/` by
  // some browsers.
  if (!candidate.startsWith('/') || candidate.startsWith('//') || candidate.includes('\\')) {
    return fallback
  }
  const base = trimTrailing(config.basePath)
  // The router's paths are relative to the base path; a stored value carrying
  // the base is accepted and stripped, and anything else outside it is refused.
  if (base !== '' && candidate.startsWith(`${base}/`)) {
    return candidate.slice(base.length) || fallback
  }
  if (base !== '' && candidate === base) return fallback
  return candidate
}

export function logoutUrl(config: ConsoleRuntimeConfig, idToken: string | null): string | null {
  if (!config.oidc.endSessionEndpoint) return null
  const url = new URL(config.oidc.endSessionEndpoint)
  url.searchParams.set('post_logout_redirect_uri', new URL(config.basePath, window.location.origin).toString())
  if (idToken) url.searchParams.set('id_token_hint', idToken)
  return url.toString()
}

// --- transient flow state ---------------------------------------------------

export function saveFlow(flow: FlowState): void {
  try {
    window.sessionStorage.setItem(FLOW_KEY, JSON.stringify(flow))
  } catch {
    // A browser with storage disabled cannot complete a redirect flow at all.
    // completeLogin says so rather than failing obscurely here.
  }
}

export function takeFlow(): FlowState | null {
  let raw: string | null = null
  try {
    raw = window.sessionStorage.getItem(FLOW_KEY)
    window.sessionStorage.removeItem(FLOW_KEY)
  } catch {
    return null
  }
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as Partial<FlowState>
    if (typeof parsed.state !== 'string' || typeof parsed.verifier !== 'string') return null
    return {
      state: parsed.state,
      verifier: parsed.verifier,
      returnTo: typeof parsed.returnTo === 'string' ? parsed.returnTo : '/',
      startedAt: typeof parsed.startedAt === 'number' ? parsed.startedAt : 0,
    }
  } catch {
    return null
  }
}

export function clearFlow(): void {
  try {
    window.sessionStorage.removeItem(FLOW_KEY)
  } catch {
    /* nothing to clear */
  }
}

function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

function trimTrailing(path: string): string {
  return path.replace(/\/+$/, '')
}
