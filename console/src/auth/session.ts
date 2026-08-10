/**
 * The session, held in a module-level variable and nowhere else.
 *
 * "Nowhere else" is the whole design. No localStorage, no sessionStorage, no
 * cookie, no IndexedDB: closing the tab ends the session, and a script that
 * arrives on this origin after the fact finds nothing to read. The cost is a
 * redirect through the IdP on every reload, which is the correct trade for a
 * console that submits approvals.
 */
import { decodeClaims, expiresAt, type TokenClaims } from './claims'
import type { TokenSet } from './oidc'

export interface Session {
  readonly accessToken: string
  readonly idToken: string | null
  readonly claims: TokenClaims | null
  /** Seconds since the epoch, or null when neither source stated one. */
  readonly expiresAt: number | null
}

let current: Session | null = null

export function sessionFromTokens(tokens: TokenSet): Session {
  // The access token is what the engine verifies, so its claims are the ones
  // that describe what this session is. The id token is kept only for the
  // logout hint.
  const claims = decodeClaims(tokens.accessToken)
  return {
    accessToken: tokens.accessToken,
    idToken: tokens.idToken,
    claims,
    expiresAt: tokens.expiresAt ?? expiresAt(claims),
  }
}

export function setSession(session: Session | null): void {
  current = session
}

export function getSession(): Session | null {
  return current
}

export function getAccessToken(): string | null {
  return current?.accessToken ?? null
}

export function isExpired(session: Session | null, now = Date.now()): boolean {
  if (!session) return true
  if (session.expiresAt === null) return false
  return session.expiresAt * 1000 <= now
}
