/**
 * Reading a token's claims for display and navigation.
 *
 * This decodes; it does not verify. Verification happens in the engine, on
 * every request, against the IdP's JWKS — R17 — and a browser-side check would
 * add nothing because anything that could forge the token could also forge the
 * check's result. What the claims are used for here is which links to show and
 * where to land, and getting that wrong shows a person a screen whose API calls
 * then fail with 403. That is the correct failure: the server decides.
 */

export interface TokenClaims {
  readonly sub?: string
  readonly name?: string
  readonly email?: string
  readonly preferred_username?: string
  readonly exp?: number
  readonly iss?: string
  readonly [claim: string]: unknown
}

export function decodeClaims(jwt: string): TokenClaims | null {
  const parts = jwt.split('.')
  if (parts.length !== 3) return null
  const payload = parts[1]
  if (!payload) return null
  try {
    const padded = payload.replace(/-/g, '+').replace(/_/g, '/')
    const json = decodeURIComponent(
      atob(padded + '='.repeat((4 - (padded.length % 4)) % 4))
        .split('')
        .map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`)
        .join(''),
    )
    const parsed: unknown = JSON.parse(json)
    if (typeof parsed !== 'object' || parsed === null) return null
    return parsed as TokenClaims
  } catch {
    return null
  }
}

export function displayName(claims: TokenClaims | null): string {
  if (!claims) return '알 수 없는 사용자'
  return (
    (typeof claims.name === 'string' && claims.name) ||
    (typeof claims.preferred_username === 'string' && claims.preferred_username) ||
    (typeof claims.email === 'string' && claims.email) ||
    (typeof claims.sub === 'string' && claims.sub) ||
    '알 수 없는 사용자'
  )
}

/** Seconds since the epoch at which the token stops being usable. */
export function expiresAt(claims: TokenClaims | null): number | null {
  return claims && typeof claims.exp === 'number' ? claims.exp : null
}
