/**
 * PKCE, RFC 7636, S256 only.
 *
 * `plain` is not implemented. It is still in the RFC and it is still worthless:
 * a verifier sent in the clear is a verifier an interceptor of the redirect
 * already has.
 */

const VERIFIER_BYTES = 32

export interface PKCEPair {
  readonly verifier: string
  readonly challenge: string
}

export function randomUrlSafeString(bytes = VERIFIER_BYTES): string {
  const buffer = new Uint8Array(bytes)
  crypto.getRandomValues(buffer)
  return base64UrlEncode(buffer)
}

export async function createPKCEPair(): Promise<PKCEPair> {
  const verifier = randomUrlSafeString()
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return { verifier, challenge: base64UrlEncode(new Uint8Array(digest)) }
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
