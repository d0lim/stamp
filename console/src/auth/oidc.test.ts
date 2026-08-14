import { describe, expect, it, vi } from 'vitest'
import {
  AuthError,
  buildAuthorizationUrl,
  completeLogin,
  beginLogin,
  redirectUri,
  safeReturnTo,
  takeFlow,
} from './oidc'
import { createPKCEPair } from './pkce'
import { testConfig } from '../test/harness'

const config = testConfig()

describe('authorization code + PKCE', () => {
  it('sends the visitor to the IdP with an S256 challenge attached', async () => {
    const navigate = vi.fn()
    await beginLogin(config, '/inbox', navigate)

    expect(navigate).toHaveBeenCalledTimes(1)
    const url = new URL(navigate.mock.calls[0]?.[0] as string)
    expect(url.origin + url.pathname).toBe('https://idp.test/authorize')
    expect(url.searchParams.get('response_type')).toBe('code')
    expect(url.searchParams.get('code_challenge_method')).toBe('S256')
    expect(url.searchParams.get('code_challenge')).toBeTruthy()
    expect(url.searchParams.get('client_id')).toBe('stamp-console')
    expect(url.searchParams.get('redirect_uri')).toBe(redirectUri(config))
  })

  it('keeps the verifier in sessionStorage and the tokens nowhere', async () => {
    await beginLogin(config, '/inbox', vi.fn())
    const stored = JSON.stringify(window.sessionStorage)
    expect(stored).toContain('verifier')
    expect(window.localStorage.length).toBe(0)
  })

  it('the challenge is the SHA-256 of the verifier', async () => {
    const pair = await createPKCEPair()
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pair.verifier))
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
    expect(pair.challenge).toBe(expected)
  })

  it('does not exchange the token when the state differs', async () => {
    await beginLogin(config, '/inbox', vi.fn())
    const fetchImpl = vi.fn()

    await expect(
      completeLogin(config, { code: 'c', state: 'not-the-one' }, fetchImpl as unknown as typeof fetch),
    ).rejects.toBeInstanceOf(AuthError)
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('refuses a callback that did not start in this browser', async () => {
    await expect(completeLogin(config, { code: 'c', state: 's' })).rejects.toThrow(AuthError)
  })

  it('carries the reason through when the IdP returns an error', async () => {
    await expect(
      completeLogin(config, { error: 'access_denied', errorDescription: 'the user cancelled' }),
    ).rejects.toThrow(/did not complete/)
  })

  it('exchanges the code and returns to the original screen', async () => {
    const navigate = vi.fn()
    await beginLogin(config, '/console/inbox/d-1', navigate)
    const authorizeUrl = new URL(navigate.mock.calls[0]?.[0] as string)
    const state = authorizeUrl.searchParams.get('state') as string

    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify({ access_token: 'at', id_token: 'it', expires_in: 300 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    const result = await completeLogin(
      config,
      { code: 'the-code', state },
      fetchImpl as unknown as typeof fetch,
    )

    expect(result.tokens.accessToken).toBe('at')
    // The base path is stripped: the router's paths are relative to it.
    expect(result.returnTo).toBe('/inbox/d-1')
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('https://idp.test/token')
    expect(String(init.body)).toContain('code_verifier=')
    // The flow is single use.
    expect(takeFlow()).toBeNull()
  })

  it('the authorization url requests exactly the configured scopes', () => {
    const url = new URL(buildAuthorizationUrl(config, 'st', 'ch'))
    expect(url.searchParams.get('scope')).toBe('openid profile')
  })
})

describe('validating the return path', () => {
  it.each([
    ['https://attacker.example/', '/'],
    ['//attacker.example/', '/'],
    ['/\\attacker.example', '/'],
    ['javascript:alert(1)', '/'],
  ])('refuses the off-origin return path %s', (candidate, expected) => {
    expect(safeReturnTo(candidate, config)).toBe(expected)
  })

  it('uses a path inside the console as given', () => {
    expect(safeReturnTo('/console/policies', config)).toBe('/policies')
    expect(safeReturnTo('/inbox', config)).toBe('/inbox')
  })
})
