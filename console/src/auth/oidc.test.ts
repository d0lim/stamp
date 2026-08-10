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
  it('S256 challenge를 붙여 IdP로 보낸다', async () => {
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

  it('verifier는 sessionStorage에, 토큰은 어디에도 저장하지 않는다', async () => {
    await beginLogin(config, '/inbox', vi.fn())
    const stored = JSON.stringify(window.sessionStorage)
    expect(stored).toContain('verifier')
    expect(window.localStorage.length).toBe(0)
  })

  it('challenge는 verifier의 SHA-256이다', async () => {
    const pair = await createPKCEPair()
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pair.verifier))
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
    expect(pair.challenge).toBe(expected)
  })

  it('state가 다르면 토큰 교환을 하지 않는다', async () => {
    await beginLogin(config, '/inbox', vi.fn())
    const fetchImpl = vi.fn()

    await expect(
      completeLogin(config, { code: 'c', state: 'not-the-one' }, fetchImpl as unknown as typeof fetch),
    ).rejects.toBeInstanceOf(AuthError)
    expect(fetchImpl).not.toHaveBeenCalled()
  })

  it('이 브라우저에서 시작하지 않은 콜백을 거부한다', async () => {
    await expect(completeLogin(config, { code: 'c', state: 's' })).rejects.toThrow(AuthError)
  })

  it('IdP가 오류를 돌려주면 사유를 전한다', async () => {
    await expect(
      completeLogin(config, { error: 'access_denied', errorDescription: '사용자가 취소함' }),
    ).rejects.toThrow(/완료되지 않았습니다/)
  })

  it('코드를 교환하고 원래 화면으로 돌아간다', async () => {
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

  it('authorization url은 설정된 scope를 그대로 요청한다', () => {
    const url = new URL(buildAuthorizationUrl(config, 'st', 'ch'))
    expect(url.searchParams.get('scope')).toBe('openid profile')
  })
})

describe('복귀 경로 검증', () => {
  it.each([
    ['https://attacker.example/', '/'],
    ['//attacker.example/', '/'],
    ['/\\attacker.example', '/'],
    ['javascript:alert(1)', '/'],
  ])('오리진 밖 복귀 경로 %s를 거부한다', (candidate, expected) => {
    expect(safeReturnTo(candidate, config)).toBe(expected)
  })

  it('콘솔 안의 경로는 그대로 쓴다', () => {
    expect(safeReturnTo('/console/policies', config)).toBe('/policies')
    expect(safeReturnTo('/inbox', config)).toBe('/inbox')
  })
})
