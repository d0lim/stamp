import { describe, expect, it, vi } from 'vitest'
import { ApiError, createApiClient } from './client'
import { ENDPOINTS, UnknownEndpointError, fillPath } from './contract'
import { testConfig } from '../test/harness'

function client(options: {
  readonly apiBaseUrl?: string
  readonly token?: string | null
  readonly respond?: (url: string, init: RequestInit) => Response
  readonly onUnauthenticated?: () => void
}) {
  const calls: { url: string; init: RequestInit }[] = []
  const fetchImpl = vi.fn(async (url: string | URL | Request, init: RequestInit = {}) => {
    calls.push({ url: String(url), init })
    return options.respond?.(String(url), init) ?? new Response('{}', { status: 200 })
  })
  const api = createApiClient({
    config: testConfig(options.apiBaseUrl === undefined ? {} : { apiBaseUrl: options.apiBaseUrl }),
    getAccessToken: () => options.token ?? null,
    ...(options.onUnauthenticated ? { onUnauthenticated: options.onUnauthenticated } : {}),
    fetchImpl: fetchImpl as unknown as typeof fetch,
  })
  return { api, calls }
}

describe('API 클라이언트', () => {
  it('계약에 있는 이름으로만 호출한다', async () => {
    const { api } = client({})
    await expect(api.request('policy-secret-list')).rejects.toBeInstanceOf(UnknownEndpointError)
  })

  it('계약이 선언한 메서드와 경로로 요청한다', async () => {
    const { api, calls } = client({ token: 'tok' })
    await api.request('revision-read', { params: { id: 'rev-1' } })

    expect(calls[0]?.url).toBe('/policies/revisions/rev-1')
    expect(calls[0]?.init.method).toBe('GET')
    expect((calls[0]?.init.headers as Record<string, string>).Authorization).toBe('Bearer tok')
  })

  it('경로 인자를 인코딩한다', () => {
    expect(fillPath('/policies/revisions/{id}', { id: 'a/../b' })).toBe('/policies/revisions/a%2F..%2Fb')
  })

  it('설정된 기준 주소를 그대로 쓴다 — 다른 오리진이어도', async () => {
    const { api, calls } = client({ apiBaseUrl: 'https://engine.other' })
    await api.request('policy-list')
    expect(calls[0]?.url).toBe('https://engine.other/policies')
  })

  it('기준 주소가 비면 같은 오리진으로 간다', async () => {
    const { api, calls } = client({})
    await api.request('policy-list')
    expect(calls[0]?.url).toBe('/policies')
  })

  it('주변 자격증명을 보내지 않는다', async () => {
    const { api, calls } = client({ token: 'tok' })
    await api.request('policy-list')
    expect(calls[0]?.init.credentials).toBe('omit')
    expect(calls[0]?.init.redirect).toBe('error')
  })

  it('401이면 재로그인 훅을 부르고 ApiError를 던진다', async () => {
    const onUnauthenticated = vi.fn()
    const { api } = client({
      onUnauthenticated,
      respond: () => new Response('{"error":"expired"}', { status: 401 }),
    })
    const error = await api.request('policy-list').catch((e: unknown) => e)

    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).isUnauthenticated).toBe(true)
    expect(onUnauthenticated).toHaveBeenCalledTimes(1)
  })

  it('403은 권한 부족으로 구분된다', async () => {
    const { api } = client({ respond: () => new Response('{}', { status: 403 }) })
    const error = (await api.request('policy-list').catch((e: unknown) => e)) as ApiError
    expect(error.isForbidden).toBe(true)
  })
})

describe('계약 문서', () => {
  it('Go가 생성한 엔드포인트를 담고 있다', () => {
    const names = ENDPOINTS.map((e) => e.name)
    expect(names).toContain('policy-list')
    expect(names).toContain('approval-submit')
    expect(names).toContain('delay-cancel')
  })

  it('모든 API 엔드포인트가 사용자 토큰을 요구한다', () => {
    for (const e of ENDPOINTS.filter((x) => x.group === 'api')) {
      expect(e.auth).toBe('user')
    }
  })
})
