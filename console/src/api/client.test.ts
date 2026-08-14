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

describe('the API client', () => {
  it('calls only names the contract declares', async () => {
    const { api } = client({})
    await expect(api.request('policy-secret-list')).rejects.toBeInstanceOf(UnknownEndpointError)
  })

  it('requests with the method and path the contract declares', async () => {
    const { api, calls } = client({ token: 'tok' })
    await api.request('revision-read', { params: { id: 'rev-1' } })

    expect(calls[0]?.url).toBe('/policies/revisions/rev-1')
    expect(calls[0]?.init.method).toBe('GET')
    expect((calls[0]?.init.headers as Record<string, string>).Authorization).toBe('Bearer tok')
  })

  it('encodes path arguments', () => {
    expect(fillPath('/policies/revisions/{id}', { id: 'a/../b' })).toBe('/policies/revisions/a%2F..%2Fb')
  })

  it('uses the configured base address as given — even on another origin', async () => {
    const { api, calls } = client({ apiBaseUrl: 'https://engine.other' })
    await api.request('policy-list')
    expect(calls[0]?.url).toBe('https://engine.other/policies')
  })

  it('goes to the same origin when the base address is empty', async () => {
    const { api, calls } = client({})
    await api.request('policy-list')
    expect(calls[0]?.url).toBe('/policies')
  })

  it('sends no ambient credentials', async () => {
    const { api, calls } = client({ token: 'tok' })
    await api.request('policy-list')
    expect(calls[0]?.init.credentials).toBe('omit')
    expect(calls[0]?.init.redirect).toBe('error')
  })

  it('calls the re-login hook and throws ApiError on a 401', async () => {
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

  it('a 403 is distinguished as a missing permission', async () => {
    const { api } = client({ respond: () => new Response('{}', { status: 403 }) })
    const error = (await api.request('policy-list').catch((e: unknown) => e)) as ApiError
    expect(error.isForbidden).toBe(true)
  })

  it('a 404 is distinguished as absence, and does not overlap a 403', async () => {
    // The decision surfaces answer this for "not yours" as well (#38), so the
    // screens that used to read isForbidden read this instead. The two stay
    // separate here because the audit *list* still has a real 403.
    const { api } = client({
      respond: () => new Response('{"error":"not_found"}', { status: 404 }),
    })
    const error = (await api.request('policy-list').catch((e: unknown) => e)) as ApiError
    expect(error.isNotFound).toBe(true)
    expect(error.isForbidden).toBe(false)
  })
})

describe('the contract document', () => {
  it('carries the endpoints Go generated', () => {
    const names = ENDPOINTS.map((e) => e.name)
    expect(names).toContain('policy-list')
    expect(names).toContain('approval-submit')
    expect(names).toContain('delay-cancel')
  })

  it('every API endpoint requires a user token', () => {
    for (const e of ENDPOINTS.filter((x) => x.group === 'api')) {
      expect(e.auth).toBe('user')
    }
  })
})
