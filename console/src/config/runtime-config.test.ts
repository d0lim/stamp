/**
 * R50, asserted rather than asserted-to.
 *
 * The claim is that the API base address comes only from the server-supplied
 * document. The way to test a negative like that is to put the attacker's value
 * in every channel that has ever been used to configure a single page app, load
 * the console the way it really loads, and check that the value that came out
 * is still the server's.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ConfigError, loadRuntimeConfig, parseRuntimeConfig } from './runtime-config'
import { TEST_CONFIG_DOCUMENT } from '../test/harness'

const SERVER_VALUE = 'https://api.stamp.internal'
const ATTACKER_VALUE = 'https://attacker.example'

function serverDocument(overrides: Record<string, unknown> = {}) {
  return { ...TEST_CONFIG_DOCUMENT, apiBaseUrl: SERVER_VALUE, ...overrides }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('API 기준 주소의 출처', () => {
  beforeEach(() => {
    window.localStorage.clear()
    window.sessionStorage.clear()
  })

  it('질의 문자열로 덮어쓰려는 시도를 무시한다', async () => {
    // The link an approver was sent.
    window.history.replaceState({}, '', `/console/inbox?apiBaseUrl=${encodeURIComponent(ATTACKER_VALUE)}`)
    const fetchImpl = vi.fn(async () => jsonResponse(serverDocument()))

    const config = await loadRuntimeConfig(fetchImpl as unknown as typeof fetch)

    expect(config.apiBaseUrl).toBe(SERVER_VALUE)
    expect(window.location.search).toContain('attacker.example')
  })

  it('조각(fragment)으로 덮어쓰려는 시도를 무시한다', async () => {
    window.history.replaceState({}, '', `/console/inbox#apiBaseUrl=${encodeURIComponent(ATTACKER_VALUE)}`)
    const fetchImpl = vi.fn(async () => jsonResponse(serverDocument()))

    const config = await loadRuntimeConfig(fetchImpl as unknown as typeof fetch)

    expect(config.apiBaseUrl).toBe(SERVER_VALUE)
  })

  it('localStorage로 덮어쓰려는 시도를 무시한다', async () => {
    // Every plausible key an implementation might have used.
    for (const key of ['apiBaseUrl', 'stamp.apiBaseUrl', 'STAMP_API_BASE_URL', 'config']) {
      window.localStorage.setItem(key, ATTACKER_VALUE)
    }
    window.sessionStorage.setItem('stamp.apiBaseUrl', ATTACKER_VALUE)
    const fetchImpl = vi.fn(async () => jsonResponse(serverDocument()))

    const config = await loadRuntimeConfig(fetchImpl as unknown as typeof fetch)

    expect(config.apiBaseUrl).toBe(SERVER_VALUE)
  })

  it('설정 문서만 읽는다 — 같은 오리진의 한 곳', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(serverDocument()))
    await loadRuntimeConfig(fetchImpl as unknown as typeof fetch)

    expect(fetchImpl).toHaveBeenCalledTimes(1)
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('/console/config.json')
    expect(init.credentials).toBe('omit')
  })

  it('설정된 값은 동결되어 나중에 바뀌지 않는다', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(serverDocument()))
    const config = await loadRuntimeConfig(fetchImpl as unknown as typeof fetch)

    expect(() => {
      ;(config as { apiBaseUrl: string }).apiBaseUrl = ATTACKER_VALUE
    }).toThrow()
    expect(config.apiBaseUrl).toBe(SERVER_VALUE)
  })
})

describe('설정 문서 검증', () => {
  it('빈 기준 주소는 같은 오리진을 뜻한다', () => {
    expect(parseRuntimeConfig(serverDocument({ apiBaseUrl: '' })).apiBaseUrl).toBe('')
  })

  it('다른 오리진의 기준 주소를 받아들인다', () => {
    // D19's separability: the same bundle, pointed at another origin.
    expect(parseRuntimeConfig(serverDocument({ apiBaseUrl: 'https://engine.other' })).apiBaseUrl).toBe(
      'https://engine.other',
    )
  })

  it('상대 경로 기준 주소를 거부한다', () => {
    expect(() => parseRuntimeConfig(serverDocument({ apiBaseUrl: '/api' }))).toThrow(ConfigError)
  })

  it('javascript: 스킴을 거부한다', () => {
    expect(() => parseRuntimeConfig(serverDocument({ apiBaseUrl: 'javascript:alert(1)' }))).toThrow(
      ConfigError,
    )
  })

  it('이해하지 못하는 문서 버전을 거부한다', () => {
    expect(() => parseRuntimeConfig(serverDocument({ version: 99 }))).toThrow(ConfigError)
  })

  it('설정 문서를 못 받으면 명확한 오류가 된다', async () => {
    const fetchImpl = vi.fn(async () => new Response('nope', { status: 503 }))
    await expect(loadRuntimeConfig(fetchImpl as unknown as typeof fetch)).rejects.toThrow(ConfigError)
  })
})
