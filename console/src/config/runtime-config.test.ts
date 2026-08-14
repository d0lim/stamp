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

describe('where the API base address comes from', () => {
  beforeEach(() => {
    window.localStorage.clear()
    window.sessionStorage.clear()
  })

  it('ignores an attempt to override it through the query string', async () => {
    // The link an approver was sent.
    window.history.replaceState({}, '', `/console/inbox?apiBaseUrl=${encodeURIComponent(ATTACKER_VALUE)}`)
    const fetchImpl = vi.fn(async () => jsonResponse(serverDocument()))

    const config = await loadRuntimeConfig(fetchImpl as unknown as typeof fetch)

    expect(config.apiBaseUrl).toBe(SERVER_VALUE)
    expect(window.location.search).toContain('attacker.example')
  })

  it('ignores an attempt to override it through the fragment', async () => {
    window.history.replaceState({}, '', `/console/inbox#apiBaseUrl=${encodeURIComponent(ATTACKER_VALUE)}`)
    const fetchImpl = vi.fn(async () => jsonResponse(serverDocument()))

    const config = await loadRuntimeConfig(fetchImpl as unknown as typeof fetch)

    expect(config.apiBaseUrl).toBe(SERVER_VALUE)
  })

  it('ignores an attempt to override it through localStorage', async () => {
    // Every plausible key an implementation might have used.
    for (const key of ['apiBaseUrl', 'stamp.apiBaseUrl', 'STAMP_API_BASE_URL', 'config']) {
      window.localStorage.setItem(key, ATTACKER_VALUE)
    }
    window.sessionStorage.setItem('stamp.apiBaseUrl', ATTACKER_VALUE)
    const fetchImpl = vi.fn(async () => jsonResponse(serverDocument()))

    const config = await loadRuntimeConfig(fetchImpl as unknown as typeof fetch)

    expect(config.apiBaseUrl).toBe(SERVER_VALUE)
  })

  it('reads the configuration document alone — one place, same origin', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(serverDocument()))
    await loadRuntimeConfig(fetchImpl as unknown as typeof fetch)

    expect(fetchImpl).toHaveBeenCalledTimes(1)
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('/console/config.json')
    expect(init.credentials).toBe('omit')
  })

  it('the configured value is frozen and cannot be changed later', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(serverDocument()))
    const config = await loadRuntimeConfig(fetchImpl as unknown as typeof fetch)

    expect(() => {
      ;(config as { apiBaseUrl: string }).apiBaseUrl = ATTACKER_VALUE
    }).toThrow()
    expect(config.apiBaseUrl).toBe(SERVER_VALUE)
  })
})

describe('validating the configuration document', () => {
  it('an empty base address means the same origin', () => {
    expect(parseRuntimeConfig(serverDocument({ apiBaseUrl: '' })).apiBaseUrl).toBe('')
  })

  it('accepts a base address on another origin', () => {
    // D19's separability: the same bundle, pointed at another origin.
    expect(parseRuntimeConfig(serverDocument({ apiBaseUrl: 'https://engine.other' })).apiBaseUrl).toBe(
      'https://engine.other',
    )
  })

  it('refuses a relative base address', () => {
    expect(() => parseRuntimeConfig(serverDocument({ apiBaseUrl: '/api' }))).toThrow(ConfigError)
  })

  it('refuses the javascript: scheme', () => {
    expect(() => parseRuntimeConfig(serverDocument({ apiBaseUrl: 'javascript:alert(1)' }))).toThrow(
      ConfigError,
    )
  })

  it('refuses a document version it does not understand', () => {
    expect(() => parseRuntimeConfig(serverDocument({ version: 99 }))).toThrow(ConfigError)
  })

  it('becomes a clear error when the configuration document does not arrive', async () => {
    const fetchImpl = vi.fn(async () => new Response('nope', { status: 503 }))
    await expect(loadRuntimeConfig(fetchImpl as unknown as typeof fetch)).rejects.toThrow(ConfigError)
  })
})
