/**
 * jsdom is missing two things the console genuinely uses, and both are filled
 * with the real implementation rather than a stub: WebCrypto, which PKCE needs
 * for a verifier that is actually random, and a `fetch` that fails loudly so a
 * test which forgot to inject one does not quietly reach the network.
 */
import '@testing-library/jest-dom/vitest'
import { webcrypto } from 'node:crypto'
import { afterEach, vi } from 'vitest'
import { cleanup } from '@testing-library/react'
import { setSession } from '../auth/session'

if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true })
}

globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
  throw new Error(
    `A test called fetch without injecting one: ${String(input)}. ` +
      `Pass fetchImpl.`,
  )
}) as unknown as typeof fetch

afterEach(() => {
  cleanup()
  // The session is module state by design (auth/session.ts). Tests share a
  // module registry, so leaving it set would leak one test's login into the
  // next one's assertions.
  setSession(null)
  window.sessionStorage.clear()
})
