/**
 * The test harness the shell's own tests use, and the one U15 and U16 inherit.
 *
 * It renders the real shell — real router, real auth provider, real API client
 * — with two things substituted: the configuration document, which a server
 * would have supplied, and `fetch`, which is the boundary a unit test should
 * not cross. Everything else is the production path, because a harness that
 * mocked the provider would test the harness.
 */
import { render, type RenderResult } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { useEffect, type ReactNode } from 'react'
import type { ApiClient } from '../api/client'
import { App } from '../app/App'
import { AuthProvider, useAuth } from '../auth/AuthProvider'
import { sessionFromTokens } from '../auth/session'
import { parseRuntimeConfig, type ConsoleRuntimeConfig } from '../config/runtime-config'

export const TEST_CONFIG_DOCUMENT = {
  version: 1,
  apiBaseUrl: '',
  basePath: '/console/',
  oidc: {
    issuer: 'https://idp.test',
    authorizationEndpoint: 'https://idp.test/authorize',
    tokenEndpoint: 'https://idp.test/token',
    endSessionEndpoint: 'https://idp.test/logout',
    clientId: 'stamp-console',
    scopes: ['openid', 'profile'],
    roleClaim: 'roles',
  },
} as const

export function testConfig(overrides: Record<string, unknown> = {}): ConsoleRuntimeConfig {
  return parseRuntimeConfig({ ...TEST_CONFIG_DOCUMENT, ...overrides })
}

/** A token shaped like one an IdP would return, unsigned — nothing here verifies. */
export function testToken(claims: Record<string, unknown>): string {
  // btoa is Latin-1 only, and a real deployment's `name` claim carries whatever
  // the IdP holds — routinely characters outside Latin-1. The console decodes
  // UTF-8 on the way out (auth/claims.ts), so the harness has to encode it on
  // the way in or the tests would only ever exercise ASCII.
  const encode = (value: unknown) => {
    const utf8 = new TextEncoder().encode(JSON.stringify(value))
    let binary = ''
    for (const byte of utf8) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }
  return `${encode({ alg: 'none' })}.${encode(claims)}.`
}

export interface HarnessOptions {
  readonly roles?: readonly string[]
  readonly signedIn?: boolean
  readonly route?: string
  readonly config?: ConsoleRuntimeConfig
  readonly fetchImpl?: typeof fetch
  readonly navigateAway?: (url: string) => void
  /**
   * The `name` claim the fake token carries. Its default is non-ASCII on
   * purpose — see `renderShell` below.
   */
  readonly name?: string
  /**
   * Stands in for a feature screen: it is handed the same API client every
   * screen gets, and runs once after mount. U15 and U16 will have real screens
   * here; the shell's tests need something that calls the API without owning
   * how a failure is handled.
   */
  readonly probe?: (api: ApiClient) => void
}

function Probe({ run }: { readonly run: (api: ApiClient) => void }) {
  const { api } = useAuth()
  useEffect(() => {
    run(api)
  }, [api, run])
  return null
}

export function renderShell(options: HarnessOptions = {}): RenderResult {
  const {
    roles = ['author'],
    signedIn = true,
    route = '/',
    config = testConfig(),
    fetchImpl,
    navigateAway = () => undefined,
    // Non-ASCII on purpose, and outside Latin-1 on purpose: this is what
    // drives the UTF-8 encode/decode path through `testToken` above and
    // `decodeClaims` in auth/claims.ts. Nothing asserts on this string, so this
    // comment is the only thing holding that coverage — simplifying it to
    // `Test User` would delete the path from every test in the suite and leave
    // them all green. Do not.
    name = 'Łukasz Wróblewski',
    probe,
  } = options

  const session = signedIn
    ? sessionFromTokens({
        accessToken: testToken({ sub: 'u-1', name, roles, exp: Math.floor(Date.now() / 1000) + 3600 }),
        idToken: null,
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      })
    : null

  return render(
    <Wrapper
      config={config}
      session={session}
      route={route}
      {...(fetchImpl ? { fetchImpl } : {})}
      navigateAway={navigateAway}
    >
      <App />
      {probe ? <Probe run={probe} /> : null}
    </Wrapper>,
  )
}

function Wrapper({
  config,
  session,
  route,
  fetchImpl,
  navigateAway,
  children,
}: {
  readonly config: ConsoleRuntimeConfig
  readonly session: ReturnType<typeof sessionFromTokens> | null
  readonly route: string
  readonly fetchImpl?: typeof fetch
  readonly navigateAway: (url: string) => void
  readonly children: ReactNode
}) {
  return (
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider
        config={config}
        initialSession={session}
        navigateAway={navigateAway}
        {...(fetchImpl ? { fetchImpl } : {})}
      >
        {children}
      </AuthProvider>
    </MemoryRouter>
  )
}
