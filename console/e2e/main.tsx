/**
 * The end-to-end page's entry point.
 *
 * It renders the production shell — the real router, the real AuthProvider, the
 * real API client, the real stylesheets — with the two substitutions a test
 * always makes: the configuration document a server would have supplied, and
 * `fetch`. Everything visual is the shipped thing, which is the whole point:
 * the check this suite exists for is colour contrast, and a page that styled
 * itself would be measuring its own stylesheet.
 */
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App } from '../src/app/App'
import { AuthProvider } from '../src/auth/AuthProvider'
import { sessionFromTokens } from '../src/auth/session'
import { parseRuntimeConfig } from '../src/config/runtime-config'
import { scenarioFetch } from './scenario'
import '../src/styles.css'

const config = parseRuntimeConfig({
  version: 1,
  apiBaseUrl: '',
  basePath: '/',
  oidc: {
    issuer: 'https://idp.test',
    authorizationEndpoint: 'https://idp.test/authorize',
    tokenEndpoint: 'https://idp.test/token',
    endSessionEndpoint: 'https://idp.test/logout',
    clientId: 'stamp-console',
    scopes: ['openid', 'profile'],
    roleClaim: 'roles',
  },
})

/** A token shaped like an IdP's, unsigned — nothing in this page verifies. */
function token(claims: Record<string, unknown>): string {
  const encode = (value: unknown) => {
    const utf8 = new TextEncoder().encode(JSON.stringify(value))
    let binary = ''
    for (const byte of utf8) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }
  return `${encode({ alg: 'none' })}.${encode(claims)}.`
}

const session = sessionFromTokens({
  accessToken: token({
    sub: 'u-1',
    name: '테스트 승인자',
    roles: ['author', 'approver', 'auditor'],
    exp: Math.floor(Date.now() / 1000) + 3600,
  }),
  idToken: null,
  expiresAt: Math.floor(Date.now() / 1000) + 3600,
})

const container = document.getElementById('root')
if (!container) throw new Error('#root가 문서에 없습니다.')

createRoot(container).render(
  <StrictMode>
    <BrowserRouter basename={config.basePath}>
      <AuthProvider
        config={config}
        initialSession={session}
        navigateAway={() => undefined}
        fetchImpl={scenarioFetch()}
      >
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
)
