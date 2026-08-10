/**
 * The unauthenticated door.
 *
 * An unauthenticated visit does not silently redirect to the IdP. It renders a
 * screen with one button, and the reason is that a silent redirect on load is
 * indistinguishable from a broken deployment when the IdP is misconfigured —
 * the person sees a flash and an error page from a host they do not recognise.
 * With the button, the console has already told them where they are, and the
 * location they were headed for is preserved across the round trip.
 */
import { useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'
import { RouteAnnouncer } from '../a11y/RouteAnnouncer'
import { useAuth } from '../auth/AuthProvider'
import { isLoginConfigured } from '../config/runtime-config'
import { EnvConsoleVariables } from './config-names'

export function AuthGate({ children }: { readonly children: ReactNode }) {
  const { session, signIn, config } = useAuth()
  const routerLocation = useLocation()

  if (session) return <>{children}</>

  if (!isLoginConfigured(config)) {
    return (
      <div className="panel panel--refusal">
        <RouteAnnouncer title="로그인 설정 없음" />
        <h1>콘솔에 로그인 설정이 없습니다</h1>
        <p>이 배포는 콘솔용 OIDC 클라이언트를 설정하지 않았습니다. 다음 환경 변수를 설정하십시오.</p>
        <ul>
          {EnvConsoleVariables.map((name) => (
            <li key={name}>
              <code>{name}</code>
            </li>
          ))}
        </ul>
      </div>
    )
  }

  const returnTo = `${routerLocation.pathname}${routerLocation.search}`
  return (
    <div className="panel panel--signin">
      <RouteAnnouncer title="로그인" />
      <h1>로그인이 필요합니다</h1>
      <p>
        STAMP 콘솔은 <code>{config.oidc.issuer || '설정된 IdP'}</code>의 계정으로 로그인합니다.
      </p>
      <button
        type="button"
        className="button button--primary"
        onClick={() => void signIn(returnTo)}
        data-testid="sign-in"
      >
        로그인
      </button>
    </div>
  )
}
