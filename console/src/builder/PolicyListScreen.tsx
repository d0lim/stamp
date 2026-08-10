/**
 * The effective policy set, and the way into authoring.
 *
 * The list shows each policy's exchange-format document, because that document
 * is what the engine stores, what a file round-trips, and what an approver reads
 * in a diff — showing a prettier rendering here would give the console a second
 * idea of what a policy is.
 *
 * It is rendered as text and never as markup. A policy document is authored
 * content, and the audit view has the same rule for the same reason (R22): there
 * is no HTML interpretation path on either screen.
 *
 * Origin is displayed rather than hidden. A file-authored policy is owned by the
 * directory it came from, and editing it in the console is a handover with its
 * own procedure rather than a save — so the list says which path owns what
 * instead of offering an edit button that would fail.
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, type ApiClient } from '../api/client'
import { Disclosure } from '../a11y/Disclosure'
import { RouteAnnouncer } from '../a11y/RouteAnnouncer'
import { useAuth } from '../auth/AuthProvider'
import type { PolicyListResponse, PolicyView } from './api-types'
import { GovernanceBanner, useGovernance } from './GovernanceBanner'

const ORIGIN_LABELS: Readonly<Record<string, string>> = {
  form: '콘솔 저작',
  file: '파일 저작',
}

function usePolicies(api: ApiClient) {
  const [policies, setPolicies] = useState<readonly PolicyView[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let live = true
    void (async () => {
      try {
        const response = await api.request<PolicyListResponse>('policy-list')
        if (live) {
          setPolicies(response.policies)
          setError(null)
        }
      } catch (cause) {
        if (cause instanceof ApiError && cause.isUnauthenticated) return
        if (live) setError(cause instanceof Error ? cause.message : String(cause))
      }
    })()
    return () => {
      live = false
    }
  }, [api])

  return { policies, error }
}

export function PolicyListScreen() {
  const { api, session } = useAuth()
  const governance = useGovernance(api)
  const { policies, error } = usePolicies(api)

  return (
    <div className="panel">
      <RouteAnnouncer title="정책" />
      <h1>정책</h1>

      <GovernanceBanner
        api={api}
        state={governance}
        subjectId={typeof session?.claims?.sub === 'string' ? session.claims.sub : null}
      />

      <p>
        <Link to="/policies/new">새 정책 저작 시작</Link>
      </p>

      {error === null ? null : (
        <p className="notice notice--warning" data-testid="policy-list-error">
          정책 목록을 읽지 못했습니다: {error}
        </p>
      )}

      {policies === null ? (
        <p>정책 목록을 읽는 중입니다…</p>
      ) : policies.length === 0 ? (
        <p data-testid="policy-list-empty">
          발효 중인 정책이 없습니다. 새 정책 저작을 시작하십시오.
        </p>
      ) : (
        <ul className="policy-list">
          {policies.map((policy) => (
            <li key={policy.id}>
              <Disclosure
                summary={`${policy.id} · v${policy.version} · ${ORIGIN_LABELS[policy.origin] ?? policy.origin}${
                  policy.reserved ? ' · 예약된 정책' : ''
                }`}
              >
                {policy.origin === 'file' ? (
                  <p className="field__hint" data-testid={`file-origin-${policy.id}`}>
                    파일 저작이 소유한 정책입니다. 콘솔에서 편집하려면 소유 경로를 파일에서 콘솔로
                    넘기는 인수 절차를 거쳐야 하며, 폼에서 바로 저장할 수 없습니다.
                  </p>
                ) : null}
                <pre className="document">{policy.document}</pre>
              </Disclosure>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
