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
  form: 'console authoring',
  file: 'file authoring',
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
      <RouteAnnouncer title="Policies" />
      <h1>Policies</h1>

      <GovernanceBanner
        api={api}
        state={governance}
        subjectId={typeof session?.claims?.sub === 'string' ? session.claims.sub : null}
      />

      <p>
        <Link to="/policies/new">Start authoring a new policy</Link>
      </p>

      {error === null ? null : (
        <p className="notice notice--warning" data-testid="policy-list-error">
          Could not read the policy list: {error}
        </p>
      )}

      {policies === null ? (
        <p>Reading the policy list…</p>
      ) : policies.length === 0 ? (
        <p data-testid="policy-list-empty">
          No policy is in force. Start authoring a new one.
        </p>
      ) : (
        <ul className="policy-list">
          {policies.map((policy) => (
            <li key={policy.id}>
              <Disclosure
                summary={`${policy.id} · v${policy.version} · ${ORIGIN_LABELS[policy.origin] ?? policy.origin}${
                  policy.reserved ? ' · reserved policy' : ''
                }`}
              >
                {policy.origin === 'file' ? (
                  <p className="field__hint" data-testid={`file-origin-${policy.id}`}>
                    This policy is owned by file authoring. Editing it in the console requires the
                    adoption procedure that hands the owning path from file to console; it cannot
                    be saved straight from the form.
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
