/**
 * One decision, with the policy version and the fact snapshot it froze (R22).
 *
 * Everything on this screen is rendered as text. That is not a precaution about
 * this data in particular — it is the rule: a fact snapshot is whatever a
 * caller sent, a policy document is authored content, and there is no HTML
 * interpretation path on this screen at all. React's own escaping is what
 * enforces it, and the test that proves it feeds a script tag through.
 *
 * The policy shown is the version the decision was evaluated under and never
 * the effective one. A decision has to stay explainable by the text that
 * produced it; showing today's policy beside yesterday's decision is the
 * substitution the frozen column exists to prevent.
 */
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ApiError, type ApiClient } from '../api/client'
import { Disclosure } from '../a11y/Disclosure'
import { RouteAnnouncer } from '../a11y/RouteAnnouncer'
import { useAuth } from '../auth/AuthProvider'
import { STATE_LABELS, type AuditDecisionDetail } from './api-types'

/** JSON as text, two-space indented. Never markup. */
export function asText(value: unknown): string {
  if (value === undefined || value === null) return '(none)'
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

export function AuditDecisionScreen() {
  const { api } = useAuth()
  const params = useParams()
  const id = params.decisionId ?? ''
  const { detail, error, unavailable } = useDecision(api, id)

  return (
    <div className="panel">
      <RouteAnnouncer title="Decision detail" />
      <h1>Decision detail</h1>
      <p>
        <Link to="/audit">Back to the audit list</Link>
      </p>

      {unavailable ? (
        <div className="notice notice--warning" role="alert" data-testid="decision-unavailable">
          <p className="notice__text">
            This decision cannot be opened — it does not exist, or it is not open to you. The server
            does not distinguish between the two.
          </p>
          <p>
            Without auditor standing you can open only the decisions you initiated or are the
            subject of. Check the decision identifier again.
          </p>
        </div>
      ) : error === null ? null : (
        <p className="notice notice--warning" role="alert" data-testid="decision-error">
          The decision could not be read: {error}
        </p>
      )}

      {detail === null ? (
        unavailable ? null : <p>Reading the decision…</p>
      ) : (
        <>
          <dl className="summary-list">
            <dt>Decision</dt>
            <dd>{detail.id}</dd>
            <dt>State</dt>
            <dd>{STATE_LABELS[detail.state] ?? detail.state}</dd>
            <dt>Caller</dt>
            <dd>{detail.caller_id}</dd>
            <dt>Subject · resource · action</dt>
            <dd>
              {detail.subject_id} · {detail.resource_id} · {detail.action}
            </dd>
            <dt>Policy version applied</dt>
            <dd data-testid="policy-version">
              {detail.policy_id} · v{detail.policy_version}
              {detail.policy_origin === '' ? '' : ` · ${detail.policy_origin}`}
            </dd>
            <dt>Created · expires</dt>
            <dd>
              {detail.created_at} · {detail.expires_at}
            </dd>
            {detail.resolved_at === undefined ? null : (
              <>
                <dt>Resolved</dt>
                <dd>{detail.resolved_at}</dd>
              </>
            )}
          </dl>

          {detail.via_auditor_standing ? null : (
            <p className="field__hint" data-testid="own-record-notice">
              You are reading this under the “decisions you initiated or are the subject of” rule,
              not under auditor standing.
            </p>
          )}

          <h2>Frozen material</h2>
          <Disclosure summary="Request">
            <pre className="document" data-testid="audit-request">
              {asText(detail.request)}
            </pre>
          </Disclosure>
          <Disclosure summary="Fact snapshot">
            <pre className="document" data-testid="audit-facts">
              {asText(detail.fact_snapshot)}
            </pre>
          </Disclosure>
          <Disclosure summary="Obligations">
            <pre className="document" data-testid="audit-obligations">
              {asText(detail.obligations)}
            </pre>
          </Disclosure>
          <Disclosure summary={`Policy document (as of v${detail.policy_version})`}>
            <pre className="document" data-testid="audit-policy-document">
              {detail.policy_document === ''
                ? 'The policy document for this version could not be read.'
                : detail.policy_document}
            </pre>
          </Disclosure>

          <h2>challenge</h2>
          {detail.challenges.length === 0 ? (
            <p>This decision has no challenge.</p>
          ) : (
            <table className="audit-table" data-testid="audit-challenges">
              <caption>challenge progress</caption>
              <thead>
                <tr>
                  <th scope="col">Ordinal</th>
                  <th scope="col">Kind</th>
                  <th scope="col">State</th>
                  <th scope="col">Deadline</th>
                  <th scope="col">Satisfied</th>
                </tr>
              </thead>
              <tbody>
                {detail.challenges.map((challenge) => (
                  <tr key={challenge.ordinal}>
                    <td>{challenge.ordinal}</td>
                    <td>{challenge.kind}</td>
                    <td>{challenge.state}</td>
                    <td>{challenge.deadline ?? '—'}</td>
                    <td>{challenge.satisfied_at ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <h2>Approvals</h2>
          {detail.approvals.length === 0 ? (
            <p data-testid="audit-approvals-empty">No approval was recorded.</p>
          ) : (
            <table className="audit-table" data-testid="audit-approvals">
              <caption>The approvals collected and their binding hashes</caption>
              <thead>
                <tr>
                  <th scope="col">challenge</th>
                  <th scope="col">Approver</th>
                  <th scope="col">Judgment</th>
                  <th scope="col">Binding hash</th>
                  <th scope="col">Submitted</th>
                </tr>
              </thead>
              <tbody>
                {detail.approvals.map((approval) => (
                  <tr key={`${approval.ordinal}:${approval.approver_id}`}>
                    <td>{approval.ordinal}</td>
                    <td>{approval.approver_id}</td>
                    <td>{approval.verdict}</td>
                    <td>
                      <code>{approval.binding_hash}</code>
                    </td>
                    <td>{approval.submitted_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  )
}

/**
 * One decision, and the one thing this screen is allowed to say when it does not
 * get one.
 *
 * This used to key its refusal on a 403. The read surface no longer has one:
 * `403 not_readable` and `404 not_found` were the same existence oracle the
 * approval surface had, so they became one 404 with one body (#38). This is the
 * *other* door to R40's rule — a targeted approver reads their own decision here
 * rather than on the PEP surface — so a difference here would have been a
 * difference anyone with a console credential could reach by asking twice.
 *
 * The consequence for this screen is that "not yours" and "does not exist" are
 * one state, and the copy says both rather than picking one. The audit *list*
 * keeps its 403 and its own refusal screen: standing to read a collection says
 * nothing about any single decision (R22).
 */
function useDecision(api: ApiClient, id: string) {
  const [detail, setDetail] = useState<AuditDecisionDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [unavailable, setUnavailable] = useState(false)

  useEffect(() => {
    let live = true
    void (async () => {
      try {
        const response = await api.request<AuditDecisionDetail>('audit-decision-read', {
          params: { id },
        })
        if (!live) return
        setDetail(response)
        setError(null)
        setUnavailable(false)
      } catch (cause) {
        if (cause instanceof ApiError && cause.isUnauthenticated) return
        if (!live) return
        setDetail(null)
        setUnavailable(cause instanceof ApiError && cause.isNotFound)
        setError(cause instanceof Error ? cause.message : String(cause))
      }
    })()
    return () => {
      live = false
    }
  }, [api, id])

  return { detail, error, unavailable }
}
