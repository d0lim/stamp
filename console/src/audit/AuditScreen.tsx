/**
 * The decision history (R22).
 *
 * Four axes — period, policy, subject, state — one order, and a cursor. All of
 * them are the server's: the console sends them and echoes back what the server
 * says it applied, rather than displaying the filter it believes it sent. An
 * auditor reading a filtered history has to be able to tell what the filter
 * was, and the only honest source for that is the answer.
 *
 * Paging is a cursor and not a page number, for the reason the store states: a
 * decision inserted while an auditor pages would shift every later page under
 * an offset, and a shifted page silently drops rows.
 *
 * The accessibility bar here is the builder's, not a lower one (R55). Every
 * filter is a labelled control, the result count is announced, and nothing on
 * this screen depends on colour.
 */
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, type ApiClient } from '../api/client'
import { RouteAnnouncer } from '../a11y/RouteAnnouncer'
import { useAuth } from '../auth/AuthProvider'
import {
  DECISION_STATES,
  EMPTY_QUERY,
  STATE_LABELS,
  type AuditDecisionListResponse,
  type AuditQuery,
} from './api-types'

/** Turns the screen's four axes into the query the endpoint takes. */
export function queryParams(query: AuditQuery, cursor: string): Record<string, string | undefined> {
  const nonEmpty = (value: string) => (value.trim() === '' ? undefined : value.trim())
  return {
    from: nonEmpty(query.from),
    to: nonEmpty(query.to),
    policy: nonEmpty(query.policy),
    subject: nonEmpty(query.subject),
    state: nonEmpty(query.state),
    cursor: nonEmpty(cursor),
  }
}

export function AuditScreen() {
  const { api } = useAuth()
  const [draft, setDraft] = useState<AuditQuery>(EMPTY_QUERY)
  const [applied, setApplied] = useState<AuditQuery>(EMPTY_QUERY)
  const [cursor, setCursor] = useState('')
  const [trail, setTrail] = useState<readonly string[]>([])
  const { page, error, refused } = useHistory(api, applied, cursor)

  const search = useCallback(() => {
    setApplied(draft)
    setCursor('')
    setTrail([])
  }, [draft])

  return (
    <div className="panel">
      <RouteAnnouncer title="Audit" />
      <h1>Audit</h1>
      <p>
        The decision history. Open a decision to see the policy version it was evaluated under and
        the fact snapshot it froze.
      </p>

      {refused ? (
        <div className="notice notice--warning" role="alert" data-testid="audit-refused">
          <p className="notice__text">You do not have auditor standing to query the audit history.</p>
          <p>
            The server decides auditor standing from the token claim an operator configured. Without
            it, you can still open the decisions you initiated or are the subject of, by decision
            identifier.
          </p>
        </div>
      ) : null}

      {error === null || refused ? null : (
        <p className="notice notice--warning" role="alert" data-testid="audit-error">
          The decision history could not be read: {error}
        </p>
      )}

      <form
        className="audit-filters"
        onSubmit={(event) => {
          event.preventDefault()
          search()
        }}
      >
        <div className="field">
          <label className="field__label" htmlFor="audit-from">
            Period start (RFC 3339)
          </label>
          <input
            id="audit-from"
            className="control"
            type="text"
            placeholder="2026-08-01T00:00:00Z"
            value={draft.from}
            onChange={(event) => setDraft({ ...draft, from: event.target.value })}
          />
        </div>
        <div className="field">
          <label className="field__label" htmlFor="audit-to">
            Period end (exclusive)
          </label>
          <input
            id="audit-to"
            className="control"
            type="text"
            placeholder="2026-09-01T00:00:00Z"
            value={draft.to}
            onChange={(event) => setDraft({ ...draft, to: event.target.value })}
          />
        </div>
        <div className="field">
          <label className="field__label" htmlFor="audit-policy">
            Policy
          </label>
          <input
            id="audit-policy"
            className="control"
            type="text"
            value={draft.policy}
            onChange={(event) => setDraft({ ...draft, policy: event.target.value })}
          />
        </div>
        <div className="field">
          <label className="field__label" htmlFor="audit-subject">
            Subject
          </label>
          <input
            id="audit-subject"
            className="control"
            type="text"
            value={draft.subject}
            onChange={(event) => setDraft({ ...draft, subject: event.target.value })}
          />
        </div>
        <div className="field">
          <label className="field__label" htmlFor="audit-state">
            State
          </label>
          <select
            id="audit-state"
            className="control"
            value={draft.state}
            onChange={(event) => setDraft({ ...draft, state: event.target.value })}
          >
            <option value="">All</option>
            {DECISION_STATES.map((state) => (
              <option key={state} value={state}>
                {STATE_LABELS[state] ?? state}
              </option>
            ))}
          </select>
        </div>
        <button type="submit" className="button button--primary" data-testid="audit-search">
          Search
        </button>
      </form>

      {page === null ? (
        refused ? null : <p>Reading the decision history…</p>
      ) : (
        <>
          <p role="status" data-testid="audit-applied">
            Applied query: order {page.query.order} · page size {page.query.limit}
            {page.query.from === undefined ? '' : ` · from ${page.query.from}`}
            {page.query.to === undefined ? '' : ` · until ${page.query.to}`}
            {page.query.policy === undefined ? '' : ` · policy ${page.query.policy}`}
            {page.query.subject === undefined ? '' : ` · subject ${page.query.subject}`}
            {page.query.state === undefined ? '' : ` · state ${page.query.state}`}
            {` · ${page.decisions.length} decisions`}
          </p>

          {page.decisions.length === 0 ? (
            <p data-testid="audit-empty">No decision matches the query.</p>
          ) : (
            <table className="audit-table" data-testid="audit-table">
              <caption>Decision history (newest first)</caption>
              <thead>
                <tr>
                  <th scope="col">Decision</th>
                  <th scope="col">Policy</th>
                  <th scope="col">Subject</th>
                  <th scope="col">Action</th>
                  <th scope="col">State</th>
                  <th scope="col">Created</th>
                </tr>
              </thead>
              <tbody>
                {page.decisions.map((row) => (
                  <tr key={row.id}>
                    <td>
                      <Link to={`/audit/${row.id}`}>{row.id}</Link>
                    </td>
                    <td>
                      {row.policy_id} · v{row.policy_version}
                    </td>
                    <td>{row.subject_id}</td>
                    <td>{row.action}</td>
                    <td>{STATE_LABELS[row.state] ?? row.state}</td>
                    <td>{row.created_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <div className="pager">
            <button
              type="button"
              className="button button--quiet"
              disabled={trail.length === 0}
              data-testid="audit-prev"
              onClick={() => {
                const previous = trail[trail.length - 1] ?? ''
                setTrail(trail.slice(0, -1))
                setCursor(previous)
              }}
            >
              Previous page
            </button>
            <button
              type="button"
              className="button button--quiet"
              disabled={page.next_cursor === undefined || page.next_cursor === ''}
              data-testid="audit-next"
              onClick={() => {
                setTrail([...trail, cursor])
                setCursor(page.next_cursor ?? '')
              }}
            >
              Next page
            </button>
          </div>
        </>
      )}
    </div>
  )
}

function useHistory(api: ApiClient, query: AuditQuery, cursor: string) {
  const [page, setPage] = useState<AuditDecisionListResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [refused, setRefused] = useState(false)

  useEffect(() => {
    let live = true
    void (async () => {
      try {
        const response = await api.request<AuditDecisionListResponse>('audit-decision-list', {
          query: queryParams(query, cursor),
        })
        if (!live) return
        setPage(response)
        setError(null)
        setRefused(false)
      } catch (cause) {
        if (cause instanceof ApiError && cause.isUnauthenticated) return
        if (!live) return
        setPage(null)
        // R22's refusal is its own screen, not an error string: it names a
        // standing the reader does not have and a path that still works.
        //
        // The 403 here is real and stays. It is `not_an_auditor` — standing to
        // read the collection — and the server kept it out of the collapse that
        // made "not yours" and "does not exist" one answer on the decision
        // surfaces (#38): standing to read a list says nothing about whether any
        // particular decision exists, so it is no oracle for anything.
        setRefused(cause instanceof ApiError && cause.isForbidden)
        setError(cause instanceof Error ? cause.message : String(cause))
      }
    })()
    return () => {
      live = false
    }
  }, [api, query, cursor])

  return { page, error, refused }
}
