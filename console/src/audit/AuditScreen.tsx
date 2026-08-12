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
      <RouteAnnouncer title="감사" />
      <h1>감사</h1>
      <p>
        결정 이력입니다. 각 결정에서 적용된 정책 버전과 사실 스냅샷은 결정을 열어 확인합니다.
      </p>

      {refused ? (
        <div className="notice notice--warning" role="alert" data-testid="audit-refused">
          <p className="notice__text">감사 이력을 조회할 자격이 없습니다.</p>
          <p>
            감사자 자격은 운영자가 설정한 토큰 claim으로 서버가 판별합니다. 자격이 없어도 자신이
            초기화했거나 자신이 대상인 결정은 결정 식별자로 열람할 수 있습니다.
          </p>
        </div>
      ) : null}

      {error === null || refused ? null : (
        <p className="notice notice--warning" role="alert" data-testid="audit-error">
          결정 이력을 읽지 못했습니다: {error}
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
            기간 시작 (RFC 3339)
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
            기간 끝 (미포함)
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
            정책
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
            주체
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
            상태
          </label>
          <select
            id="audit-state"
            className="control"
            value={draft.state}
            onChange={(event) => setDraft({ ...draft, state: event.target.value })}
          >
            <option value="">전체</option>
            {DECISION_STATES.map((state) => (
              <option key={state} value={state}>
                {STATE_LABELS[state] ?? state}
              </option>
            ))}
          </select>
        </div>
        <button type="submit" className="button button--primary" data-testid="audit-search">
          조회
        </button>
      </form>

      {page === null ? (
        refused ? null : <p>결정 이력을 읽는 중입니다…</p>
      ) : (
        <>
          <p role="status" data-testid="audit-applied">
            적용된 조회: 정렬 {page.query.order} · 페이지 크기 {page.query.limit}
            {page.query.from === undefined ? '' : ` · ${page.query.from} 이후`}
            {page.query.to === undefined ? '' : ` · ${page.query.to} 이전`}
            {page.query.policy === undefined ? '' : ` · 정책 ${page.query.policy}`}
            {page.query.subject === undefined ? '' : ` · 주체 ${page.query.subject}`}
            {page.query.state === undefined ? '' : ` · 상태 ${page.query.state}`}
            {` · ${page.decisions.length}건`}
          </p>

          {page.decisions.length === 0 ? (
            <p data-testid="audit-empty">조회 조건에 맞는 결정이 없습니다.</p>
          ) : (
            <table className="audit-table" data-testid="audit-table">
              <caption>결정 이력 (최신순)</caption>
              <thead>
                <tr>
                  <th scope="col">결정</th>
                  <th scope="col">정책</th>
                  <th scope="col">주체</th>
                  <th scope="col">액션</th>
                  <th scope="col">상태</th>
                  <th scope="col">생성</th>
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
              이전 페이지
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
              다음 페이지
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
