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
  if (value === undefined || value === null) return '(없음)'
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
      <RouteAnnouncer title="결정 상세" />
      <h1>결정 상세</h1>
      <p>
        <Link to="/audit">감사 목록으로 돌아가기</Link>
      </p>

      {unavailable ? (
        <div className="notice notice--warning" role="alert" data-testid="decision-unavailable">
          <p className="notice__text">
            이 결정을 열람할 수 없습니다 — 존재하지 않거나, 당신에게 열려 있지 않습니다. 서버는 이
            둘을 구분해 답하지 않습니다.
          </p>
          <p>
            감사자 자격이 없는 경우 자신이 초기화했거나 자신이 대상인 결정만 열람할 수 있습니다.
            결정 식별자를 다시 확인하십시오.
          </p>
        </div>
      ) : error === null ? null : (
        <p className="notice notice--warning" role="alert" data-testid="decision-error">
          결정을 읽지 못했습니다: {error}
        </p>
      )}

      {detail === null ? (
        unavailable ? null : <p>결정을 읽는 중입니다…</p>
      ) : (
        <>
          <dl className="summary-list">
            <dt>결정</dt>
            <dd>{detail.id}</dd>
            <dt>상태</dt>
            <dd>{STATE_LABELS[detail.state] ?? detail.state}</dd>
            <dt>호출자</dt>
            <dd>{detail.caller_id}</dd>
            <dt>주체 · 리소스 · 액션</dt>
            <dd>
              {detail.subject_id} · {detail.resource_id} · {detail.action}
            </dd>
            <dt>적용된 정책 버전</dt>
            <dd data-testid="policy-version">
              {detail.policy_id} · v{detail.policy_version}
              {detail.policy_origin === '' ? '' : ` · ${detail.policy_origin}`}
            </dd>
            <dt>생성 · 만료</dt>
            <dd>
              {detail.created_at} · {detail.expires_at}
            </dd>
            {detail.resolved_at === undefined ? null : (
              <>
                <dt>종결</dt>
                <dd>{detail.resolved_at}</dd>
              </>
            )}
          </dl>

          {detail.via_auditor_standing ? null : (
            <p className="field__hint" data-testid="own-record-notice">
              감사자 자격이 아니라 “자신이 초기화했거나 대상인 결정” 규칙으로 열람하고 있습니다.
            </p>
          )}

          <h2>고정된 자료</h2>
          <Disclosure summary="요청 (request)">
            <pre className="document" data-testid="audit-request">
              {asText(detail.request)}
            </pre>
          </Disclosure>
          <Disclosure summary="사실 스냅샷 (fact snapshot)">
            <pre className="document" data-testid="audit-facts">
              {asText(detail.fact_snapshot)}
            </pre>
          </Disclosure>
          <Disclosure summary="의무 (obligations)">
            <pre className="document" data-testid="audit-obligations">
              {asText(detail.obligations)}
            </pre>
          </Disclosure>
          <Disclosure summary={`정책 문서 (v${detail.policy_version} 시점)`}>
            <pre className="document" data-testid="audit-policy-document">
              {detail.policy_document === '' ? '이 버전의 정책 문서를 읽지 못했습니다.' : detail.policy_document}
            </pre>
          </Disclosure>

          <h2>challenge</h2>
          {detail.challenges.length === 0 ? (
            <p>이 결정에는 challenge가 없습니다.</p>
          ) : (
            <table className="audit-table" data-testid="audit-challenges">
              <caption>challenge 진행</caption>
              <thead>
                <tr>
                  <th scope="col">순번</th>
                  <th scope="col">종류</th>
                  <th scope="col">상태</th>
                  <th scope="col">기한</th>
                  <th scope="col">충족</th>
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

          <h2>승인</h2>
          {detail.approvals.length === 0 ? (
            <p data-testid="audit-approvals-empty">기록된 승인이 없습니다.</p>
          ) : (
            <table className="audit-table" data-testid="audit-approvals">
              <caption>수집된 승인과 그 바인딩 해시</caption>
              <thead>
                <tr>
                  <th scope="col">challenge</th>
                  <th scope="col">승인자</th>
                  <th scope="col">판정</th>
                  <th scope="col">바인딩 해시</th>
                  <th scope="col">제출</th>
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
