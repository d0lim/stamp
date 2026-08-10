/**
 * The approver's list: what is waiting on them, soonest first.
 *
 * The "waiting on me" filter is the server's (R21) and this screen does not
 * re-apply it. That is not laziness — a list the console narrowed would be a
 * display convention, and the moment it disagreed with the submission rule an
 * approver would either be shown a decision they cannot act on or be hidden
 * from one they must.
 *
 * Time remaining is computed against the clock the server sent, not the
 * browser's. An approver whose machine is an hour fast would otherwise be told
 * a live decision had expired, and would stop trying.
 *
 * Refresh is on window focus, which is the shape of the task: an approver
 * leaves the tab to go and check something, and comes back. Polling a list
 * nobody is looking at costs a query per approver per interval for an answer
 * that changes a few times a day.
 */
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, type ApiClient } from '../api/client'
import { RouteAnnouncer } from '../a11y/RouteAnnouncer'
import { useAuth } from '../auth/AuthProvider'
import type { InboxItem, InboxResponse } from './api-types'

const MODE_LABELS: Readonly<Record<string, string>> = {
  members: '명시 목록',
  claim: '토큰 claim',
  source: 'IdP 그룹',
}

/** The list, plus the instant the server took it at. */
export function useInbox(api: ApiClient) {
  const [response, setResponse] = useState<InboxResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setResponse(await api.request<InboxResponse>('inbox-list'))
      setError(null)
    } catch (cause) {
      // A 401 is the shell's to handle: it owns the session and the re-login.
      if (cause instanceof ApiError && cause.isUnauthenticated) return
      setError(cause instanceof Error ? cause.message : String(cause))
    }
  }, [api])

  useEffect(() => {
    void load()
    const onFocus = () => void load()
    window.addEventListener('focus', onFocus)
    return () => window.removeEventListener('focus', onFocus)
  }, [load])

  return { response, error, reload: load }
}

/**
 * Time remaining, in words.
 *
 * It rounds down and never says "0분": an approver reading "1분 미만" knows they
 * are out of time, and one reading "0분" cannot tell that from a bug.
 */
export function remaining(expiresAt: string, serverTime: string): string {
  const ms = Date.parse(expiresAt) - Date.parse(serverTime)
  if (Number.isNaN(ms)) return '알 수 없음'
  if (ms <= 0) return '만료됨'
  const minutes = Math.floor(ms / 60000)
  if (minutes < 1) return '1분 미만'
  if (minutes < 60) return `${minutes}분`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}시간 ${minutes % 60}분`
  return `${Math.floor(hours / 24)}일 ${hours % 24}시간`
}

export function InboxScreen() {
  const { api } = useAuth()
  const { response, error, reload } = useInbox(api)

  return (
    <div className="panel">
      <RouteAnnouncer title="승인함" />
      <h1>승인함</h1>
      <p>
        내가 승인 대상인 미결 결정입니다. 목록과 필터는 서버가 결정하며, 만료가 임박한 순서로
        정렬됩니다.
      </p>

      {error === null ? null : (
        <p className="notice notice--warning" role="alert" data-testid="inbox-error">
          승인함을 읽지 못했습니다: {error}
        </p>
      )}

      <button type="button" className="button button--quiet" onClick={() => void reload()}>
        다시 읽기
      </button>

      {response === null ? (
        <p>승인함을 읽는 중입니다…</p>
      ) : response.items.length === 0 ? (
        <p data-testid="inbox-empty">지금 승인을 기다리는 결정이 없습니다.</p>
      ) : (
        <ul className="inbox-list" data-testid="inbox-list">
          {response.items.map((item) => (
            <InboxRow key={`${item.decision_id}:${item.ordinal}`} item={item} serverTime={response.server_time} />
          ))}
        </ul>
      )}
    </div>
  )
}

function InboxRow({ item, serverTime }: { readonly item: InboxItem; readonly serverTime: string }) {
  return (
    <li className="inbox-row" data-testid={`inbox-row-${item.decision_id}`}>
      <h2 className="inbox-row__title">
        <Link to={`/inbox/${item.decision_id}/${item.ordinal}`}>
          {item.action} · {item.resource_id}
        </Link>
      </h2>
      <dl className="summary-list">
        <dt>정책</dt>
        <dd>{item.policy_id}</dd>
        <dt>대상</dt>
        <dd>{item.subject_id}</dd>
        <dt>수집 현황</dt>
        <dd data-testid={`inbox-progress-${item.decision_id}`}>
          {item.have} / {item.need} · 승인자 해석: {MODE_LABELS[item.mode] ?? item.mode}
        </dd>
        <dt>남은 시간</dt>
        <dd data-testid={`inbox-remaining-${item.decision_id}`}>
          {remaining(item.expires_at, serverTime)} (만료 {item.expires_at})
        </dd>
        <dt>내 제출</dt>
        <dd>{item.submitted ? '이미 제출했습니다' : '아직 제출하지 않았습니다'}</dd>
      </dl>
    </li>
  )
}
