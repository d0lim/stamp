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
  members: 'explicit list',
  claim: 'token claim',
  source: 'IdP group',
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

/** A count and its unit, pluralised, so "1 minutes" never reaches a reader. */
function units(count: number, unit: string): string {
  return `${count} ${unit}${count === 1 ? '' : 's'}`
}

/**
 * Time remaining, in words.
 *
 * It rounds down and never says "0 minutes": an approver reading "under 1
 * minute" knows they are out of time, and one reading "0 minutes" cannot tell
 * that from a bug.
 */
export function remaining(expiresAt: string, serverTime: string): string {
  const ms = Date.parse(expiresAt) - Date.parse(serverTime)
  if (Number.isNaN(ms)) return 'unknown'
  if (ms <= 0) return 'expired'
  const minutes = Math.floor(ms / 60000)
  if (minutes < 1) return 'under 1 minute'
  if (minutes < 60) return units(minutes, 'minute')
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${units(hours, 'hour')} ${units(minutes % 60, 'minute')}`
  return `${units(Math.floor(hours / 24), 'day')} ${units(hours % 24, 'hour')}`
}

export function InboxScreen() {
  const { api } = useAuth()
  const { response, error, reload } = useInbox(api)

  return (
    <div className="panel">
      <RouteAnnouncer title="Approval inbox" />
      <h1>Approval inbox</h1>
      <p>
        The pending decisions you are an approver for. The list and its filter are the server's, and
        the soonest to expire comes first.
      </p>

      {error === null ? null : (
        <p className="notice notice--warning" role="alert" data-testid="inbox-error">
          The approval inbox could not be read: {error}
        </p>
      )}

      <button type="button" className="button button--quiet" onClick={() => void reload()}>
        Read again
      </button>

      {response === null ? (
        <p>Reading the approval inbox…</p>
      ) : response.items.length === 0 ? (
        <p data-testid="inbox-empty">No decision is waiting for your approval.</p>
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
        <dt>Policy</dt>
        <dd>{item.policy_id}</dd>
        <dt>Subject</dt>
        <dd>{item.subject_id}</dd>
        <dt>Collected</dt>
        <dd data-testid={`inbox-progress-${item.decision_id}`}>
          {item.have} / {item.need} · approver resolution: {MODE_LABELS[item.mode] ?? item.mode}
        </dd>
        <dt>Time remaining</dt>
        <dd data-testid={`inbox-remaining-${item.decision_id}`}>
          {remaining(item.expires_at, serverTime)} (expires {item.expires_at})
        </dd>
        <dt>Your submission</dt>
        <dd>{item.submitted ? 'Already submitted' : 'Not submitted yet'}</dd>
      </dl>
    </li>
  )
}
