/**
 * What an author needs to know before they start, not after they finish.
 *
 * U9 admits one open revision at a time. A builder that discovered this at
 * submission would let somebody fill four steps of a form and then refuse it,
 * so the check happens on entry to authoring and the answer stays on screen as a
 * banner for the whole session. If a proposal appears while the form is being
 * filled, submission raises the same banner rather than a generic error — one
 * fact, one place, whichever moment it arrives in.
 *
 * The banner also carries the withdrawal action for a proposal this person
 * opened, because "another revision is open" is only actionable if the person
 * who opened it can close it.
 *
 * The unlocked warning is R41's and is deliberately unconditional: an
 * installation whose governance is not locked yet has no quorum standing between
 * an author and the effective policy set, and that is a standing condition
 * rather than an event.
 */
import { useCallback, useEffect, useState } from 'react'
import { ApiError, type ApiClient } from '../api/client'
import { Disclosure } from '../a11y/Disclosure'
import type { GovernanceView, Proposal } from './api-types'

export interface GovernanceState {
  readonly view: GovernanceView | null
  readonly error: string | null
  readonly reload: () => void
}

/** Reads the governance mode and any open revision. */
export function useGovernance(api: ApiClient): GovernanceState {
  const [view, setView] = useState<GovernanceView | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    let live = true
    void (async () => {
      try {
        const next = await api.request<GovernanceView>('governance-read')
        if (live) {
          setView(next)
          setError(null)
        }
      } catch (cause) {
        // A 401 is the shell's business, not this screen's — it drops the
        // session and raises its own notice, so re-reporting it here would put
        // two explanations of the same thing on the page.
        if (cause instanceof ApiError && cause.isUnauthenticated) return
        if (live) setError(cause instanceof Error ? cause.message : String(cause))
      }
    })()
    return () => {
      live = false
    }
  }, [api, tick])

  const reload = useCallback(() => setTick((value) => value + 1), [])
  return { view, error, reload }
}

function changedPolicies(proposal: Proposal): readonly string[] {
  return proposal.delta.changes.map((change) => `${change.policy_id} (${change.kind})`)
}

export function GovernanceBanner({
  api,
  state,
  subjectId,
}: {
  readonly api: ApiClient
  readonly state: GovernanceState
  /** The `sub` of the signed-in token, which is what a proposal records. */
  readonly subjectId: string | null
}) {
  const [withdrawing, setWithdrawing] = useState(false)
  const [withdrawError, setWithdrawError] = useState<string | null>(null)
  const view = state.view
  const pending = view?.pending_revision ?? null

  async function withdraw(id: string) {
    setWithdrawing(true)
    setWithdrawError(null)
    try {
      await api.request<Proposal>('revision-withdraw', { params: { id } })
      state.reload()
    } catch (cause) {
      setWithdrawError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setWithdrawing(false)
    }
  }

  return (
    <>
      {state.error === null ? null : (
        <p className="notice notice--warning" data-testid="governance-error">
          거버넌스 상태를 읽지 못했습니다: {state.error}
        </p>
      )}

      {view?.mode === 'solo_admin' ? (
        <p className="notice notice--warning" data-testid="unlocked-warning">
          이 설치는 거버넌스가 잠기지 않았습니다. 개정이 정족수 없이 발효됩니다.
        </p>
      ) : null}

      {pending === null ? null : (
        <div className="notice notice--warning" data-testid="pending-revision-banner">
          <div>
            <p className="notice__text">
              이미 열려 있는 개정 제안이 있습니다 — 승인자는 한 번에 하나의 diff만 봅니다. 이 제안이
              끝나기 전에는 새 개정을 제출할 수 없습니다.
            </p>
            <Disclosure summary={`제안 ${pending.id} · 승인 ${pending.threshold}명 필요`}>
              <dl className="summary-list">
                <dt>제안자</dt>
                <dd>{pending.proposer_id}</dd>
                <dt>상태</dt>
                <dd>{pending.state}</dd>
                <dt>변경 대상</dt>
                <dd>{changedPolicies(pending).join(', ')}</dd>
                <dt>델타 다이제스트</dt>
                <dd>
                  <code>{pending.delta_digest}</code>
                </dd>
              </dl>
            </Disclosure>
            {withdrawError === null ? null : (
              <p className="notice__text" role="alert">
                {withdrawError}
              </p>
            )}
          </div>
          {subjectId !== null && subjectId === pending.proposer_id ? (
            <button
              type="button"
              className="button"
              disabled={withdrawing}
              onClick={() => withdraw(pending.id)}
              data-testid="withdraw-revision"
            >
              내 제안 철회
            </button>
          ) : (
            <p className="notice__text">이 제안은 다른 사람이 올렸습니다. 철회는 제안자만 할 수 있습니다.</p>
          )}
        </div>
      )}
    </>
  )
}
