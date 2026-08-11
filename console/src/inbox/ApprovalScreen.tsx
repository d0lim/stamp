/**
 * One approval: what the hash covers, what the revision changes, and the gate.
 *
 * Three rules make this screen what it is, and all three come from the same
 * place — an approval is worth something only if the approver read the thing it
 * binds to.
 *
 * The binding hash is the server's and is echoed back verbatim (R31). The
 * console never computes it, never reformats it, and shows the approver what it
 * covers *and what it does not*: the threshold and the policy version are
 * excluded on purpose, so that raising a quorum does not evaporate approvals
 * already collected, and an approver who was not told that would reasonably
 * believe they had signed for a number.
 *
 * Collapse is visual compression and not suppression (R55). Every entry stays
 * in the DOM — the `Disclosure` primitive is what guarantees that — so a screen
 * reader and find-in-page reach a collapsed policy's fields.
 *
 * The approve button is disabled until every entry has been expanded once, and
 * "expand all" satisfies that in one action. This is the rule the unit exists
 * for: an approver who approves a delta they never opened is exactly the
 * failure a quorum is there to prevent, and a UI that lets them is the hole.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ApiError, type ApiClient } from '../api/client'
import { Disclosure } from '../a11y/Disclosure'
import { RouteAnnouncer } from '../a11y/RouteAnnouncer'
import { useAuth } from '../auth/AuthProvider'
import type { Proposal } from '../builder/api-types'
import { DocumentDiff } from '../diff/FieldDiff'
import type { DecisionResult, QuorumReview } from './api-types'
import {
  materialEntries,
  policyEntries,
  revisionRefOf,
  summarize,
  type ReviewEntry,
} from './entries'

/** How often the detail re-reads while it is open. */
export const DETAIL_POLL_MS = 5000

/** What the binding hash covers, in the approver's words (R31). */
const COVERED = [
  '결정 식별 정보 (결정 ID·호출자·주체·리소스·액션)',
  '요청 (request)',
  '사실 스냅샷 (fact snapshot)',
  '의무 (obligations)',
  '승인자 집합 — 해석 방식·발급자·구성원(또는 claim·source)',
]

/** What it deliberately does not cover, and why. */
const NOT_COVERED = [
  '정족수 임계값 — 임계값만 올리는 개정에서 이미 모인 승인이 증발하지 않게 하기 위해 제외됩니다.',
  '정책 버전 식별자 — 같은 이유로 제외됩니다.',
]

/**
 * What the server says when a decision cannot be read or acted on, and it is
 * not the reader's session that is the problem.
 *
 * The server answers this on every surface that acts on one named decision, and
 * it answers the same bytes for "there is no such decision" and for "it is not
 * yours" (#38). That is deliberate: two requests with one identifier would
 * otherwise read the status code as an oracle for whether the identifier names
 * anything, which is what R40 exists to prevent.
 *
 * So this screen does not know which of the two happened, and says so. The
 * approver who was revised out of the set is the one who pays for that, and the
 * next step points them at the place where they are told the truth: a list of
 * what is waiting on you leaks nothing by leaving out what is not.
 */
const NOT_FOUND = {
  text: '이 결정을 열 수 없습니다 — 존재하지 않거나, 당신에게 열려 있지 않습니다. 서버는 이 둘을 구분해 답하지 않습니다.',
  next: '승인함 목록을 다시 읽으십시오. 승인자 집합이 개정으로 바뀌었더라도, 당신을 기다리는 결정은 그 목록에 남아 있습니다.',
} as const

/** R21's submission failures, each with its own words and its own next step. */
const FAILURES: Readonly<Record<string, { readonly text: string; readonly next: string }>> = {
  expired: {
    text: '이 결정은 만료되었습니다. 승인은 기록되지 않았습니다.',
    next: '승인함으로 돌아가십시오. 필요하다면 요청자가 결정을 다시 만들어야 합니다.',
  },
  not_collecting: {
    text: '이 challenge는 더 이상 제출을 받지 않습니다 — 이미 정족수가 충족되었거나 결정이 종결되었습니다.',
    next: '아래의 수집 현황을 확인하십시오. 추가 승인은 필요하지 않습니다.',
  },
  // Where `not_an_approver` used to be. The server no longer sends it: being
  // outside the approver set, naming a challenge that is not there, and naming
  // a decision that does not exist are one 404 with one body.
  not_found: NOT_FOUND,
  material_changed: {
    text: '표시된 이후 결정 내용이 바뀌어 승인이 거부되었습니다 — 당신이 읽은 자료에 묶인 해시가 더 이상 유효하지 않습니다.',
    next: '화면을 다시 읽고 바뀐 자료를 처음부터 검토하십시오.',
  },
}

export function ApprovalScreen() {
  const { api } = useAuth()
  const params = useParams()
  const decisionID = params.decisionId ?? ''
  const ordinal = params.ordinal ?? '0'

  const { review, error, unavailable, reload } = useReview(api, decisionID, ordinal)
  const proposal = useProposal(api, review)

  return (
    <div className="panel">
      <RouteAnnouncer title="승인 상세" />
      <h1>승인 상세</h1>
      <p>
        <Link to="/inbox">승인함으로 돌아가기</Link>
      </p>

      {unavailable ? (
        <div className="notice notice--warning" role="alert" data-testid="review-unavailable">
          <p className="notice__text">{NOT_FOUND.text}</p>
          <p>{NOT_FOUND.next}</p>
        </div>
      ) : error === null ? null : (
        <p className="notice notice--warning" role="alert" data-testid="review-error">
          승인 자료를 읽지 못했습니다: {error}
        </p>
      )}

      {review === null ? (
        unavailable ? null : <p>승인 자료를 읽는 중입니다…</p>
      ) : (
        <ReviewBody
          api={api}
          decisionID={decisionID}
          ordinal={ordinal}
          review={review}
          proposal={proposal}
          onSubmitted={reload}
        />
      )}
    </div>
  )
}

/** The review, re-read on an interval while the screen is open. */
function useReview(api: ApiClient, decisionID: string, ordinal: string) {
  const [review, setReview] = useState<QuorumReview | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Kept apart from `error` because it is not one: the read succeeded and the
  // answer was that there is nothing here for this reader. It gets the refusal
  // the server can no longer word for us, rather than "읽지 못했습니다: 대상을
  // 찾을 수 없습니다", which reads like an outage.
  const [unavailable, setUnavailable] = useState(false)

  const load = useCallback(async () => {
    try {
      setReview(
        await api.request<QuorumReview>('approval-review', {
          params: { id: decisionID, ordinal },
        }),
      )
      setError(null)
      setUnavailable(false)
    } catch (cause) {
      if (cause instanceof ApiError && cause.isUnauthenticated) return
      setUnavailable(cause instanceof ApiError && cause.isNotFound)
      setError(describe(cause))
    }
  }, [api, decisionID, ordinal])

  useEffect(() => {
    void load()
    const timer = setInterval(() => void load(), DETAIL_POLL_MS)
    return () => clearInterval(timer)
  }, [load])

  return { review, error, unavailable, reload: load }
}

/**
 * The proposal behind a governance decision, when this is one.
 *
 * The delta is fetched separately because the decision froze its *digest*, not
 * its content. The screen checks the two against each other before drawing
 * anything: a delta whose digest is not the one the hash covers is not the
 * change this approval would authorise.
 */
function useProposal(api: ApiClient, review: QuorumReview | null) {
  const [proposal, setProposal] = useState<Proposal | null>(null)
  const ref = useMemo(() => (review === null ? null : revisionRefOf(review.decision.request)), [review])

  useEffect(() => {
    if (ref === null) {
      setProposal(null)
      return
    }
    let live = true
    void (async () => {
      try {
        const fetched = await api.request<Proposal>('revision-read', { params: { id: ref.proposalID } })
        if (live) setProposal(fetched)
      } catch {
        // A proposal the approver cannot read is not an error to narrate here:
        // the material entries still render and the screen says the delta is
        // unavailable rather than pretending the change is empty.
        if (live) setProposal(null)
      }
    })()
    return () => {
      live = false
    }
  }, [api, ref])

  // Memoized because the entry list is derived from it: a fresh object every
  // render would rebuild the entries every render, and a gate keyed on entries
  // that are never the same twice is not a gate.
  return useMemo(() => {
    if (ref === null) return null
    if (proposal === null) return { ref, proposal: null, mismatch: false }
    const mismatch = ref.deltaDigest !== '' && proposal.delta_digest !== ref.deltaDigest
    return { ref, proposal, mismatch }
  }, [ref, proposal])
}

type ProposalState = ReturnType<typeof useProposal>

function ReviewBody({
  api,
  decisionID,
  ordinal,
  review,
  proposal,
  onSubmitted,
}: {
  readonly api: ApiClient
  readonly decisionID: string
  readonly ordinal: string
  readonly review: QuorumReview
  readonly proposal: ProposalState
  readonly onSubmitted: () => void
}) {
  const usableDelta = proposal !== null && proposal.proposal !== null && !proposal.mismatch
  const entries = useMemo(() => {
    const policies = usableDelta && proposal?.proposal
      ? policyEntries(proposal.proposal.delta, proposal.proposal.findings)
      : []
    return [...policies, ...materialEntries(review)]
  }, [proposal, review, usableDelta])

  const gate = useExpandGate(entries)
  const summary = summarize(entries)

  return (
    <>
      <BindingPanel review={review} />

      {proposal === null ? null : proposal.mismatch ? (
        <p className="notice notice--warning" role="alert" data-testid="digest-mismatch">
          이 결정이 고정한 delta digest와 지금 읽은 개정 제안의 digest가 다릅니다. 화면에 그려질
          변경 내용이 승인 해시가 덮는 그 변경이라고 보장할 수 없으므로 표시하지 않습니다.
        </p>
      ) : proposal.proposal === null ? (
        <p className="notice notice--warning" data-testid="proposal-unavailable">
          이 결정이 가리키는 개정 제안({proposal.ref.proposalID})을 읽지 못했습니다. 아래의 해시
          입력 자료만 표시합니다.
        </p>
      ) : null}

      <h2>검토 항목</h2>
      <p data-testid="delta-summary">
        변경된 정책 {summary.policies}건 · 완화로 분류된 항목 {summary.weakening}건 · 읽은 항목{' '}
        {gate.seen.size} / {entries.length}
      </p>
      <p className="field__hint">
        접기는 표시를 감추지 않습니다 — 접힌 항목의 내용도 화면에 남아 스크린 리더와 페이지 내
        검색에 잡힙니다. 승인 버튼은 모든 항목을 한 번씩 펼친 뒤에 열립니다.
      </p>
      <button
        type="button"
        className="button button--quiet"
        onClick={gate.expandAll}
        data-testid="expand-all"
      >
        모두 펼치기
      </button>

      <ul className="entry-list" data-testid="entry-list">
        {entries.map((entry) => (
          <li key={entry.id}>
            <Disclosure
              summary={
                <span className="entry__summary">
                  <span className="entry__title">{entry.title}</span>
                  <span className="entry__meta">{entry.meta}</span>
                  {entry.weakening ? <span className="entry__weakening">완화</span> : null}
                </span>
              }
              expanded={gate.isExpanded(entry)}
              onToggle={(next) => gate.toggle(entry.id, next)}
            >
              <EntryBody entry={entry} />
            </Disclosure>
          </li>
        ))}
      </ul>

      <SubmitPanel
        api={api}
        decisionID={decisionID}
        ordinal={ordinal}
        review={review}
        ready={gate.allSeen}
        unread={entries.length - gate.seen.size}
        onSubmitted={onSubmitted}
      />
    </>
  )
}

/**
 * The expand gate.
 *
 * The state is an *override* per entry rather than a set of open entries, and
 * the seen set is only ever added to. That shape is what makes the two rules
 * hold while the entry list is still arriving:
 *
 *   - a weakening entry is open, and read, from the moment it exists. R23 puts
 *     it open on the screen, and an entry the screen opened is an entry the
 *     approver was shown. Storing that as a default rather than as initial
 *     state means it survives the delta loading after the material did;
 *   - read is read. Collapsing something already shown does not un-show it, so
 *     the gate never closes behind an approver who tidied their screen.
 */
export function useExpandGate(entries: readonly ReviewEntry[]) {
  const [override, setOverride] = useState<ReadonlyMap<string, boolean>>(new Map())
  const [opened, setOpened] = useState<ReadonlySet<string>>(new Set())

  const isExpanded = useCallback(
    (entry: ReviewEntry) => override.get(entry.id) ?? entry.weakening,
    [override],
  )

  const seen = useMemo(() => {
    const out = new Set(opened)
    for (const entry of entries) if (entry.weakening) out.add(entry.id)
    return out
  }, [entries, opened])

  const toggle = useCallback((id: string, next: boolean) => {
    setOverride((current) => new Map(current).set(id, next))
    if (next) setOpened((current) => new Set(current).add(id))
  }, [])

  const expandAll = useCallback(() => {
    setOverride(new Map(entries.map((entry) => [entry.id, true])))
    setOpened((current) => new Set([...current, ...entries.map((entry) => entry.id)]))
  }, [entries])

  const allSeen = entries.length > 0 && entries.every((entry) => seen.has(entry.id))
  return { isExpanded, seen, toggle, expandAll, allSeen }
}

function EntryBody({ entry }: { readonly entry: ReviewEntry }) {
  if (entry.kind === 'material') {
    // Text, never markup. A fact snapshot carrying a script tag is displayed as
    // a script tag (R22's rule, and the same one applies here).
    return <pre className="document">{entry.value}</pre>
  }
  const change = entry.change
  if (change === undefined) return null
  return (
    <>
      {entry.findings === undefined || entry.findings.length === 0 ? null : (
        <ul className="trace" data-testid={`findings-${change.policy_id}`}>
          {entry.findings.map((finding, index) => (
            <li key={`${finding.reason}-${index}`}>
              <strong>완화</strong> · {finding.reason} — {finding.detail}
            </li>
          ))}
        </ul>
      )}
      {change.from_origin === undefined || change.to_origin === undefined ? null : (
        <p className="field__hint">
          소유 경로: {change.from_origin} → {change.to_origin}
        </p>
      )}
      <DocumentDiff
        idPrefix={`diff-${change.policy_id}`}
        {...(change.before === undefined ? {} : { before: change.before })}
        {...(change.after === undefined ? {} : { after: change.after })}
      />
    </>
  )
}

function BindingPanel({ review }: { readonly review: QuorumReview }) {
  return (
    <section className="binding" aria-labelledby="binding-heading">
      <h2 id="binding-heading">승인 바인딩 해시</h2>
      <p className="field__hint">
        승인은 아래 해시에 묶입니다. 서버가 내려준 값을 그대로 제출에 실어 보내므로, 지금 보고 있는
        자료가 바뀌면 제출이 거부됩니다.
      </p>
      <p className="document" data-testid="binding-hash">
        {review.binding_hash}
      </p>
      <h3>해시가 덮는 것</h3>
      <ul data-testid="binding-covered">
        {COVERED.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
      <h3>해시가 덮지 않는 것</h3>
      <ul data-testid="binding-not-covered">
        {NOT_COVERED.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
      <dl className="summary-list">
        <dt>수집 현황</dt>
        <dd data-testid="collection-progress">
          {review.have} / {review.need}
        </dd>
        <dt>만료</dt>
        <dd>{review.decision.expires_at}</dd>
      </dl>
    </section>
  )
}

function SubmitPanel({
  api,
  decisionID,
  ordinal,
  review,
  ready,
  unread,
  onSubmitted,
}: {
  readonly api: ApiClient
  readonly decisionID: string
  readonly ordinal: string
  readonly review: QuorumReview
  readonly ready: boolean
  readonly unread: number
  readonly onSubmitted: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<{ text: string; next: string } | null>(null)
  const [result, setResult] = useState<DecisionResult | null>(null)

  async function approve() {
    setBusy(true)
    setFailure(null)
    try {
      const submitted = await api.request<DecisionResult>('approval-submit', {
        params: { id: decisionID, ordinal },
        // The hash is echoed exactly as it arrived. The console does not
        // recompute it and could not: it is the server's statement about what
        // it showed.
        body: { verdict: 'approve', binding_hash: review.binding_hash },
      })
      setResult(submitted)
      onSubmitted()
    } catch (cause) {
      setFailure(failureOf(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="submit" aria-labelledby="submit-heading">
      <h2 id="submit-heading">승인</h2>
      <p id="approve-gate" className="field__hint" data-testid="approve-gate">
        {ready
          ? '모든 항목을 펼쳤습니다. 승인하면 위 해시에 묶인 자료를 검토했다는 기록이 남습니다.'
          : `아직 펼치지 않은 항목이 ${unread}건 있습니다. 모든 항목을 한 번씩 펼쳐야 승인할 수 있습니다.`}
      </p>
      <button
        type="button"
        className="button button--primary"
        onClick={() => void approve()}
        disabled={!ready || busy || result !== null}
        aria-describedby="approve-gate"
        data-testid="approve"
      >
        승인
      </button>
      <p className="field__hint" data-testid="reject-unavailable">
        거부 제출은 이 버전에서 수집하지 않습니다 — 거부가 결정을 즉시 deny로 옮기는지, 정족수
        충족 불가가 확정될 때까지 pending인지가 아직 정해지지 않았기 때문입니다. 승인하지 않으면
        이 결정은 정족수를 채우지 못한 채 만료됩니다.
      </p>

      {failure === null ? null : (
        <div className="notice notice--warning" role="alert" data-testid="submit-failure">
          <p className="notice__text">{failure.text}</p>
          <p>{failure.next}</p>
        </div>
      )}

      {result === null ? null : (
        <div className="proposal" role="status" data-testid="submit-result">
          <h3>승인이 기록되었습니다</h3>
          <dl className="summary-list">
            <dt>결정 상태</dt>
            <dd>{result.state}</dd>
            {(result.challenges ?? []).map((challenge) => (
              <div key={challenge.ordinal} className="summary-list__pair">
                <dt>challenge {challenge.ordinal}</dt>
                <dd>
                  {challenge.kind} · {challenge.state}
                  {challenge.need === undefined ? '' : ` · ${challenge.have ?? 0}/${challenge.need}`}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </section>
  )
}

/**
 * Maps a submission failure to the screen that words it.
 *
 * The 404 is matched on the status as well as on the code, because it is the
 * one failure here that the console can meet without a body it understands —
 * an identifier that never named anything answers it too.
 */
export function failureOf(cause: unknown): { text: string; next: string } {
  if (cause instanceof ApiError) {
    const body = cause.body as { error?: string; message?: string } | undefined
    const known = body?.error === undefined ? undefined : FAILURES[body.error]
    if (known) return known
    if (cause.isNotFound) return NOT_FOUND
    return {
      text: body?.message !== undefined && body.message !== '' ? body.message : cause.message,
      next: '문제가 계속되면 운영자에게 이 화면의 결정 식별자를 전달하십시오.',
    }
  }
  return { text: describe(cause), next: '네트워크 상태를 확인한 뒤 다시 시도하십시오.' }
}

function describe(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause)
}
