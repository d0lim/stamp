/**
 * The inbox, and the rule this unit exists for.
 *
 * R55 says two things and both are tested here as behaviour rather than as
 * styling. A collapsed entry stays in the DOM, reachable by a screen reader and
 * by find-in-page. The approve button is unreachable until every entry has been
 * expanded once — because an approver who approves a delta they never opened is
 * exactly the failure a quorum exists to prevent, and the binding hash R31 puts
 * on the submission is worth nothing if the material it covers was never shown.
 *
 * The rest guards R21: the list is the server's, ordered by expiry, with time
 * remaining computed against the server's clock, and the four submission
 * failures each get their own words.
 */
import axe from 'axe-core'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { renderShell } from '../test/harness'
import { remaining } from './InboxScreen'
import { revisionRefOf, summarize, policyEntries, materialEntries } from './entries'

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

const DECISION_ID = '3f1b0f2a-0000-4000-8000-000000000001'
const PROPOSAL_ID = 'rev-1'
const DELTA_DIGEST = 'abc123'
const SERVER_NOW = '2026-08-10T12:00:00Z'

function policyDocument(id: string, threshold: number, description: string): string {
  return [
    'apiVersion: stamp/v1',
    'kind: Policy',
    `id: ${id}`,
    `description: ${description}`,
    'subject: user',
    'resource: transfer',
    'actions: [approve]',
    'challenges:',
    '  - type: quorum',
    `    threshold: ${threshold}`,
    '',
  ].join('\n')
}

/** Twelve policies, one of them weakening, which is the plan's own scenario. */
function twelvePolicyDelta() {
  return {
    changes: Array.from({ length: 12 }, (_, index) => ({
      kind: index === 0 ? ('modify' as const) : ('modify' as const),
      policy_id: `policy-${index}`,
      before: policyDocument(`policy-${index}`, 3, `이전 ${index}`),
      // Only policy-0 lowers its quorum, which is what makes it the weakening
      // one; every policy changes something, because a delta of twelve
      // policies where eleven are identical is not the case being tested.
      after: policyDocument(`policy-${index}`, index === 0 ? 1 : 3, `개정 ${index}`),
    })),
  }
}

const WEAKENING_FINDING = {
  subject: 'policy-0',
  reason: 'quorum_lowered',
  detail: '정족수가 3에서 1로 낮아집니다',
}

function review(overrides: Record<string, unknown> = {}) {
  return {
    ordinal: 0,
    state: 'pending',
    have: 1,
    need: 2,
    approvers: ['bob', 'carol'],
    mode: 'members',
    issuer: 'https://idp.test',
    binding_hash: 'f00dbabe',
    decision: {
      id: DECISION_ID,
      caller_id: 'stamp',
      subject_id: 'alice',
      resource_id: 'default',
      action: 'policy.revise',
      policy_id: 'stamp.governance',
      request: {
        action: 'policy.revise',
        subject: { type: 'admin', id: 'alice' },
        resource: { type: 'policy_set', id: 'default' },
        context: {
          type: 'revision',
          id: PROPOSAL_ID,
          attributes: { delta_digest: DELTA_DIGEST, weakening: true, change_count: 12 },
        },
      },
      fact_snapshot: { note: '<script>alert(1)</script>' },
      obligations: [],
      created_at: '2026-08-10T11:00:00Z',
      expires_at: '2026-08-10T13:00:00Z',
    },
    ...overrides,
  }
}

function proposal(overrides: Record<string, unknown> = {}) {
  return {
    id: PROPOSAL_ID,
    proposer_id: 'alice',
    delta: twelvePolicyDelta(),
    delta_digest: DELTA_DIGEST,
    application_mode: 'revaluate',
    state: 'pending',
    weakening: true,
    findings: [WEAKENING_FINDING],
    threshold: 2,
    created_at: '2026-08-10T11:00:00Z',
    ...overrides,
  }
}

interface Answer {
  readonly status: number
  readonly body: unknown
  /** Response headers beyond the JSON content type, when a case needs one. */
  readonly headers?: Readonly<Record<string, string>>
}

interface StubOptions {
  readonly inbox?: Answer
  /**
   * The review answer. An array is answered in order, with the last entry
   * repeating — which is how a screen that re-reads on an interval is given a
   * read that succeeds and then stops succeeding.
   */
  readonly review?: Answer | readonly Answer[]
  readonly proposal?: Answer
  readonly submit?: Answer
}

function stub(options: StubOptions = {}) {
  const calls: { method: string; path: string; body: unknown }[] = []
  let reviewCalls = 0
  const impl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://console.test')
    const method = init?.method ?? 'GET'
    const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined
    calls.push({ method, path: url.pathname, body })
    const answer = (result: Answer) =>
      new Response(JSON.stringify(result.body), {
        status: result.status,
        headers: { 'Content-Type': 'application/json', ...(result.headers ?? {}) },
      })

    if (url.pathname === '/decisions/inbox') {
      return answer(options.inbox ?? { status: 200, body: { items: [], server_time: SERVER_NOW } })
    }
    if (url.pathname.endsWith('/approval')) {
      const configured = options.review ?? { status: 200, body: review() }
      const index = reviewCalls++
      if (!Array.isArray(configured)) return answer(configured as Answer)
      const sequence = configured as readonly Answer[]
      return answer(sequence[Math.min(index, sequence.length - 1)] as Answer)
    }
    if (url.pathname.endsWith('/approvals')) {
      return answer(
        options.submit ?? {
          status: 200,
          body: { id: DECISION_ID, state: 'pending', reason: '', challenges: [] },
        },
      )
    }
    if (url.pathname.startsWith('/policies/revisions/')) {
      return answer(options.proposal ?? { status: 200, body: proposal() })
    }
    return answer({ status: 404, body: { error: 'not_found', message: `no stub for ${method} ${url.pathname}` } })
  })
  return { impl: impl as unknown as typeof fetch, calls }
}

function renderApproval(options: StubOptions = {}) {
  const stubbed = stub(options)
  const rendered = renderShell({
    roles: ['approver'],
    route: `/inbox/${DECISION_ID}/0`,
    fetchImpl: stubbed.impl,
  })
  return { ...rendered, calls: stubbed.calls }
}

/**
 * Waits until the delta has arrived and the entry list is complete.
 *
 * The material entries render as soon as the review does; the policy entries
 * need a second call. A gate assertion taken between the two would be asserting
 * against a list that is still growing.
 */
async function entryList(expected: number): Promise<HTMLElement> {
  const list = await screen.findByTestId('entry-list')
  await waitFor(() => expect(within(list).getAllByRole('button')).toHaveLength(expected))
  return list
}

// ---------------------------------------------------------------------------
// R21: the list
// ---------------------------------------------------------------------------

describe('승인함 목록', () => {
  it('서버가 준 순서를 그대로 쓰고 서버 시계로 잔여 시간을 계산한다', async () => {
    const items = [
      {
        decision_id: 'soon',
        ordinal: 0,
        policy_id: 'wire',
        subject_id: 'alice',
        resource_id: 'acct-1',
        action: 'transfer',
        have: 1,
        need: 2,
        mode: 'members',
        submitted: false,
        created_at: SERVER_NOW,
        expires_at: '2026-08-10T12:30:00Z',
      },
      {
        decision_id: 'later',
        ordinal: 0,
        policy_id: 'card',
        subject_id: 'bob',
        resource_id: 'acct-2',
        action: 'issue',
        have: 0,
        need: 3,
        mode: 'claim',
        submitted: true,
        created_at: SERVER_NOW,
        expires_at: '2026-08-11T12:00:00Z',
      },
    ]
    renderShell({
      roles: ['approver'],
      route: '/inbox',
      fetchImpl: stub({ inbox: { status: 200, body: { items, server_time: SERVER_NOW } } }).impl,
    })

    const list = await screen.findByTestId('inbox-list')
    const rows = within(list).getAllByRole('listitem')
    expect(rows[0]).toHaveAttribute('data-testid', 'inbox-row-soon')
    expect(rows[1]).toHaveAttribute('data-testid', 'inbox-row-later')

    // The browser's clock is not consulted: the remaining time is the gap
    // between the server's expiry and the server's own now.
    expect(screen.getByTestId('inbox-remaining-soon')).toHaveTextContent('30분')
    expect(screen.getByTestId('inbox-remaining-later')).toHaveTextContent('1일 0시간')
    expect(screen.getByTestId('inbox-progress-soon')).toHaveTextContent('1 / 2')
  })

  it('빈 승인함은 빈 목록이라고 말한다', async () => {
    renderShell({ roles: ['approver'], route: '/inbox', fetchImpl: stub().impl })
    expect(await screen.findByTestId('inbox-empty')).toBeInTheDocument()
  })

  it('잔여 시간은 0분이라고 말하지 않는다', () => {
    expect(remaining('2026-08-10T12:00:30Z', SERVER_NOW)).toBe('1분 미만')
    expect(remaining('2026-08-10T11:59:00Z', SERVER_NOW)).toBe('만료됨')
  })
})

// ---------------------------------------------------------------------------
// R55: collapse is compression, and the gate
// ---------------------------------------------------------------------------

describe('접힘과 승인 게이트', () => {
  it('정책별로 접히고 완화 항목이 펼쳐진 채 맨 위에 온다', async () => {
    renderApproval()
    const list = await entryList(17)
    const triggers = within(list).getAllByRole('button')

    // Twelve policies plus five material entries.
    expect(triggers).toHaveLength(17)
    // The weakening policy is first and is the only one that starts expanded.
    expect(triggers[0]).toHaveTextContent('policy-0')
    expect(triggers[0]).toHaveAttribute('aria-expanded', 'true')
    expect(triggers[1]).toHaveAttribute('aria-expanded', 'false')

    // Collapsed or not, the summary states the totals (R23).
    expect(screen.getByTestId('delta-summary')).toHaveTextContent('변경된 정책 12건')
    expect(screen.getByTestId('delta-summary')).toHaveTextContent('완화로 분류된 항목 1건')
  })

  it('접힌 항목의 내용이 DOM에 남아 스크린 리더와 페이지 내 검색에 잡힌다', async () => {
    renderApproval()
    await entryList(17)

    // policy-5 is collapsed: its trigger says so.
    const trigger = screen.getByRole('button', { name: /^policy-5\b/u })
    expect(trigger).toHaveAttribute('aria-expanded', 'false')

    // Its fields are still in the document, still in the accessibility tree,
    // and still findable by text. `hidden`, `display:none` and unmounting all
    // fail at least one of these three.
    const region = screen.getByTestId('diff-policy-5-fields')
    expect(region).toBeInTheDocument()
    expect(region).toBeVisible()
    expect(screen.getAllByText('challenges[0].threshold').length).toBeGreaterThan(0)
    expect(region.closest('[hidden]')).toBeNull()
    expect(region.closest('[aria-hidden="true"]')).toBeNull()
  })

  it('모든 항목을 펼치기 전에는 승인 버튼이 비활성이다', async () => {
    const user = userEvent.setup()
    renderApproval()
    await entryList(17)

    const approve = screen.getByTestId('approve')
    expect(approve).toBeDisabled()
    expect(screen.getByTestId('approve-gate')).toHaveTextContent('아직 펼치지 않은 항목이 16건')

    // Opening one entry is not enough, and the gate says how many are left.
    await user.click(screen.getByRole('button', { name: /^policy-1\b/u }))
    expect(approve).toBeDisabled()
    expect(screen.getByTestId('approve-gate')).toHaveTextContent('15건')

    // A disabled button is not merely styled disabled — it cannot be pressed.
    await user.click(approve)
    expect(screen.queryByTestId('submit-result')).toBeNull()
  })

  it('항목을 하나씩 전부 펼치면 승인 버튼이 열린다', async () => {
    const user = userEvent.setup()
    renderApproval()
    const list = await entryList(17)
    const approve = screen.getByTestId('approve')

    for (const trigger of within(list).getAllByRole('button')) {
      if (trigger.getAttribute('aria-expanded') === 'false') await user.click(trigger)
    }
    expect(approve).toBeEnabled()
  })

  it('모두 펼치기 한 번으로도 게이트가 열리고, 다시 접어도 닫히지 않는다', async () => {
    const user = userEvent.setup()
    renderApproval()
    await entryList(17)

    const approve = screen.getByTestId('approve')
    expect(approve).toBeDisabled()

    await user.click(screen.getByTestId('expand-all'))
    expect(approve).toBeEnabled()
    expect(screen.getByRole('button', { name: /^policy-5\b/u })).toHaveAttribute('aria-expanded', 'true')

    // Read is read. Collapsing something already shown does not un-show it —
    // the gate is about having been shown the material, not about the current
    // shape of the screen.
    await user.click(screen.getByRole('button', { name: /^policy-5\b/u }))
    expect(screen.getByRole('button', { name: /^policy-5\b/u })).toHaveAttribute('aria-expanded', 'false')
    expect(approve).toBeEnabled()
  })

  it('펼침·접힘이 키보드로 조작되고 aria-expanded가 따라온다', async () => {
    const user = userEvent.setup()
    renderApproval()
    await entryList(17)

    const trigger = screen.getByRole('button', { name: /^policy-1\b/u })
    trigger.focus()
    expect(trigger).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    await user.keyboard(' ')
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
  })

  it('변경 유형이 색 외 수단으로도 구분된다', async () => {
    renderApproval()
    await entryList(17)
    const fields = screen.getByTestId('diff-policy-0-fields')
    // The kind is a word. Greyscale, a screen reader and find-in-page all get it.
    expect(within(fields).getAllByText('수정').length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// R31: the hash, and what it covers
// ---------------------------------------------------------------------------

describe('승인 바인딩 해시', () => {
  it('해시와 그 범위를 보여주고, 덮지 않는 것도 명시한다', async () => {
    renderApproval()
    expect(await screen.findByTestId('binding-hash')).toHaveTextContent('f00dbabe')

    const covered = screen.getByTestId('binding-covered')
    expect(covered).toHaveTextContent('사실 스냅샷')
    expect(covered).toHaveTextContent('의무')
    expect(covered).toHaveTextContent('승인자 집합')

    const notCovered = screen.getByTestId('binding-not-covered')
    expect(notCovered).toHaveTextContent('정족수 임계값')
    expect(notCovered).toHaveTextContent('정책 버전')
  })

  it('표시된 자료 집합이 해시 입력 집합과 일치한다', async () => {
    renderApproval()
    await entryList(17)
    // One entry per hash input, and no entry that is not one.
    const material = materialEntries(review() as never).map((entry) => entry.id)
    expect(material).toEqual([
      'material:decision',
      'material:request',
      'material:facts',
      'material:obligations',
      'material:approvers',
    ])
    for (const title of ['요청 (request)', '사실 스냅샷 (fact snapshot)', '의무 (obligations)', '승인자 집합']) {
      expect(screen.getByRole('button', { name: new RegExp(title.split(' ')[0] ?? title) })).toBeInTheDocument()
    }
  })

  it('서버가 내려준 해시를 그대로 제출에 싣는다', async () => {
    const user = userEvent.setup()
    const { calls } = renderApproval()
    await entryList(17)
    await user.click(screen.getByTestId('expand-all'))
    await user.click(screen.getByTestId('approve'))

    await waitFor(() => expect(screen.getByTestId('submit-result')).toBeInTheDocument())
    const submission = calls.find((call) => call.path.endsWith('/approvals'))
    expect(submission?.body).toEqual({ verdict: 'approve', binding_hash: 'f00dbabe' })
  })

  it('결정이 고정한 digest와 다른 delta는 그리지 않는다', async () => {
    renderApproval({ proposal: { status: 200, body: proposal({ delta_digest: 'deadbeef' }) } })
    expect(await screen.findByTestId('digest-mismatch')).toBeInTheDocument()
    // The material entries are still there; the delta is not.
    expect(screen.queryByTestId('diff-policy-0-fields')).toBeNull()
    expect(screen.getByTestId('delta-summary')).toHaveTextContent('변경된 정책 0건')
  })

  it('HTML 페이로드가 담긴 사실 스냅샷을 이스케이프해 표시한다', async () => {
    const { container } = renderApproval()
    await entryList(17)
    expect(container.querySelector('script')).toBeNull()
    expect(screen.getAllByText(/<script>alert\(1\)<\/script>/).length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// R21: the submission failures
// ---------------------------------------------------------------------------

describe('제출 실패', () => {
  // Status and code together, because they are what the server sends together.
  // The one that changed is the last: `403 not_an_approver` is gone, and being
  // outside the approver set now arrives as the same `404 not_found` a decision
  // that never existed answers with (#38). The old case here stubbed a code the
  // server no longer sends, and passed — a stub asserts against itself, so it
  // stayed green while the branch it exercised became dead.
  const cases: readonly (readonly [number, string, string])[] = [
    [409, 'expired', '만료되었습니다'],
    [409, 'not_collecting', '더 이상 제출을 받지 않습니다'],
    [409, 'material_changed', '결정 내용이 바뀌어'],
    [404, 'not_found', '존재하지 않거나, 당신에게 열려 있지 않습니다'],
  ]

  for (const [status, code, phrase] of cases) {
    it(`${code}는 전용 문구와 후속 동작을 보여준다`, async () => {
      const user = userEvent.setup()
      renderApproval({ submit: { status, body: { error: code, message: 'server wording' } } })
      await entryList(17)
      await user.click(screen.getByTestId('expand-all'))
      await user.click(screen.getByTestId('approve'))

      const failure = await screen.findByTestId('submit-failure')
      expect(failure).toHaveTextContent(phrase)
      // Every one of them names a next step; a refusal with no next step is a
      // dead end an approver cannot act on.
      expect(failure.querySelectorAll('p')).toHaveLength(2)
    })
  }

  it('404는 없는 결정인지 남의 결정인지 말하지 않고, 승인함으로 돌려보낸다', async () => {
    // The server made the two indistinguishable on purpose, so the console must
    // not word one of them. What it can do is point at the surface that still
    // tells the truth: the inbox lists what is waiting on you, and omitting what
    // is not leaks nothing.
    const user = userEvent.setup()
    renderApproval({ submit: { status: 404, body: { error: 'not_found', message: 'no such decision or challenge' } } })
    await entryList(17)
    await user.click(screen.getByTestId('expand-all'))
    await user.click(screen.getByTestId('approve'))

    const failure = await screen.findByTestId('submit-failure')
    expect(failure).toHaveTextContent('승인함 목록을 다시 읽으십시오')
    for (const forbidden of ['기다리고 있지 않습니다', '권한이 없습니다']) {
      expect(failure).not.toHaveTextContent(forbidden)
    }
  })

  it('429 rate_limited는 기다리라고 말하지, 운영자에게 가라고 하지 않는다', async () => {
    // The budget refills on a timer (R43). Sending the approver to an operator
    // — which is what the generic branch does — is the one piece of advice that
    // makes the situation worse: the operator has nothing to do, and the
    // approver stops doing the thing that works. The server states the wait in
    // `Retry-After` for exactly this rendering.
    const user = userEvent.setup()
    renderApproval({
      submit: {
        status: 429,
        body: { error: 'rate_limited', message: 'too many submissions; try again shortly' },
        headers: { 'Retry-After': '30' },
      },
    })
    await entryList(17)
    await user.click(screen.getByTestId('expand-all'))
    await user.click(screen.getByTestId('approve'))

    const failure = await screen.findByTestId('submit-failure')
    expect(failure).toHaveTextContent('30초')
    expect(failure).toHaveTextContent('다시 누르십시오')
    // And it says the approval did not land, because an approver who thinks it
    // might have walks away from a quorum still one short.
    expect(failure).toHaveTextContent('기록되지 않았습니다')
    expect(failure).not.toHaveTextContent('운영자에게 이 화면의 결정 식별자를 전달')
  })

  it('Retry-After가 없으면 숫자를 지어내지 않고 그래도 기다리라고 말한다', async () => {
    // The header can be absent for reasons that are not about this deployment's
    // budget — a cross-origin response that does not expose it, a proxy that
    // dropped it. The advice is unchanged; only the number goes.
    const user = userEvent.setup()
    renderApproval({
      submit: { status: 429, body: { error: 'rate_limited', message: 'too many submissions' } },
    })
    await entryList(17)
    await user.click(screen.getByTestId('expand-all'))
    await user.click(screen.getByTestId('approve'))

    const failure = await screen.findByTestId('submit-failure')
    expect(failure).toHaveTextContent('잠시 기다린 뒤')
    expect(failure).not.toHaveTextContent('NaN')
    expect(failure).not.toHaveTextContent('undefined')
    expect(failure).not.toHaveTextContent('운영자에게 이 화면의 결정 식별자를 전달')
  })

  it('읽기가 실패하면 직전에 성공한 검토 화면은 남지 않는다', async () => {
    // This screen re-reads while it is open, so a read that stops working has a
    // previous one to leave behind. Left behind, the "cannot be opened" notice
    // renders on top of a full review body with a live approve button under it:
    // material the server has just refused to stand behind, next to the control
    // that would submit against it. AuditDecisionScreen clears its body on the
    // same failure; this asserts they agree.
    //
    // The second read is driven by the reload a successful submission triggers
    // rather than by the poll timer, because it is the same function — useReview
    // hands `load` out as `reload` — and a test that waits five seconds for a
    // timer is a test that eventually gets deleted for being slow.
    const user = userEvent.setup()
    renderApproval({
      review: [
        { status: 200, body: review() },
        { status: 404, body: { error: 'not_found', message: 'no such decision or challenge' } },
      ],
    })
    await entryList(17)
    await user.click(screen.getByTestId('expand-all'))
    await user.click(screen.getByTestId('approve'))

    const notice = await screen.findByTestId('review-unavailable')
    expect(notice).toHaveTextContent('존재하지 않거나, 당신에게 열려 있지 않습니다')
    await waitFor(() => expect(screen.queryByTestId('entry-list')).toBeNull())
    expect(screen.queryByTestId('approve')).toBeNull()
    expect(screen.queryByTestId('binding-hash')).toBeNull()
    // And not the loading line either: the read finished, it just did not give
    // us anything.
    expect(screen.queryByText('승인 자료를 읽는 중입니다…')).toBeNull()
  })

  it('열 수 없는 승인 화면은 오류가 아니라 거부로 말한다', async () => {
    // The read surface collapsed the same way the submission did, so the first
    // load of a decision that is not yours answers 404. "읽지 못했습니다" would
    // read as an outage and invite a retry that cannot succeed.
    renderApproval({ review: { status: 404, body: { error: 'not_found', message: 'no such decision or challenge' } } })

    const notice = await screen.findByTestId('review-unavailable')
    expect(notice).toHaveTextContent('존재하지 않거나, 당신에게 열려 있지 않습니다')
    expect(screen.queryByTestId('review-error')).toBeNull()
    expect(screen.queryByText('승인 자료를 읽는 중입니다…')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// pure helpers
// ---------------------------------------------------------------------------

describe('개정 참조와 요약', () => {
  it('거버넌스 결정의 요청에서 제안 식별자와 digest를 읽는다', () => {
    expect(revisionRefOf(review().decision.request)).toEqual({
      proposalID: PROPOSAL_ID,
      deltaDigest: DELTA_DIGEST,
    })
    expect(revisionRefOf({ context: { type: 'user', id: 'x' } })).toBeNull()
    expect(revisionRefOf('nonsense')).toBeNull()
  })

  it('완화 항목이 앞에 오고 요약이 건수를 센다', () => {
    const entries = policyEntries(twelvePolicyDelta(), [WEAKENING_FINDING])
    expect(entries[0]?.id).toBe('policy:policy-0')
    expect(entries[0]?.weakening).toBe(true)
    expect(summarize(entries)).toEqual({ policies: 12, weakening: 1 })
  })
})

// ---------------------------------------------------------------------------
// R55: the accessibility bar is the builder's
// ---------------------------------------------------------------------------

async function auditable(container: HTMLElement): Promise<string[]> {
  const results = await axe.run(container, {
    // jsdom computes no colours. Contrast is checked in the Playwright pass,
    // which runs a real browser, and stated with ratios in the stylesheets.
    rules: { 'color-contrast': { enabled: false } },
  })
  return results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length}곳)`)
}

describe('승인함 접근성', () => {
  it('목록 화면에 axe 위반이 없다', async () => {
    const { container } = renderShell({
      roles: ['approver'],
      route: '/inbox',
      fetchImpl: stub({
        inbox: {
          status: 200,
          body: {
            items: [
              {
                decision_id: 'soon',
                ordinal: 0,
                policy_id: 'wire',
                subject_id: 'alice',
                resource_id: 'acct-1',
                action: 'transfer',
                have: 1,
                need: 2,
                mode: 'members',
                submitted: false,
                created_at: SERVER_NOW,
                expires_at: '2026-08-10T12:30:00Z',
              },
            ],
            server_time: SERVER_NOW,
          },
        },
      }).impl,
    })
    await screen.findByTestId('inbox-list')
    expect(await auditable(container)).toEqual([])
  })

  it('승인 상세 화면에 axe 위반이 없다 — 접힌 상태와 펼친 상태 모두', async () => {
    const user = userEvent.setup()
    const { container } = renderApproval()
    await entryList(17)
    expect(await auditable(container)).toEqual([])

    await user.click(screen.getByTestId('expand-all'))
    expect(await auditable(container)).toEqual([])
  })
})
