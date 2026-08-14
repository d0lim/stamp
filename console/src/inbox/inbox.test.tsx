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
      before: policyDocument(`policy-${index}`, 3, `before ${index}`),
      // Only policy-0 lowers its quorum, which is what makes it the weakening
      // one; every policy changes something, because a delta of twelve
      // policies where eleven are identical is not the case being tested.
      after: policyDocument(`policy-${index}`, index === 0 ? 1 : 3, `revised ${index}`),
    })),
  }
}

const WEAKENING_FINDING = {
  subject: 'policy-0',
  reason: 'quorum_lowered',
  detail: 'the quorum drops from 3 to 1',
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

describe('the approval inbox list', () => {
  it('keeps the order the server gave and computes time remaining on the server clock', async () => {
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
    expect(screen.getByTestId('inbox-remaining-soon')).toHaveTextContent('30 minutes')
    expect(screen.getByTestId('inbox-remaining-later')).toHaveTextContent('1 day 0 hours')
    expect(screen.getByTestId('inbox-progress-soon')).toHaveTextContent('1 / 2')
  })

  it('says an empty inbox is an empty list', async () => {
    renderShell({ roles: ['approver'], route: '/inbox', fetchImpl: stub().impl })
    expect(await screen.findByTestId('inbox-empty')).toBeInTheDocument()
  })

  it('never states the time remaining as 0 minutes', () => {
    expect(remaining('2026-08-10T12:00:30Z', SERVER_NOW)).toBe('under 1 minute')
    expect(remaining('2026-08-10T11:59:00Z', SERVER_NOW)).toBe('expired')
  })
})

// ---------------------------------------------------------------------------
// R55: collapse is compression, and the gate
// ---------------------------------------------------------------------------

describe('collapse and the approve gate', () => {
  it('collapses per policy and puts the weakening entry first, expanded', async () => {
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
    expect(screen.getByTestId('delta-summary')).toHaveTextContent('12 policies changed')
    expect(screen.getByTestId('delta-summary')).toHaveTextContent('1 classified as weakening')
  })

  it('leaves a collapsed entry in the DOM, reachable by screen reader and find-in-page', async () => {
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

  it('keeps the approve button disabled until every entry has been expanded', async () => {
    const user = userEvent.setup()
    renderApproval()
    await entryList(17)

    const approve = screen.getByTestId('approve')
    expect(approve).toBeDisabled()
    expect(screen.getByTestId('approve-gate')).toHaveTextContent('16 entries have not been expanded')

    // Opening one entry is not enough, and the gate says how many are left.
    await user.click(screen.getByRole('button', { name: /^policy-1\b/u }))
    expect(approve).toBeDisabled()
    expect(screen.getByTestId('approve-gate')).toHaveTextContent('15 entries')

    // A disabled button is not merely styled disabled — it cannot be pressed.
    await user.click(approve)
    expect(screen.queryByTestId('submit-result')).toBeNull()
  })

  it('opens the approve button once every entry has been expanded one at a time', async () => {
    const user = userEvent.setup()
    renderApproval()
    const list = await entryList(17)
    const approve = screen.getByTestId('approve')

    for (const trigger of within(list).getAllByRole('button')) {
      if (trigger.getAttribute('aria-expanded') === 'false') await user.click(trigger)
    }
    expect(approve).toBeEnabled()
  })

  it('opens the gate with one expand-all, and collapsing again does not close it', async () => {
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

  it('expands and collapses from the keyboard, with aria-expanded following', async () => {
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

  it('distinguishes the change kind by more than colour', async () => {
    renderApproval()
    await entryList(17)
    const fields = screen.getByTestId('diff-policy-0-fields')
    // The kind is a word — the shared diff's own label, not this screen's.
    // Greyscale, a screen reader and find-in-page all get it.
    expect(within(fields).getAllByText('Changed').length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// R31: the hash, and what it covers
// ---------------------------------------------------------------------------

describe('the approval binding hash', () => {
  it('shows the hash and its reach, and states what it does not cover', async () => {
    renderApproval()
    expect(await screen.findByTestId('binding-hash')).toHaveTextContent('f00dbabe')

    const covered = screen.getByTestId('binding-covered')
    expect(covered).toHaveTextContent('Fact snapshot')
    expect(covered).toHaveTextContent('Obligations')
    expect(covered).toHaveTextContent('Approver set')

    const notCovered = screen.getByTestId('binding-not-covered')
    expect(notCovered).toHaveTextContent('Quorum threshold')
    expect(notCovered).toHaveTextContent('Policy version')
  })

  it('displays exactly the material set the hash takes as input', async () => {
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
    for (const title of ['Request', 'Fact snapshot', 'Obligations', 'Approver set']) {
      expect(screen.getByRole('button', { name: new RegExp(`^${title}\\b`, 'u') })).toBeInTheDocument()
    }
  })

  it('submits the hash the server sent, verbatim', async () => {
    const user = userEvent.setup()
    const { calls } = renderApproval()
    await entryList(17)
    await user.click(screen.getByTestId('expand-all'))
    await user.click(screen.getByTestId('approve'))

    await waitFor(() => expect(screen.getByTestId('submit-result')).toBeInTheDocument())
    const submission = calls.find((call) => call.path.endsWith('/approvals'))
    expect(submission?.body).toEqual({ verdict: 'approve', binding_hash: 'f00dbabe' })
  })

  it('does not draw a delta whose digest is not the one the decision froze', async () => {
    renderApproval({ proposal: { status: 200, body: proposal({ delta_digest: 'deadbeef' }) } })
    expect(await screen.findByTestId('digest-mismatch')).toBeInTheDocument()
    // The material entries are still there; the delta is not.
    expect(screen.queryByTestId('diff-policy-0-fields')).toBeNull()
    expect(screen.getByTestId('delta-summary')).toHaveTextContent('0 policies changed')
  })

  it('escapes a fact snapshot carrying an HTML payload', async () => {
    const { container } = renderApproval()
    await entryList(17)
    expect(container.querySelector('script')).toBeNull()
    expect(screen.getAllByText(/<script>alert\(1\)<\/script>/).length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// R21: the submission failures
// ---------------------------------------------------------------------------

describe('submission failures', () => {
  // Status and code together, because they are what the server sends together.
  // The one that changed is the last: `403 not_an_approver` is gone, and being
  // outside the approver set now arrives as the same `404 not_found` a decision
  // that never existed answers with (#38). The old case here stubbed a code the
  // server no longer sends, and passed — a stub asserts against itself, so it
  // stayed green while the branch it exercised became dead.
  const cases: readonly (readonly [number, string, string])[] = [
    [409, 'expired', 'This decision has expired'],
    [409, 'not_collecting', 'no longer takes submissions'],
    [409, 'material_changed', 'The decision changed after it was displayed'],
    [404, 'not_found', 'it does not exist, or it is not open to you'],
  ]

  for (const [status, code, phrase] of cases) {
    it(`${code} gets its own words and its own next step`, async () => {
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

  it('does not say which of the two a 404 was, and sends the approver back to the inbox', async () => {
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
    expect(failure).toHaveTextContent('Read the approval inbox again')
    for (const forbidden of ['is not waiting on you', 'do not have permission']) {
      expect(failure).not.toHaveTextContent(forbidden)
    }
  })

  it('words a 429 rate_limited as a wait, and does not send the approver to an operator', async () => {
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
    expect(failure).toHaveTextContent('about 30 seconds')
    expect(failure).toHaveTextContent('press the approve button again')
    // And it says the approval did not land, because an approver who thinks it
    // might have walks away from a quorum still one short.
    expect(failure).toHaveTextContent('was not recorded')
    expect(failure).not.toHaveTextContent('give an operator the decision identifier')
  })

  it('invents no number when Retry-After is missing, and still says to wait', async () => {
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
    expect(failure).toHaveTextContent('Wait a moment')
    expect(failure).not.toHaveTextContent('NaN')
    expect(failure).not.toHaveTextContent('undefined')
    expect(failure).not.toHaveTextContent('give an operator the decision identifier')
  })

  it('reads a 429 with no code as a wait too — the intermediary case', async () => {
    // The two cases above both carry `rate_limited` in the body, so either half
    // of `cause.isRateLimited || body?.error === RATE_LIMITED` alone keeps them
    // green — the mutation audit removed each half in turn and neither showed
    // up (docs/testing/mutation-matrix.md). The half that matters is the status,
    // and this is the request that needs it: a 429 raised between the console
    // and the engine — an ingress limiter, a mesh sidecar, a CDN — answers with
    // a body of its own, and nothing in it is this API's error vocabulary.
    //
    // It is still a limit and it still clears on a timer, so the advice is the
    // same. Falling through to the generic branch would send the approver to an
    // operator who has nothing to do, which is the one answer that makes the
    // situation worse.
    const user = userEvent.setup()
    renderApproval({
      submit: { status: 429, body: '<html><body>429 Too Many Requests</body></html>' },
    })
    await entryList(17)
    await user.click(screen.getByTestId('expand-all'))
    await user.click(screen.getByTestId('approve'))

    const failure = await screen.findByTestId('submit-failure')
    expect(failure).toHaveTextContent('was not recorded')
    expect(failure).toHaveTextContent('press the approve button again')
    expect(failure).not.toHaveTextContent('give an operator the decision identifier')
  })

  it('leaves no previously successful review body behind when a read fails', async () => {
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
    expect(notice).toHaveTextContent('it does not exist, or it is not open to you')
    await waitFor(() => expect(screen.queryByTestId('entry-list')).toBeNull())
    expect(screen.queryByTestId('approve')).toBeNull()
    expect(screen.queryByTestId('binding-hash')).toBeNull()
    // And not the loading line either: the read finished, it just did not give
    // us anything.
    expect(screen.queryByText('Reading the approval material…')).toBeNull()
  })

  it('words an approval screen that cannot be opened as a refusal, not an error', async () => {
    // The read surface collapsed the same way the submission did, so the first
    // load of a decision that is not yours answers 404. "could not be read"
    // would read as an outage and invite a retry that cannot succeed.
    renderApproval({ review: { status: 404, body: { error: 'not_found', message: 'no such decision or challenge' } } })

    const notice = await screen.findByTestId('review-unavailable')
    expect(notice).toHaveTextContent('it does not exist, or it is not open to you')
    expect(screen.queryByTestId('review-error')).toBeNull()
    expect(screen.queryByText('Reading the approval material…')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// pure helpers
// ---------------------------------------------------------------------------

describe('the revision reference and the summary', () => {
  it('reads the proposal identifier and digest out of a governance decision request', () => {
    expect(revisionRefOf(review().decision.request)).toEqual({
      proposalID: PROPOSAL_ID,
      deltaDigest: DELTA_DIGEST,
    })
    expect(revisionRefOf({ context: { type: 'user', id: 'x' } })).toBeNull()
    expect(revisionRefOf('nonsense')).toBeNull()
  })

  it('puts weakening entries first and counts them in the summary', () => {
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
  return results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length} nodes)`)
}

describe('approval inbox accessibility', () => {
  it('has no axe violation on the list screen', async () => {
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

  it('has no axe violation on the approval detail screen, collapsed or expanded', async () => {
    const user = userEvent.setup()
    const { container } = renderApproval()
    await entryList(17)
    expect(await auditable(container)).toEqual([])

    await user.click(screen.getByTestId('expand-all'))
    expect(await auditable(container)).toEqual([])
  })
})
