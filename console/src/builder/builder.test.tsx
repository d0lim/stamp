/**
 * The builder's behaviour, stated as the three things this unit has to be true
 * about.
 *
 * A diagnostic's JSON Pointer lands on the field that caused it. The form cannot
 * express a condition the AST cannot hold. An author is told, before submitting,
 * that a post-lock revision needs a quorum.
 *
 * Everything else here supports one of those three or guards the accessibility
 * the Verification Contract runs axe against.
 */
import axe from 'axe-core'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { renderShell } from '../test/harness'
import { NODE_KINDS, OPERAND_KINDS } from './model'

// ---------------------------------------------------------------------------
// a fetch that answers the authoring endpoints
// ---------------------------------------------------------------------------

interface Call {
  readonly method: string
  readonly path: string
  readonly body: unknown
}

interface StubOptions {
  readonly governance?: unknown
  readonly policies?: unknown
  readonly dryRun?: { readonly status: number; readonly body: unknown }
  readonly preview?: { readonly status: number; readonly body: unknown }
  readonly submit?: { readonly status: number; readonly body: unknown }
  readonly withdraw?: { readonly status: number; readonly body: unknown }
}

function stub(options: StubOptions = {}) {
  const calls: Call[] = []
  const impl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://console.test')
    const path = url.pathname
    const method = init?.method ?? 'GET'
    const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined
    calls.push({ method, path, body })

    const answer = (status: number, payload: unknown) =>
      new Response(JSON.stringify(payload), {
        status,
        headers: { 'Content-Type': 'application/json' },
      })

    if (path === '/governance') return answer(200, options.governance ?? { mode: 'quorum' })
    if (path === '/policies' && method === 'GET') {
      return answer(200, options.policies ?? { policies: [] })
    }
    if (path === '/console/v1/policies/dry-run') {
      const result = options.dryRun ?? { status: 200, body: EMPTY_DRY_RUN }
      return answer(result.status, result.body)
    }
    if (path === '/policies/revisions/preview') {
      const result = options.preview ?? { status: 200, body: QUORUM_PREVIEW }
      return answer(result.status, result.body)
    }
    if (path === '/policies/revisions' && method === 'POST') {
      const result = options.submit ?? { status: 202, body: PROPOSAL }
      return answer(result.status, result.body)
    }
    if (path.endsWith('/withdrawal')) {
      const result = options.withdraw ?? { status: 200, body: PROPOSAL }
      return answer(result.status, result.body)
    }
    return answer(404, { error: 'not_found', message: `no stub for ${method} ${path}` })
  })
  return { impl: impl as unknown as typeof fetch, calls }
}

const EMPTY_DRY_RUN = {
  policy_id: 'p1',
  matched: true,
  holds: true,
  decision: 'allow',
  reason: '',
  conditions: [{ pointer: '/condition', kind: 'all', result: true }],
  challenges: [],
  stored: false,
}

const QUORUM_PREVIEW = {
  mode: 'quorum',
  weakening: false,
  findings: [],
  threshold: 3,
  approvers: ['alice', 'bob', 'carol'],
  exclude_proposer: true,
  affected_decisions: 4,
}

const PROPOSAL = {
  id: 'rev-1',
  proposer_id: 'u-1',
  delta: { changes: [{ kind: 'add', policy_id: 'p1', after: '' }] },
  delta_digest: 'abc',
  application_mode: 'revaluate',
  state: 'pending',
  weakening: false,
  findings: [],
  threshold: 3,
  created_at: '2026-08-10T00:00:00Z',
}

async function auditable(container: HTMLElement): Promise<string[]> {
  const results = await axe.run(container, {
    // jsdom computes no colours; contrast is settled in the stylesheets, where
    // every token pair is written down with its ratio.
    rules: { 'color-contrast': { enabled: false } },
  })
  return results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length} nodes)`)
}

async function openBuilder(options: StubOptions = {}) {
  const stubbed = stub(options)
  const rendered = renderShell({
    roles: ['author'],
    route: '/policies/new',
    fetchImpl: stubbed.impl,
  })
  await screen.findByRole('heading', { level: 1, name: 'Policy authoring' })
  return { ...rendered, calls: stubbed.calls }
}

/** Moves to a step by its button, the way a keyboard user would. */
async function goToStep(name: RegExp) {
  await userEvent.click(await screen.findByRole('button', { name }))
}

/** The minimum an author declares before a rule can be written. */
async function declareEntity(name: string, attribute: string) {
  await goToStep(/^1\. Declarations$/)
  await userEvent.click(screen.getByRole('button', { name: 'Add entity declaration' }))
  await userEvent.type(screen.getByLabelText('Name'), name)
  await userEvent.click(screen.getByRole('button', { name: 'Add attribute' }))
  await userEvent.type(screen.getByLabelText('Attribute 1 name'), attribute)
}

// ---------------------------------------------------------------------------
// (a) a diagnostic lands on the field that caused it
// ---------------------------------------------------------------------------

describe('a diagnostic attaches to the field that caused it', () => {
  it('ties a challenge threshold diagnostic to the threshold input and points the summary at it', async () => {
    await openBuilder({
      dryRun: {
        status: 400,
        body: {
          error: 'invalid_policy',
          diagnostics: [
            {
              pointer: '/policies/0/challenges/0/threshold',
              code: 'invalid_value',
              message: 'quorum threshold must be at least 1',
            },
          ],
        },
      },
    })

    await goToStep(/^5\. challenge$/)
    await userEvent.click(screen.getByRole('button', { name: 'Add quorum approval (quorum)' }))
    await goToStep(/^6\. Dry run$/)
    await userEvent.click(screen.getByRole('button', { name: 'Run dry run' }))

    // The flow moved to the step that owns the pointer, because an anchor into
    // a step that is not rendered is an anchor to nothing.
    const threshold = await screen.findByLabelText('Quorum')
    expect(threshold.id).toBe('bf.policies.0.challenges.0.threshold')
    expect(threshold).toHaveAttribute('aria-invalid', 'true')
    expect(threshold).toHaveAccessibleDescription(/quorum threshold must be at least 1/)

    const summary = screen.getByTestId('error-summary')
    const link = within(summary).getByRole('link', { name: /quorum threshold must be at least 1/ })
    expect(link).toHaveAttribute('href', '#bf.policies.0.challenges.0.threshold')
    expect(document.getElementById('bf.policies.0.challenges.0.threshold')).toBe(threshold)
  })

  it('attaches an approver-list diagnostic to that approver input', async () => {
    await openBuilder({
      dryRun: {
        status: 400,
        body: {
          error: 'invalid_policy',
          diagnostics: [
            {
              pointer: '/policies/0/challenges/0/approvers/members/0',
              code: 'invalid_value',
              message: 'an approver may not be empty',
            },
          ],
        },
      },
    })

    await goToStep(/^5\. challenge$/)
    await userEvent.click(screen.getByRole('button', { name: 'Add quorum approval (quorum)' }))
    await goToStep(/^6\. Dry run$/)
    await userEvent.click(screen.getByRole('button', { name: 'Run dry run' }))

    const member = await screen.findByLabelText('Approver 1')
    expect(member).toHaveAccessibleDescription(/an approver may not be empty/)
  })

  it('climbs a pointer the form does not render to the nearest ancestor field', async () => {
    await openBuilder({
      dryRun: {
        status: 400,
        body: {
          error: 'invalid_policy',
          diagnostics: [
            {
              // The validator reports the rule itself, which has no input of
              // its own — the row it names does.
              pointer: '/policies/0/challenges/0/approvers/members/0/nowhere',
              code: 'invalid_value',
              message: 'a diagnostic that has to climb to an ancestor',
            },
          ],
        },
      },
    })

    await goToStep(/^5\. challenge$/)
    await userEvent.click(screen.getByRole('button', { name: 'Add quorum approval (quorum)' }))
    await goToStep(/^6\. Dry run$/)
    await userEvent.click(screen.getByRole('button', { name: 'Run dry run' }))

    const member = await screen.findByLabelText('Approver 1')
    expect(member).toHaveAccessibleDescription(/a diagnostic that has to climb to an ancestor/)
  })

  it('shows a diagnostic no field owns at document level rather than dropping it', async () => {
    await openBuilder({
      dryRun: {
        status: 400,
        body: {
          error: 'invalid_policy',
          diagnostics: [
            { pointer: '', code: 'invalid_yaml', message: 'the document could not be read' },
          ],
        },
      },
    })

    await goToStep(/^6\. Dry run$/)
    await userEvent.click(screen.getByRole('button', { name: 'Run dry run' }))

    const summary = await screen.findByTestId('error-summary')
    const link = within(summary).getByRole('link', { name: /the document could not be read/ })
    expect(link).toHaveAttribute('href', '#bf-unplaced')
    expect(document.getElementById('bf-unplaced')).toHaveTextContent(
      'the document could not be read',
    )
  })
})

// ---------------------------------------------------------------------------
// (b) the form cannot express what the AST cannot hold
// ---------------------------------------------------------------------------

describe('the form cannot express a condition the AST cannot hold', () => {
  it('offers exactly the node kinds the AST has in the rule palette', async () => {
    await openBuilder()
    await goToStep(/^4\. Rule$/)

    const palette = await screen.findByTestId('condition-palette')
    const offered = within(palette)
      .getAllByRole('button')
      .map((button) => button.dataset.nodeKind)
    expect(offered).toEqual([...NODE_KINDS])
    expect(offered).toHaveLength(3)
  })

  it("takes only a reference on a rule's left side — a constant is not on offer", async () => {
    await openBuilder()
    await declareEntity('user', 'id')
    await goToStep(/^4\. Rule$/)
    await userEvent.click(screen.getByRole('button', { name: 'Add comparison rule' }))

    const left = screen.getByLabelText('Left operand kind') as HTMLSelectElement
    const kinds = Array.from(left.options).map((option) => option.value)
    expect(kinds).toEqual(['field', 'source'])
    expect(kinds).not.toContain('literal')

    // The right side does offer all three, which is the AST's own asymmetry.
    const right = screen.getByLabelText('Right operand kind') as HTMLSelectElement
    expect(Array.from(right.options).map((o) => o.value)).toEqual([...OPERAND_KINDS])
  })

  it("cannot make a fact source's argument another source call", async () => {
    await openBuilder()
    await goToStep(/^1\. Declarations$/)
    await userEvent.click(screen.getByRole('button', { name: 'Add source declaration' }))
    await userEvent.type(screen.getByLabelText('Name'), 'role_members')
    await userEvent.click(screen.getByRole('button', { name: 'Add parameter' }))
    await userEvent.type(screen.getByLabelText('Parameter 1 name'), 'role')

    await goToStep(/^4\. Rule$/)
    await userEvent.click(screen.getByRole('button', { name: 'Add comparison rule' }))
    await userEvent.selectOptions(screen.getByLabelText('Left operand kind'), 'source')
    await userEvent.selectOptions(
      screen.getByLabelText('Left operand — fact source'),
      'role_members',
    )

    const argument = screen.getByLabelText('Argument role (string) kind') as HTMLSelectElement
    const kinds = Array.from(argument.options).map((option) => option.value)
    expect(kinds).toEqual(['field', 'literal'])
    expect(kinds).not.toContain('source')
  })

  it('cannot choose a source that is not in the declarations', async () => {
    await openBuilder()
    await declareEntity('user', 'id')
    await goToStep(/^4\. Rule$/)
    await userEvent.click(screen.getByRole('button', { name: 'Add comparison rule' }))
    await userEvent.selectOptions(screen.getByLabelText('Left operand kind'), 'source')

    const picker = screen.getByLabelText('Left operand — fact source') as HTMLSelectElement
    expect(Array.from(picker.options).map((o) => o.value)).toEqual([''])
    // And there is no text box to type one into.
    expect(picker.tagName).toBe('SELECT')
  })

  it('turns an empty allowlist into an operator request rather than a free-text target', async () => {
    await openBuilder()
    await goToStep(/^5\. challenge$/)
    await userEvent.click(screen.getByRole('button', { name: 'Add external approval (external)' }))

    const target = screen.getByLabelText('External target') as HTMLSelectElement
    expect(target.tagName).toBe('SELECT')
    expect(target).toBeDisabled()
    expect(screen.getByTestId('egress-empty')).toHaveTextContent('Ask the operator')
  })

  it('gives not exactly one operand', async () => {
    await openBuilder()
    await goToStep(/^4\. Rule$/)
    await userEvent.click(screen.getByRole('button', { name: 'Add logic group' }))
    await userEvent.click(screen.getByRole('button', { name: 'Add comparison rule' }))
    await userEvent.click(screen.getByRole('button', { name: 'Add membership rule' }))
    expect(screen.getByText('Exchange format')).toBeInTheDocument()

    await userEvent.selectOptions(screen.getByLabelText('Combination'), 'not')
    const document_ = screen.getByTestId('document-preview').textContent ?? ''
    expect(document_).toContain('not:')
    // The second operand is gone, and there is no button to add another.
    expect(document_.match(/left:/g)).toHaveLength(1)
    expect(screen.queryByRole('button', { name: 'Add membership rule' })).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// (c) the gap between submitted and in effect
// ---------------------------------------------------------------------------

describe('the gap between submitted and in force', () => {
  it('refuses submission before the preflight, with the reason tied to the button', async () => {
    await openBuilder()
    await goToStep(/^7\. Submit$/)

    const submit = screen.getByRole('button', { name: 'Submit revision' })
    expect(submit).toBeDisabled()
    expect(submit).toHaveAccessibleDescription(/The preflight has to run before/)
  })

  it('shows the quorum and the proposer exclusion before submission on a locked installation', async () => {
    const { calls } = await openBuilder()
    await goToStep(/^7\. Submit$/)
    await userEvent.click(screen.getByRole('button', { name: 'Check before submitting (preflight)' }))

    const notice = await screen.findByTestId('quorum-notice')
    expect(notice).toHaveTextContent('does not put this in force')
    expect(notice).toHaveTextContent('a quorum of 3 approvers')
    expect(notice).toHaveTextContent("the proposer's own approval does not count toward the quorum")
    expect(screen.getByTestId('affected-decisions')).toHaveTextContent(
      'Pending decisions this revision would affect: 4',
    )

    // Only now does submission open, and nothing was submitted to get here.
    expect(screen.getByRole('button', { name: 'Submit revision' })).toBeEnabled()
    expect(calls.filter((call) => call.path === '/policies/revisions')).toHaveLength(0)
  })

  it('keeps the submit button shut after the preflight when an operator floor is violated', async () => {
    await openBuilder({
      preview: {
        status: 200,
        body: {
          ...QUORUM_PREVIEW,
          violations: ['the quorum may not be lowered below the minimum of 2'],
        },
      },
    })
    await goToStep(/^7\. Submit$/)
    await userEvent.click(screen.getByRole('button', { name: 'Check before submitting (preflight)' }))

    expect(await screen.findByTestId('floor-violations')).toHaveTextContent('the minimum of 2')
    expect(screen.getByRole('button', { name: 'Submit revision' })).toBeDisabled()
  })

  it('reports a submission as pending rather than as a success', async () => {
    const { calls } = await openBuilder()
    await goToStep(/^7\. Submit$/)
    await userEvent.click(screen.getByRole('button', { name: 'Check before submitting (preflight)' }))
    await screen.findByTestId('quorum-notice')
    await userEvent.click(screen.getByRole('button', { name: 'Submit revision' }))

    const result = await screen.findByTestId('proposal-result')
    expect(result).toHaveTextContent('pending — not in force yet')
    expect(result).toHaveTextContent('once approvers reach the quorum')

    const submission = calls.find((call) => call.path === '/policies/revisions')
    const body = submission?.body as { delta: { changes: { kind: string }[] } }
    // A form edit is a one-element delta and not a special path.
    expect(body.delta.changes).toHaveLength(1)
    expect(body.delta.changes[0]?.kind).toBe('add')
  })

  it('states that the installation is unlocked instead of naming a quorum', async () => {
    await openBuilder({
      governance: { mode: 'solo_admin' },
      preview: { status: 200, body: { ...QUORUM_PREVIEW, mode: 'solo_admin', threshold: 0 } },
    })
    expect(await screen.findByTestId('unlocked-warning')).toBeInTheDocument()
    await goToStep(/^7\. Submit$/)
    await userEvent.click(screen.getByRole('button', { name: 'Check before submitting (preflight)' }))
    expect(await screen.findByTestId('unlocked-notice')).toHaveTextContent(
      'takes effect without a quorum',
    )
  })
})

// ---------------------------------------------------------------------------
// pending revisions, on entry rather than at submission
// ---------------------------------------------------------------------------

describe('pending revisions', () => {
  const pending = {
    governance: { mode: 'quorum', pending_revision: { ...PROPOSAL, proposer_id: 'u-1' } },
  }

  it('raises the banner on entry to authoring, with a withdrawal for your own proposal', async () => {
    const { calls } = await openBuilder(pending)
    const banner = await screen.findByTestId('pending-revision-banner')
    expect(banner).toHaveTextContent('rev-1')
    await userEvent.click(within(banner).getByTestId('withdraw-revision'))
    expect(calls.some((call) => call.path === '/policies/revisions/rev-1/withdrawal')).toBe(true)
  })

  it("names the proposer instead of offering a withdrawal on someone else's proposal", async () => {
    await openBuilder({
      governance: { mode: 'quorum', pending_revision: { ...PROPOSAL, proposer_id: 'someone-else' } },
    })
    const banner = await screen.findByTestId('pending-revision-banner')
    expect(within(banner).queryByTestId('withdraw-revision')).toBeNull()
    expect(banner).toHaveTextContent('Only the proposer can withdraw')
  })

  it('answers a revision that appears at submission with the same banner, not a generic error', async () => {
    let hasPending = false
    const impl = vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input), 'http://console.test').pathname
      const json = (status: number, body: unknown) =>
        new Response(JSON.stringify(body), {
          status,
          headers: { 'Content-Type': 'application/json' },
        })
      if (path === '/governance') {
        return json(
          200,
          hasPending
            ? { mode: 'quorum', pending_revision: { ...PROPOSAL, proposer_id: 'u-1' } }
            : { mode: 'quorum' },
        )
      }
      if (path === '/policies/revisions/preview') {
        hasPending = true
        return json(409, {
          error: 'revision_pending',
          message: 'another revision is open; approvers review one diff at a time',
        })
      }
      return json(404, { error: 'not_found', message: path })
    })

    renderShell({
      roles: ['author'],
      route: '/policies/new',
      fetchImpl: impl as unknown as typeof fetch,
    })
    await screen.findByRole('heading', { level: 1, name: 'Policy authoring' })
    await userEvent.click(await screen.findByRole('button', { name: /^7\. Submit$/ }))
    await userEvent.click(screen.getByRole('button', { name: 'Check before submitting (preflight)' }))

    expect(await screen.findByTestId('pending-revision-banner')).toBeInTheDocument()
    expect(screen.getByTestId('submit-failure')).toHaveTextContent('See the banner above')
  })
})

// ---------------------------------------------------------------------------
// the dry run
// ---------------------------------------------------------------------------

describe('the dry run', () => {
  it('returns the match, the per-condition results and the challenges that would fire, and says it stored nothing', async () => {
    await openBuilder({
      dryRun: {
        status: 200,
        body: {
          policy_id: 'todo.owner-write',
          matched: true,
          holds: false,
          decision: 'deny',
          reason: 'condition_false',
          conditions: [
            { pointer: '/condition', kind: 'all', result: false },
            { pointer: '/condition/all/0', kind: 'member', result: true },
            { pointer: '/condition/all/1', kind: 'compare', result: false },
          ],
          challenges: [{ type: 'quorum', detail: { threshold: 2 } }],
          sources: ['role_members("editor")'],
          stored: false,
        },
      },
    })

    await goToStep(/^6\. Dry run$/)
    await userEvent.click(screen.getByRole('button', { name: 'Run dry run' }))

    const result = await screen.findByTestId('dry-run-result')
    expect(result).toHaveTextContent('applies to this request')
    expect(result).toHaveTextContent('does not hold')
    expect(result).toHaveTextContent('deny (condition_false)')
    expect(screen.getByTestId('dry-run-stored')).toHaveTextContent('not stored')
    expect(result).toHaveTextContent('quorum')
    expect(result).toHaveTextContent('role_members("editor")')

    // Trace pointers arrive rooted at the policy and are shown in the space the
    // diagnostics use, so a node's result and a node's error name the same row.
    const rows = within(result)
      .getAllByRole('listitem')
      .map((item) => item.getAttribute('data-pointer'))
      .filter((value): value is string => value !== null)
    expect(rows).toEqual([
      '/policies/0/condition',
      '/policies/0/condition/all/0',
      '/policies/0/condition/all/1',
    ])
  })

  it('keeps an undeclared attribute out of the sample input form', async () => {
    const { calls } = await openBuilder()
    await declareEntity('user', 'dept')
    await goToStep(/^2\. Trigger conditions$/)
    await userEvent.selectOptions(screen.getByLabelText('subject entity'), 'user')
    await goToStep(/^6\. Dry run$/)

    expect(screen.getByLabelText('dept (string)')).toBeInTheDocument()
    expect(screen.queryByLabelText('secret (string)')).toBeNull()

    await userEvent.type(screen.getByLabelText('dept (string)'), 'ops')
    await userEvent.click(screen.getByRole('button', { name: 'Run dry run' }))

    const call = calls.find((c) => c.path === '/console/v1/policies/dry-run')
    const body = call?.body as { input: { subject: { attributes: Record<string, unknown> } } }
    expect(body.input.subject.attributes).toEqual({ dept: 'ops' })
  })
})

// ---------------------------------------------------------------------------
// accessibility
// ---------------------------------------------------------------------------

describe('accessibility', () => {
  it('has no axe violations on the policy list', async () => {
    const stubbed = stub({
      policies: {
        policies: [
          {
            id: 'todo.read',
            version: 3,
            origin: 'file',
            reserved: false,
            document: 'apiVersion: stamp/v1\nkind: Policy\nid: todo.read\n',
          },
        ],
      },
    })
    const { container } = renderShell({
      roles: ['author'],
      route: '/policies',
      fetchImpl: stubbed.impl,
    })
    await screen.findByRole('heading', { level: 1, name: 'Policies' })
    await screen.findByRole('button', { name: /todo\.read/ })
    expect(await auditable(container)).toEqual([])
  })

  it('has no axe violations on any step of the builder', async () => {
    const { container } = await openBuilder()
    await declareEntity('user', 'dept')
    await goToStep(/^4\. Rule$/)
    await userEvent.click(screen.getByRole('button', { name: 'Add comparison rule' }))
    await goToStep(/^5\. challenge$/)
    await userEvent.click(screen.getByRole('button', { name: 'Add quorum approval (quorum)' }))

    for (const step of [
      /^1\. Declarations$/,
      /^2\. Trigger conditions$/,
      /^3\. source binding$/,
      /^4\. Rule$/,
      /^5\. challenge$/,
      /^6\. Dry run$/,
      /^7\. Submit$/,
    ]) {
      await goToStep(step)
      expect(await auditable(container)).toEqual([])
    }
  })

  it('has no axe violations on a form carrying errors', async () => {
    const { container } = await openBuilder({
      dryRun: {
        status: 400,
        body: {
          error: 'invalid_policy',
          diagnostics: [
            {
              pointer: '/policies/0/challenges/0/threshold',
              code: 'invalid_value',
              message: 'quorum threshold must be at least 1',
            },
          ],
        },
      },
    })
    await goToStep(/^5\. challenge$/)
    await userEvent.click(screen.getByRole('button', { name: 'Add quorum approval (quorum)' }))
    await goToStep(/^6\. Dry run$/)
    await userEvent.click(screen.getByRole('button', { name: 'Run dry run' }))
    await screen.findByTestId('error-summary')
    expect(await auditable(container)).toEqual([])
  })

  it('moves between steps with the keyboard alone', async () => {
    await openBuilder()
    const first = screen.getByRole('button', { name: /^1\. Declarations$/ })
    first.focus()
    await userEvent.keyboard('{Enter}')
    expect(screen.getByRole('button', { name: /^1\. Declarations$/ })).toHaveAttribute(
      'aria-current',
      'step',
    )

    await userEvent.tab()
    await userEvent.keyboard('{Enter}')
    expect(screen.getByRole('button', { name: /^2\. Trigger conditions$/ })).toHaveAttribute(
      'aria-current',
      'step',
    )
  })
})
