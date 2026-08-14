/**
 * The audit console.
 *
 * R22 asks for three things a test can hold: the four query axes reach the
 * server, a reader without auditor standing gets a refusal that names what they
 * can still do, and a decision's policy version and fact snapshot are readable
 * — as text, with no HTML interpretation path anywhere on the screen.
 *
 * R55 adds a fourth: the accessibility bar here is the builder's. axe runs over
 * both screens for the same reason it runs over the builder.
 */
import axe from 'axe-core'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { renderShell } from '../test/harness'
import { queryParams } from './AuditScreen'
import { asText } from './AuditDecisionScreen'
import { EMPTY_QUERY } from './api-types'

const DECISION_ID = '5c2d1e3a-0000-4000-8000-0000000000aa'

const ROW = {
  id: DECISION_ID,
  caller_id: 'workload:https://idp.test#payments',
  policy_id: 'wire',
  policy_version: 3,
  subject_id: 'alice',
  resource_id: 'acct-1',
  action: 'transfer',
  state: 'allowed',
  created_at: '2026-08-10T11:00:00Z',
  expires_at: '2026-08-10T12:00:00Z',
}

const DETAIL = {
  ...ROW,
  request: { action: 'transfer', subject: { type: 'user', id: 'alice' } },
  // The payload the audit view has to render inert.
  fact_snapshot: { note: '<img src=x onerror="alert(1)">', script: '<script>alert(2)</script>' },
  obligations: [{ type: 'notify' }],
  policy_document: 'apiVersion: stamp/v1\nkind: Policy\nid: wire\n',
  policy_origin: 'form',
  challenges: [{ ordinal: 0, kind: 'quorum', state: 'satisfied', satisfied_at: '2026-08-10T11:30:00Z' }],
  approvals: [
    {
      ordinal: 0,
      approver_id: 'bob',
      verdict: 'approve',
      binding_hash: 'f00dbabe',
      submitted_at: '2026-08-10T11:20:00Z',
    },
  ],
  via_auditor_standing: true,
}

interface StubOptions {
  readonly list?: { readonly status: number; readonly body: unknown }
  readonly detail?: { readonly status: number; readonly body: unknown }
}

function stub(options: StubOptions = {}) {
  const calls: { path: string; search: string }[] = []
  const impl = vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://console.test')
    calls.push({ path: url.pathname, search: url.search })
    const answer = (status: number, payload: unknown) =>
      new Response(JSON.stringify(payload), { status, headers: { 'Content-Type': 'application/json' } })

    if (url.pathname === '/audit/decisions') {
      const result = options.list ?? {
        status: 200,
        body: {
          decisions: [ROW],
          query: { limit: 50, order: 'created_at desc' },
        },
      }
      return answer(result.status, result.body)
    }
    if (url.pathname.startsWith('/audit/decisions/')) {
      const result = options.detail ?? { status: 200, body: DETAIL }
      return answer(result.status, result.body)
    }
    return answer(404, { error: 'not_found', message: `no stub for ${url.pathname}` })
  })
  return { impl: impl as unknown as typeof fetch, calls }
}

// ---------------------------------------------------------------------------
// R22: the axes
// ---------------------------------------------------------------------------

describe('the audit list', () => {
  it('sends the four axes to the server and displays the server answer as the applied query', async () => {
    const user = userEvent.setup()
    const stubbed = stub({
      list: {
        status: 200,
        body: {
          decisions: [ROW],
          query: {
            from: '2026-08-01T00:00:00Z',
            to: '2026-09-01T00:00:00Z',
            policy: 'wire',
            subject: 'alice',
            state: 'allowed',
            limit: 50,
            order: 'created_at desc',
          },
        },
      },
    })
    renderShell({ roles: ['auditor'], route: '/audit', fetchImpl: stubbed.impl })
    await screen.findByTestId('audit-table')

    await user.type(screen.getByLabelText('Period start (RFC 3339)'), '2026-08-01T00:00:00Z')
    await user.type(screen.getByLabelText('Period end (exclusive)'), '2026-09-01T00:00:00Z')
    await user.type(screen.getByLabelText('Policy'), 'wire')
    await user.type(screen.getByLabelText('Subject'), 'alice')
    await user.selectOptions(screen.getByLabelText('State'), 'allowed')
    await user.click(screen.getByTestId('audit-search'))

    const last = stubbed.calls[stubbed.calls.length - 1]
    const sent = new URLSearchParams(last?.search ?? '')
    expect(sent.get('from')).toBe('2026-08-01T00:00:00Z')
    expect(sent.get('to')).toBe('2026-09-01T00:00:00Z')
    expect(sent.get('policy')).toBe('wire')
    expect(sent.get('subject')).toBe('alice')
    expect(sent.get('state')).toBe('allowed')

    // The screen reports the filter the *server* says it applied, so an auditor
    // can tell what they are looking at rather than what they meant to ask for.
    expect(screen.getByTestId('audit-applied')).toHaveTextContent('policy wire')
    expect(screen.getByTestId('audit-applied')).toHaveTextContent('created_at desc')
  })

  it('leaves an empty axis off the query', () => {
    expect(queryParams(EMPTY_QUERY, '')).toEqual({
      from: undefined,
      to: undefined,
      policy: undefined,
      subject: undefined,
      state: undefined,
      cursor: undefined,
    })
    expect(queryParams({ ...EMPTY_QUERY, policy: '  wire  ' }, 'c1').policy).toBe('wire')
    expect(queryParams(EMPTY_QUERY, 'c1').cursor).toBe('c1')
  })

  it('pages by cursor and disables next on the last page', async () => {
    const user = userEvent.setup()
    const stubbed = stub({
      list: {
        status: 200,
        body: { decisions: [ROW], next_cursor: 'cursor-2', query: { limit: 50, order: 'created_at desc' } },
      },
    })
    renderShell({ roles: ['auditor'], route: '/audit', fetchImpl: stubbed.impl })
    await screen.findByTestId('audit-table')

    expect(screen.getByTestId('audit-prev')).toBeDisabled()
    await user.click(screen.getByTestId('audit-next'))
    const last = stubbed.calls[stubbed.calls.length - 1]
    expect(new URLSearchParams(last?.search ?? '').get('cursor')).toBe('cursor-2')
  })

  it('shows a refusal that names the path still open when auditor standing is missing', async () => {
    // The one 403 that survived #38's collapse, and it is not an accident:
    // standing to read a collection says nothing about whether any single
    // decision exists, so it is an oracle for nothing (R22).
    renderShell({
      roles: ['auditor'],
      route: '/audit',
      fetchImpl: stub({ list: { status: 403, body: { error: 'not_an_auditor', message: 'nope' } } }).impl,
    })
    const refusal = await screen.findByTestId('audit-refused')
    expect(refusal).toHaveTextContent('do not have auditor standing')
    expect(refusal).toHaveTextContent('are the subject of')
    expect(screen.queryByTestId('audit-table')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// R22: one decision
// ---------------------------------------------------------------------------

describe('one decision', () => {
  it('shows the policy version applied and the fact snapshot', async () => {
    renderShell({ roles: ['auditor'], route: `/audit/${DECISION_ID}`, fetchImpl: stub().impl })
    expect(await screen.findByTestId('policy-version')).toHaveTextContent('wire · v3')
    expect(screen.getByTestId('audit-policy-document')).toHaveTextContent('kind: Policy')
    expect(screen.getByTestId('audit-facts')).toHaveTextContent('onerror')
  })

  it('escapes an HTML or script payload before displaying it', async () => {
    const { container } = renderShell({
      roles: ['auditor'],
      route: `/audit/${DECISION_ID}`,
      fetchImpl: stub().impl,
    })
    await screen.findByTestId('audit-facts')
    // Nothing was interpreted: no element came out of the payload, and the
    // text is still there to read.
    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByTestId('audit-facts').textContent).toContain('<script>alert(2)</script>')
  })

  it('shows the approvals collected and their binding hashes', async () => {
    renderShell({ roles: ['auditor'], route: `/audit/${DECISION_ID}`, fetchImpl: stub().impl })
    const table = await screen.findByTestId('audit-approvals')
    expect(within(table).getByText('bob')).toBeInTheDocument()
    expect(within(table).getByText('f00dbabe')).toBeInTheDocument()
  })

  it('says so when the reading is not on auditor standing', async () => {
    renderShell({
      roles: ['approver'],
      route: `/audit/${DECISION_ID}`,
      fetchImpl: stub({ detail: { status: 200, body: { ...DETAIL, via_auditor_standing: false } } }).impl,
    })
    expect(await screen.findByTestId('own-record-notice')).toBeInTheDocument()
  })

  it('lets a reader without auditor standing reach the decision detail route', async () => {
    // R22's second half is only usable if the link works. The role claim is
    // navigation; the server is the authorisation.
    renderShell({ roles: ['approver'], route: `/audit/${DECISION_ID}`, fetchImpl: stub().impl })
    expect(await screen.findByTestId('policy-version')).toBeInTheDocument()
  })

  it('does not serve the audit list without the auditor role', async () => {
    renderShell({ roles: ['approver'], route: '/audit', fetchImpl: stub().impl })
    // The refusal itself is app/RequireRole.tsx's, not this screen's.
    expect(await screen.findByRole('heading', { level: 1, name: /do not have permission/ })).toBeInTheDocument()
  })

  it('answers a decision you cannot read as one that is not there, and says so', async () => {
    // The detail surface no longer has a `403 not_readable`: it and `404
    // not_found` were the same existence oracle the approval surface had, so
    // they became one answer with one body (#38). This test used to stub the
    // 403 and pass against its own stub while the branch it exercised was
    // already unreachable.
    renderShell({
      roles: ['approver'],
      route: `/audit/${DECISION_ID}`,
      fetchImpl: stub({ detail: { status: 404, body: { error: 'not_found', message: 'no such decision' } } })
        .impl,
    })
    const notice = await screen.findByTestId('decision-unavailable')
    // Both halves, and neither claimed as the one that happened.
    expect(notice).toHaveTextContent('it does not exist, or it is not open to you')
    expect(notice).toHaveTextContent('only the decisions you initiated or are the subject of')
    // Not the generic read failure, which reads as an outage.
    expect(screen.queryByTestId('decision-error')).toBeNull()
    expect(screen.queryByText('Reading the decision…')).toBeNull()
  })

  it('renders JSON as text', () => {
    expect(asText({ a: 1 })).toBe('{\n  "a": 1\n}')
    expect(asText(null)).toBe('(none)')
    expect(asText('x')).toBe('x')
  })
})

// ---------------------------------------------------------------------------
// R55: the same accessibility bar as the builder
// ---------------------------------------------------------------------------

async function auditable(container: HTMLElement): Promise<string[]> {
  const results = await axe.run(container, {
    rules: { 'color-contrast': { enabled: false } },
  })
  return results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length} nodes)`)
}

describe('audit console accessibility', () => {
  it('has no axe violation on the list screen', async () => {
    const { container } = renderShell({ roles: ['auditor'], route: '/audit', fetchImpl: stub().impl })
    await screen.findByTestId('audit-table')
    expect(await auditable(container)).toEqual([])
  })

  it('has no axe violation on the decision detail screen', async () => {
    const { container } = renderShell({
      roles: ['auditor'],
      route: `/audit/${DECISION_ID}`,
      fetchImpl: stub().impl,
    })
    await screen.findByTestId('policy-version')
    expect(await auditable(container)).toEqual([])
  })

  it('has no axe violation on the refusal screen', async () => {
    const { container } = renderShell({
      roles: ['auditor'],
      route: '/audit',
      fetchImpl: stub({ list: { status: 403, body: { error: 'not_an_auditor' } } }).impl,
    })
    await screen.findByTestId('audit-refused')
    expect(await auditable(container)).toEqual([])
  })
})
