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

describe('감사 목록', () => {
  it('네 축이 서버 질의로 전달되고, 적용된 조회를 서버 답으로 표시한다', async () => {
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

    await user.type(screen.getByLabelText('기간 시작 (RFC 3339)'), '2026-08-01T00:00:00Z')
    await user.type(screen.getByLabelText('기간 끝 (미포함)'), '2026-09-01T00:00:00Z')
    await user.type(screen.getByLabelText('정책'), 'wire')
    await user.type(screen.getByLabelText('주체'), 'alice')
    await user.selectOptions(screen.getByLabelText('상태'), 'allowed')
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
    expect(screen.getByTestId('audit-applied')).toHaveTextContent('정책 wire')
    expect(screen.getByTestId('audit-applied')).toHaveTextContent('created_at desc')
  })

  it('빈 축은 질의에 실리지 않는다', () => {
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

  it('커서로 페이지를 넘기고 마지막 페이지에서는 다음이 비활성이다', async () => {
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

  it('감사자 자격이 없으면 거부 화면을 보여주고 남은 경로를 알려준다', async () => {
    renderShell({
      roles: ['auditor'],
      route: '/audit',
      fetchImpl: stub({ list: { status: 403, body: { error: 'not_an_auditor', message: 'nope' } } }).impl,
    })
    const refusal = await screen.findByTestId('audit-refused')
    expect(refusal).toHaveTextContent('자격이 없습니다')
    expect(refusal).toHaveTextContent('자신이 대상인 결정')
    expect(screen.queryByTestId('audit-table')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// R22: one decision
// ---------------------------------------------------------------------------

describe('결정 상세', () => {
  it('적용된 정책 버전과 사실 스냅샷을 보여준다', async () => {
    renderShell({ roles: ['auditor'], route: `/audit/${DECISION_ID}`, fetchImpl: stub().impl })
    expect(await screen.findByTestId('policy-version')).toHaveTextContent('wire · v3')
    expect(screen.getByTestId('audit-policy-document')).toHaveTextContent('kind: Policy')
    expect(screen.getByTestId('audit-facts')).toHaveTextContent('onerror')
  })

  it('HTML·스크립트 페이로드가 이스케이프되어 표시된다', async () => {
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

  it('수집된 승인과 그 바인딩 해시를 보여준다', async () => {
    renderShell({ roles: ['auditor'], route: `/audit/${DECISION_ID}`, fetchImpl: stub().impl })
    const table = await screen.findByTestId('audit-approvals')
    expect(within(table).getByText('bob')).toBeInTheDocument()
    expect(within(table).getByText('f00dbabe')).toBeInTheDocument()
  })

  it('감사자 자격이 아닌 열람이면 그렇게 말한다', async () => {
    renderShell({
      roles: ['approver'],
      route: `/audit/${DECISION_ID}`,
      fetchImpl: stub({ detail: { status: 200, body: { ...DETAIL, via_auditor_standing: false } } }).impl,
    })
    expect(await screen.findByTestId('own-record-notice')).toBeInTheDocument()
  })

  it('감사자 자격이 없는 사람도 결정 상세 경로에는 도달한다', async () => {
    // R22's second half is only usable if the link works. The role claim is
    // navigation; the server is the authorisation.
    renderShell({ roles: ['approver'], route: `/audit/${DECISION_ID}`, fetchImpl: stub().impl })
    expect(await screen.findByTestId('policy-version')).toBeInTheDocument()
  })

  it('감사 목록은 감사자 역할이 없으면 제공되지 않는다', async () => {
    renderShell({ roles: ['approver'], route: '/audit', fetchImpl: stub().impl })
    expect(await screen.findByRole('heading', { level: 1, name: /권한이 없습니다/ })).toBeInTheDocument()
  })

  it('열람 권한이 없는 결정은 거부 문구를 보여준다', async () => {
    renderShell({
      roles: ['approver'],
      route: `/audit/${DECISION_ID}`,
      fetchImpl: stub({ detail: { status: 403, body: { error: 'not_readable', message: 'nope' } } }).impl,
    })
    expect(await screen.findByTestId('decision-refused')).toBeInTheDocument()
  })

  it('JSON은 텍스트로 렌더링된다', () => {
    expect(asText({ a: 1 })).toBe('{\n  "a": 1\n}')
    expect(asText(null)).toBe('(없음)')
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
  return results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length}곳)`)
}

describe('감사 콘솔 접근성', () => {
  it('목록 화면에 axe 위반이 없다', async () => {
    const { container } = renderShell({ roles: ['auditor'], route: '/audit', fetchImpl: stub().impl })
    await screen.findByTestId('audit-table')
    expect(await auditable(container)).toEqual([])
  })

  it('결정 상세 화면에 axe 위반이 없다', async () => {
    const { container } = renderShell({
      roles: ['auditor'],
      route: `/audit/${DECISION_ID}`,
      fetchImpl: stub().impl,
    })
    await screen.findByTestId('policy-version')
    expect(await auditable(container)).toEqual([])
  })

  it('거부 화면에도 axe 위반이 없다', async () => {
    const { container } = renderShell({
      roles: ['auditor'],
      route: '/audit',
      fetchImpl: stub({ list: { status: 403, body: { error: 'not_an_auditor' } } }).impl,
    })
    await screen.findByTestId('audit-refused')
    expect(await auditable(container)).toEqual([])
  })
})
