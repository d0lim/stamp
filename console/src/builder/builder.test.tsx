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
  return results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length}곳)`)
}

async function openBuilder(options: StubOptions = {}) {
  const stubbed = stub(options)
  const rendered = renderShell({
    roles: ['author'],
    route: '/policies/new',
    fetchImpl: stubbed.impl,
  })
  await screen.findByRole('heading', { level: 1, name: '정책 저작' })
  return { ...rendered, calls: stubbed.calls }
}

/** Moves to a step by its button, the way a keyboard user would. */
async function goToStep(name: RegExp) {
  await userEvent.click(await screen.findByRole('button', { name }))
}

/** The minimum an author declares before a rule can be written. */
async function declareEntity(name: string, attribute: string) {
  await goToStep(/^1\. 선언$/)
  await userEvent.click(screen.getByRole('button', { name: 'entity 선언 추가' }))
  await userEvent.type(screen.getByLabelText('이름'), name)
  await userEvent.click(screen.getByRole('button', { name: '속성 추가' }))
  await userEvent.type(screen.getByLabelText('속성 1 이름'), attribute)
}

// ---------------------------------------------------------------------------
// (a) a diagnostic lands on the field that caused it
// ---------------------------------------------------------------------------

describe('진단이 원인 필드에 붙는다', () => {
  it('challenge threshold 진단이 threshold 입력에 연결되고 요약이 그 필드를 가리킨다', async () => {
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
    await userEvent.click(screen.getByRole('button', { name: '정족수 승인 (quorum) 추가' }))
    await goToStep(/^6\. 시험 평가$/)
    await userEvent.click(screen.getByRole('button', { name: '시험 평가 실행' }))

    // The flow moved to the step that owns the pointer, because an anchor into
    // a step that is not rendered is an anchor to nothing.
    const threshold = await screen.findByLabelText('정족수')
    expect(threshold.id).toBe('bf.policies.0.challenges.0.threshold')
    expect(threshold).toHaveAttribute('aria-invalid', 'true')
    expect(threshold).toHaveAccessibleDescription(/quorum threshold must be at least 1/)

    const summary = screen.getByTestId('error-summary')
    const link = within(summary).getByRole('link', { name: /quorum threshold must be at least 1/ })
    expect(link).toHaveAttribute('href', '#bf.policies.0.challenges.0.threshold')
    expect(document.getElementById('bf.policies.0.challenges.0.threshold')).toBe(threshold)
  })

  it('승인자 목록 진단은 그 승인자 입력에 붙는다', async () => {
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
    await userEvent.click(screen.getByRole('button', { name: '정족수 승인 (quorum) 추가' }))
    await goToStep(/^6\. 시험 평가$/)
    await userEvent.click(screen.getByRole('button', { name: '시험 평가 실행' }))

    const member = await screen.findByLabelText('승인자 1')
    expect(member).toHaveAccessibleDescription(/an approver may not be empty/)
  })

  it('폼이 렌더링하지 않는 포인터는 가장 가까운 조상 필드로 올라간다', async () => {
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
              message: '조상으로 올라가야 하는 진단',
            },
          ],
        },
      },
    })

    await goToStep(/^5\. challenge$/)
    await userEvent.click(screen.getByRole('button', { name: '정족수 승인 (quorum) 추가' }))
    await goToStep(/^6\. 시험 평가$/)
    await userEvent.click(screen.getByRole('button', { name: '시험 평가 실행' }))

    const member = await screen.findByLabelText('승인자 1')
    expect(member).toHaveAccessibleDescription(/조상으로 올라가야 하는 진단/)
  })

  it('어느 필드도 소유하지 않는 진단은 사라지지 않고 문서 수준으로 표시된다', async () => {
    await openBuilder({
      dryRun: {
        status: 400,
        body: {
          error: 'invalid_policy',
          diagnostics: [
            { pointer: '', code: 'invalid_yaml', message: '문서를 읽을 수 없습니다' },
          ],
        },
      },
    })

    await goToStep(/^6\. 시험 평가$/)
    await userEvent.click(screen.getByRole('button', { name: '시험 평가 실행' }))

    const summary = await screen.findByTestId('error-summary')
    const link = within(summary).getByRole('link', { name: /문서를 읽을 수 없습니다/ })
    expect(link).toHaveAttribute('href', '#bf-unplaced')
    expect(document.getElementById('bf-unplaced')).toHaveTextContent('문서를 읽을 수 없습니다')
  })
})

// ---------------------------------------------------------------------------
// (b) the form cannot express what the AST cannot hold
// ---------------------------------------------------------------------------

describe('폼은 AST가 담지 못하는 조건을 표현하지 못한다', () => {
  it('규칙 팔레트는 AST의 노드 종류와 정확히 같다', async () => {
    await openBuilder()
    await goToStep(/^4\. 규칙$/)

    const palette = await screen.findByTestId('condition-palette')
    const offered = within(palette)
      .getAllByRole('button')
      .map((button) => button.dataset.nodeKind)
    expect(offered).toEqual([...NODE_KINDS])
    expect(offered).toHaveLength(3)
  })

  it('규칙의 왼쪽은 참조만 받는다 — 상수는 선택지에 없다', async () => {
    await openBuilder()
    await declareEntity('user', 'id')
    await goToStep(/^4\. 규칙$/)
    await userEvent.click(screen.getByRole('button', { name: '비교 규칙 추가' }))

    const left = screen.getByLabelText('왼쪽 종류') as HTMLSelectElement
    const kinds = Array.from(left.options).map((option) => option.value)
    expect(kinds).toEqual(['field', 'source'])
    expect(kinds).not.toContain('literal')

    // The right side does offer all three, which is the AST's own asymmetry.
    const right = screen.getByLabelText('오른쪽 종류') as HTMLSelectElement
    expect(Array.from(right.options).map((o) => o.value)).toEqual([...OPERAND_KINDS])
  })

  it('fact source 인자는 다른 source 호출이 될 수 없다', async () => {
    await openBuilder()
    await goToStep(/^1\. 선언$/)
    await userEvent.click(screen.getByRole('button', { name: 'source 선언 추가' }))
    await userEvent.type(screen.getByLabelText('이름'), 'role_members')
    await userEvent.click(screen.getByRole('button', { name: '인자 추가' }))
    await userEvent.type(screen.getByLabelText('인자 1 이름'), 'role')

    await goToStep(/^4\. 규칙$/)
    await userEvent.click(screen.getByRole('button', { name: '비교 규칙 추가' }))
    await userEvent.selectOptions(screen.getByLabelText('왼쪽 종류'), 'source')
    await userEvent.selectOptions(screen.getByLabelText('왼쪽 — fact source'), 'role_members')

    const argument = screen.getByLabelText('인자 role (string) 종류') as HTMLSelectElement
    const kinds = Array.from(argument.options).map((option) => option.value)
    expect(kinds).toEqual(['field', 'literal'])
    expect(kinds).not.toContain('source')
  })

  it('선언에 없는 source는 고를 수 없다', async () => {
    await openBuilder()
    await declareEntity('user', 'id')
    await goToStep(/^4\. 규칙$/)
    await userEvent.click(screen.getByRole('button', { name: '비교 규칙 추가' }))
    await userEvent.selectOptions(screen.getByLabelText('왼쪽 종류'), 'source')

    const picker = screen.getByLabelText('왼쪽 — fact source') as HTMLSelectElement
    expect(Array.from(picker.options).map((o) => o.value)).toEqual([''])
    // And there is no text box to type one into.
    expect(picker.tagName).toBe('SELECT')
  })

  it('허용목록이 비면 외부 대상은 자유 입력이 아니라 운영자 요청 안내가 된다', async () => {
    await openBuilder()
    await goToStep(/^5\. challenge$/)
    await userEvent.click(screen.getByRole('button', { name: '외부 승인 (external) 추가' }))

    const target = screen.getByLabelText('외부 대상') as HTMLSelectElement
    expect(target.tagName).toBe('SELECT')
    expect(target).toBeDisabled()
    expect(screen.getByTestId('egress-empty')).toHaveTextContent('운영자에게')
  })

  it('not은 피연산자를 하나만 갖는다', async () => {
    await openBuilder()
    await goToStep(/^4\. 규칙$/)
    await userEvent.click(screen.getByRole('button', { name: '논리 그룹 추가' }))
    await userEvent.click(screen.getByRole('button', { name: '비교 규칙 추가' }))
    await userEvent.click(screen.getByRole('button', { name: '포함 규칙 추가' }))
    expect(screen.getByText('교환 포맷')).toBeInTheDocument()

    await userEvent.selectOptions(screen.getByLabelText('결합 방식'), 'not')
    const document_ = screen.getByTestId('document-preview').textContent ?? ''
    expect(document_).toContain('not:')
    // The second operand is gone, and there is no button to add another.
    expect(document_.match(/left:/g)).toHaveLength(1)
    expect(screen.queryByRole('button', { name: '포함 규칙 추가' })).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// (c) the gap between submitted and in effect
// ---------------------------------------------------------------------------

describe('제출과 발효 사이', () => {
  it('프리플라이트 전에는 제출할 수 없고, 그 이유가 버튼에 연결되어 있다', async () => {
    await openBuilder()
    await goToStep(/^7\. 제출$/)

    const submit = screen.getByRole('button', { name: '개정 제출' })
    expect(submit).toBeDisabled()
    expect(submit).toHaveAccessibleDescription(/먼저 프리플라이트를 실행해야/)
  })

  it('잠긴 설치에서는 정족수와 제안자 제외가 제출 전에 표시된다', async () => {
    const { calls } = await openBuilder()
    await goToStep(/^7\. 제출$/)
    await userEvent.click(screen.getByRole('button', { name: '제출 전 확인 (프리플라이트)' }))

    const notice = await screen.findByTestId('quorum-notice')
    expect(notice).toHaveTextContent('바로 발효되지 않습니다')
    expect(notice).toHaveTextContent('승인자 3명')
    expect(notice).toHaveTextContent('제안자 본인의 승인은 정족수에 포함되지 않습니다')
    expect(screen.getByTestId('affected-decisions')).toHaveTextContent('4건')

    // Only now does submission open, and nothing was submitted to get here.
    expect(screen.getByRole('button', { name: '개정 제출' })).toBeEnabled()
    expect(calls.filter((call) => call.path === '/policies/revisions')).toHaveLength(0)
  })

  it('운영자 하한을 위반하면 프리플라이트 후에도 제출 버튼이 열리지 않는다', async () => {
    await openBuilder({
      preview: {
        status: 200,
        body: { ...QUORUM_PREVIEW, violations: ['최소 정족수 2 미만으로 낮출 수 없습니다'] },
      },
    })
    await goToStep(/^7\. 제출$/)
    await userEvent.click(screen.getByRole('button', { name: '제출 전 확인 (프리플라이트)' }))

    expect(await screen.findByTestId('floor-violations')).toHaveTextContent('최소 정족수 2')
    expect(screen.getByRole('button', { name: '개정 제출' })).toBeDisabled()
  })

  it('제출은 성공이 아니라 미결 상태로 보고된다', async () => {
    const { calls } = await openBuilder()
    await goToStep(/^7\. 제출$/)
    await userEvent.click(screen.getByRole('button', { name: '제출 전 확인 (프리플라이트)' }))
    await screen.findByTestId('quorum-notice')
    await userEvent.click(screen.getByRole('button', { name: '개정 제출' }))

    const result = await screen.findByTestId('proposal-result')
    expect(result).toHaveTextContent('미결 — 아직 발효되지 않았습니다')
    expect(result).toHaveTextContent('정족수를 채우면 발효됩니다')

    const submission = calls.find((call) => call.path === '/policies/revisions')
    const body = submission?.body as { delta: { changes: { kind: string }[] } }
    // A form edit is a one-element delta and not a special path.
    expect(body.delta.changes).toHaveLength(1)
    expect(body.delta.changes[0]?.kind).toBe('add')
  })

  it('미잠금 설치에서는 정족수 대신 잠기지 않았다는 사실을 말한다', async () => {
    await openBuilder({
      governance: { mode: 'solo_admin' },
      preview: { status: 200, body: { ...QUORUM_PREVIEW, mode: 'solo_admin', threshold: 0 } },
    })
    expect(await screen.findByTestId('unlocked-warning')).toBeInTheDocument()
    await goToStep(/^7\. 제출$/)
    await userEvent.click(screen.getByRole('button', { name: '제출 전 확인 (프리플라이트)' }))
    expect(await screen.findByTestId('unlocked-notice')).toHaveTextContent('정족수 없이 발효')
  })
})

// ---------------------------------------------------------------------------
// pending revisions, on entry rather than at submission
// ---------------------------------------------------------------------------

describe('미결 개정', () => {
  const pending = {
    governance: { mode: 'quorum', pending_revision: { ...PROPOSAL, proposer_id: 'u-1' } },
  }

  it('저작 진입 시점에 배너가 뜨고 자기 제안이면 철회할 수 있다', async () => {
    const { calls } = await openBuilder(pending)
    const banner = await screen.findByTestId('pending-revision-banner')
    expect(banner).toHaveTextContent('rev-1')
    await userEvent.click(within(banner).getByTestId('withdraw-revision'))
    expect(calls.some((call) => call.path === '/policies/revisions/rev-1/withdrawal')).toBe(true)
  })

  it('남의 제안에는 철회 대신 제안자를 알려준다', async () => {
    await openBuilder({
      governance: { mode: 'quorum', pending_revision: { ...PROPOSAL, proposer_id: 'someone-else' } },
    })
    const banner = await screen.findByTestId('pending-revision-banner')
    expect(within(banner).queryByTestId('withdraw-revision')).toBeNull()
    expect(banner).toHaveTextContent('철회는 제안자만')
  })

  it('제출 시점에 미결이 생기면 일반 오류가 아니라 같은 배너로 처리된다', async () => {
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
    await screen.findByRole('heading', { level: 1, name: '정책 저작' })
    await userEvent.click(await screen.findByRole('button', { name: /^7\. 제출$/ }))
    await userEvent.click(screen.getByRole('button', { name: '제출 전 확인 (프리플라이트)' }))

    expect(await screen.findByTestId('pending-revision-banner')).toBeInTheDocument()
    expect(screen.getByTestId('submit-failure')).toHaveTextContent('위 배너에서 확인하십시오')
  })
})

// ---------------------------------------------------------------------------
// the dry run
// ---------------------------------------------------------------------------

describe('시험 평가', () => {
  it('매칭·조건별 결과·발동될 challenge를 돌려주고 아무것도 저장하지 않았음을 말한다', async () => {
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

    await goToStep(/^6\. 시험 평가$/)
    await userEvent.click(screen.getByRole('button', { name: '시험 평가 실행' }))

    const result = await screen.findByTestId('dry-run-result')
    expect(result).toHaveTextContent('이 요청에 적용됨')
    expect(result).toHaveTextContent('불성립')
    expect(result).toHaveTextContent('deny (condition_false)')
    expect(screen.getByTestId('dry-run-stored')).toHaveTextContent('저장되지 않음')
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

  it('선언에 없는 속성은 샘플 입력 폼에 나타나지 않는다', async () => {
    const { calls } = await openBuilder()
    await declareEntity('user', 'dept')
    await goToStep(/^2\. 발동 조건$/)
    await userEvent.selectOptions(screen.getByLabelText('subject entity'), 'user')
    await goToStep(/^6\. 시험 평가$/)

    expect(screen.getByLabelText('dept (string)')).toBeInTheDocument()
    expect(screen.queryByLabelText('secret (string)')).toBeNull()

    await userEvent.type(screen.getByLabelText('dept (string)'), 'ops')
    await userEvent.click(screen.getByRole('button', { name: '시험 평가 실행' }))

    const call = calls.find((c) => c.path === '/console/v1/policies/dry-run')
    const body = call?.body as { input: { subject: { attributes: Record<string, unknown> } } }
    expect(body.input.subject.attributes).toEqual({ dept: 'ops' })
  })
})

// ---------------------------------------------------------------------------
// accessibility
// ---------------------------------------------------------------------------

describe('접근성', () => {
  it('정책 목록에 axe 위반이 없다', async () => {
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
    await screen.findByRole('heading', { level: 1, name: '정책' })
    await screen.findByRole('button', { name: /todo\.read/ })
    expect(await auditable(container)).toEqual([])
  })

  it('빌더의 모든 단계에 axe 위반이 없다', async () => {
    const { container } = await openBuilder()
    await declareEntity('user', 'dept')
    await goToStep(/^4\. 규칙$/)
    await userEvent.click(screen.getByRole('button', { name: '비교 규칙 추가' }))
    await goToStep(/^5\. challenge$/)
    await userEvent.click(screen.getByRole('button', { name: '정족수 승인 (quorum) 추가' }))

    for (const step of [
      /^1\. 선언$/,
      /^2\. 발동 조건$/,
      /^3\. source 바인딩$/,
      /^4\. 규칙$/,
      /^5\. challenge$/,
      /^6\. 시험 평가$/,
      /^7\. 제출$/,
    ]) {
      await goToStep(step)
      expect(await auditable(container)).toEqual([])
    }
  })

  it('오류가 붙은 폼에도 axe 위반이 없다', async () => {
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
    await userEvent.click(screen.getByRole('button', { name: '정족수 승인 (quorum) 추가' }))
    await goToStep(/^6\. 시험 평가$/)
    await userEvent.click(screen.getByRole('button', { name: '시험 평가 실행' }))
    await screen.findByTestId('error-summary')
    expect(await auditable(container)).toEqual([])
  })

  it('저작 흐름은 키보드만으로 단계를 오간다', async () => {
    await openBuilder()
    const first = screen.getByRole('button', { name: /^1\. 선언$/ })
    first.focus()
    await userEvent.keyboard('{Enter}')
    expect(screen.getByRole('button', { name: /^1\. 선언$/ })).toHaveAttribute(
      'aria-current',
      'step',
    )

    await userEvent.tab()
    await userEvent.keyboard('{Enter}')
    expect(screen.getByRole('button', { name: /^2\. 발동 조건$/ })).toHaveAttribute(
      'aria-current',
      'step',
    )
  })
})
