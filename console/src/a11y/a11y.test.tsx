/**
 * axe over the shell.
 *
 * The Verification Contract runs axe against U15 and U16, in Playwright, over
 * real screens. That check can only pass if the frame those screens render into
 * is already clean, so the shell runs the same engine here — in jsdom, which
 * cannot see contrast but can see everything structural: landmarks, names,
 * roles, `aria-*` that points at nothing.
 *
 * Contrast is settled in styles.css instead, where every token pair is stated
 * with its ratio.
 */
import axe from 'axe-core'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { renderShell } from '../test/harness'
import { Disclosure } from './Disclosure'
import { ErrorSummary, fieldErrorId } from './ErrorSummary'

async function auditable(container: HTMLElement): Promise<string[]> {
  const results = await axe.run(container, {
    // jsdom reports no computed colours, so contrast checks would be noise
    // rather than signal. They belong in the Playwright pass.
    rules: { 'color-contrast': { enabled: false } },
  })
  return results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length}곳)`)
}

describe('셸 접근성', () => {
  it('정책 화면에 axe 위반이 없다', async () => {
    const { container } = renderShell({ roles: ['author', 'approver', 'auditor'] })
    await screen.findByRole('heading', { level: 1 })
    expect(await auditable(container)).toEqual([])
  })

  it('권한 거부 화면에 axe 위반이 없다', async () => {
    const { container } = renderShell({ roles: ['approver'], route: '/policies' })
    await screen.findByRole('heading', { level: 1, name: /권한이 없습니다/ })
    expect(await auditable(container)).toEqual([])
  })

  it('로그인 화면에 axe 위반이 없다', async () => {
    const { container } = renderShell({ signedIn: false })
    await screen.findByTestId('sign-in')
    expect(await auditable(container)).toEqual([])
  })
})

describe('오류 요약', () => {
  it('나타나면 초점을 가져가고 각 오류가 필드로 이어진다', async () => {
    const { container } = render(
      <form>
        <ErrorSummary
          errors={[{ fieldId: 'quorum', message: '정족수는 1 이상이어야 합니다' }]}
        />
        <label htmlFor="quorum">정족수</label>
        <input id="quorum" aria-describedby={fieldErrorId('quorum')} aria-invalid="true" />
        <p id={fieldErrorId('quorum')}>정족수는 1 이상이어야 합니다</p>
      </form>,
    )

    const summary = await screen.findByTestId('error-summary')
    expect(document.activeElement).toBe(summary)
    expect(screen.getByRole('link', { name: '정족수는 1 이상이어야 합니다' })).toHaveAttribute(
      'href',
      '#quorum',
    )
    expect(screen.getByLabelText('정족수')).toHaveAccessibleDescription('정족수는 1 이상이어야 합니다')
    expect(await auditable(container)).toEqual([])
  })

  it('오류가 없으면 아무것도 렌더링하지 않는다', () => {
    render(<ErrorSummary errors={[]} />)
    expect(screen.queryByTestId('error-summary')).toBeNull()
  })
})

describe('접힘 (R55)', () => {
  it('접힌 내용도 DOM에 남아 스크린 리더와 페이지 내 검색에 잡힌다', async () => {
    render(
      <Disclosure summary="정책 변경 3건">
        <p>계좌 화이트리스트 조건이 바뀝니다</p>
      </Disclosure>,
    )

    // Collapsed, and still present and readable — not hidden, not unmounted.
    const content = screen.getByText('계좌 화이트리스트 조건이 바뀝니다')
    expect(content).toBeInTheDocument()
    expect(content).toBeVisible()
    expect(screen.getByRole('button')).toHaveAttribute('aria-expanded', 'false')
  })

  it('키보드로 펼칠 수 있고 aria-expanded가 따라간다', async () => {
    const onFirstExpand = vi.fn()
    render(
      <Disclosure summary="정책 변경 3건" onFirstExpand={onFirstExpand}>
        <p>본문</p>
      </Disclosure>,
    )

    const trigger = screen.getByRole('button')
    trigger.focus()
    await userEvent.keyboard('{Enter}')
    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    expect(onFirstExpand).toHaveBeenCalledTimes(1)

    // Collapsing and expanding again is not a second "first expand": U16's
    // rule is that every item was seen once, not that it is open now.
    await userEvent.keyboard('{Enter}')
    await userEvent.keyboard('{Enter}')
    expect(onFirstExpand).toHaveBeenCalledTimes(1)
  })

  it('접힘 컨트롤에 axe 위반이 없다', async () => {
    const { container } = render(
      <Disclosure summary="정책 변경 3건">
        <p>본문</p>
      </Disclosure>,
    )
    expect(await auditable(container)).toEqual([])
  })
})
