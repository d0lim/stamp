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
  return results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.length} nodes)`)
}

describe('shell accessibility', () => {
  it('the policy screen has no axe violations', async () => {
    const { container } = renderShell({ roles: ['author', 'approver', 'auditor'] })
    await screen.findByRole('heading', { level: 1 })
    expect(await auditable(container)).toEqual([])
  })

  it('the refusal screen has no axe violations', async () => {
    const { container } = renderShell({ roles: ['approver'], route: '/policies' })
    await screen.findByRole('heading', { level: 1, name: /do not have permission/ })
    expect(await auditable(container)).toEqual([])
  })

  it('the sign-in screen has no axe violations', async () => {
    const { container } = renderShell({ signedIn: false })
    await screen.findByTestId('sign-in')
    expect(await auditable(container)).toEqual([])
  })
})

describe('the error summary', () => {
  it('takes focus when it appears, and every error leads to its field', async () => {
    const { container } = render(
      <form>
        <ErrorSummary
          errors={[{ fieldId: 'quorum', message: 'The quorum must be at least 1' }]}
        />
        <label htmlFor="quorum">Quorum</label>
        <input id="quorum" aria-describedby={fieldErrorId('quorum')} aria-invalid="true" />
        <p id={fieldErrorId('quorum')}>The quorum must be at least 1</p>
      </form>,
    )

    const summary = await screen.findByTestId('error-summary')
    expect(document.activeElement).toBe(summary)
    expect(screen.getByRole('link', { name: 'The quorum must be at least 1' })).toHaveAttribute(
      'href',
      '#quorum',
    )
    expect(screen.getByLabelText('Quorum')).toHaveAccessibleDescription(
      'The quorum must be at least 1',
    )
    expect(await auditable(container)).toEqual([])
  })

  it('renders nothing when there are no errors', () => {
    render(<ErrorSummary errors={[]} />)
    expect(screen.queryByTestId('error-summary')).toBeNull()
  })
})

describe('disclosure (R55)', () => {
  it('collapsed content stays in the DOM, so a screen reader and find-in-page still reach it', async () => {
    render(
      <Disclosure summary="3 policy changes">
        <p>The account allowlist condition changes</p>
      </Disclosure>,
    )

    // Collapsed, and still present and readable — not hidden, not unmounted.
    const content = screen.getByText('The account allowlist condition changes')
    expect(content).toBeInTheDocument()
    expect(content).toBeVisible()
    expect(screen.getByRole('button')).toHaveAttribute('aria-expanded', 'false')
  })

  it('expands with the keyboard, and aria-expanded follows', async () => {
    const onFirstExpand = vi.fn()
    render(
      <Disclosure summary="3 policy changes" onFirstExpand={onFirstExpand}>
        <p>Body</p>
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

  it('the disclosure control has no axe violations', async () => {
    const { container } = render(
      <Disclosure summary="3 policy changes">
        <p>Body</p>
      </Disclosure>,
    )
    expect(await auditable(container)).toEqual([])
  })
})
