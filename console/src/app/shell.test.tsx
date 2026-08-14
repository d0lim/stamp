/**
 * The shell's own behaviour: who sees what, where a login lands, what an
 * expired token looks like, and whether any of it is reachable with a keyboard.
 */
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { renderShell } from '../test/harness'

describe('navigation and landing by role', () => {
  it('lands on the policy list when the token can author', async () => {
    renderShell({ roles: ['author'] })
    expect(await screen.findByRole('heading', { level: 1, name: 'Policies' })).toBeInTheDocument()
  })

  it('lands on the approval inbox when the token can only approve', async () => {
    renderShell({ roles: ['approver'] })
    expect(await screen.findByRole('heading', { level: 1, name: 'Approval inbox' })).toBeInTheDocument()
  })

  it('lands on audit when the token can only audit', async () => {
    renderShell({ roles: ['auditor'] })
    expect(await screen.findByRole('heading', { level: 1, name: 'Audit' })).toBeInTheDocument()
  })

  it('lands on a screen that explains the reason when the token has no role', async () => {
    renderShell({ roles: [] })
    expect(
      await screen.findByRole('heading', { level: 1, name: 'No screen is available to you' }),
    ).toBeInTheDocument()
  })

  it('navigation offers only the screens the token\'s roles reach', async () => {
    renderShell({ roles: ['approver'] })
    const nav = await screen.findByRole('navigation', { name: 'Primary' })
    expect(within(nav).getByRole('link', { name: 'Approval inbox' })).toBeInTheDocument()
    expect(within(nav).queryByRole('link', { name: 'Policies' })).toBeNull()
    expect(within(nav).queryByRole('link', { name: 'Audit' })).toBeNull()
  })
})

describe('opening a route the token cannot reach', () => {
  it('shows a screen carrying the reason and links to what is reachable', async () => {
    renderShell({ roles: ['approver'], route: '/policies' })

    expect(
      await screen.findByRole('heading', {
        level: 1,
        name: 'You do not have permission to open this screen',
      }),
    ).toBeInTheDocument()
    // The reason names the role that was missing.
    expect(screen.getByText(/Policy author/)).toBeInTheDocument()
    // And the way out is a link to a screen this person can actually use,
    // inside the refusal itself rather than only in the navigation.
    const main = screen.getByRole('main')
    expect(within(main).getByRole('link', { name: 'Approval inbox' })).toBeInTheDocument()
  })

  it('says so when no screen at all is reachable', async () => {
    renderShell({ roles: [], route: '/audit' })
    expect(await screen.findByText(/reaches no screen in this console/)).toBeInTheDocument()
  })
})

describe('unauthenticated access', () => {
  it('shows the sign-in screen and asks to return to where the visitor was headed', async () => {
    const navigateAway = vi.fn()
    renderShell({ signedIn: false, route: '/inbox/d-1', navigateAway })

    await userEvent.click(await screen.findByTestId('sign-in'))

    await waitFor(() => expect(navigateAway).toHaveBeenCalled())
    const url = new URL(navigateAway.mock.calls[0]?.[0] as string)
    expect(url.origin).toBe('https://idp.test')
    // The place they were going survives the round trip.
    const flow = JSON.parse(window.sessionStorage.getItem('stamp.console.oidc.flow') as string)
    expect(flow.returnTo).toBe('/inbox/d-1')
  })
})

describe('token expiry', () => {
  it('the shell offers a re-login wherever the 401 came from', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 401 }))
    // The probe stands in for whatever screen U15 or U16 puts here: it calls
    // through the client the shell handed it, and does nothing about the 401.
    // Handling it is the shell's job, which is the property being asserted.
    renderShell({
      roles: ['author'],
      fetchImpl: fetchImpl as unknown as typeof fetch,
      probe: (api) => void api.request('policy-list').catch(() => undefined),
    })

    expect(await screen.findByTestId('session-expired')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Sign in again' }))
    await waitFor(() =>
      expect(window.sessionStorage.getItem('stamp.console.oidc.flow')).not.toBeNull(),
    )
  })
})

describe('the accessibility skeleton', () => {
  it('has one of each landmark and a main that can take focus', async () => {
    renderShell({ roles: ['author'] })
    await screen.findByRole('heading', { level: 1 })

    expect(screen.getByRole('banner')).toBeInTheDocument()
    expect(screen.getByRole('contentinfo')).toBeInTheDocument()
    const main = screen.getByRole('main')
    expect(main).toHaveAttribute('id', 'main')
    expect(main).toHaveAttribute('tabindex', '-1')
  })

  it('the first focus target is the skip link', async () => {
    renderShell({ roles: ['author'] })
    await screen.findByRole('heading', { level: 1 })

    // The route announcer has just moved focus into main, so tabbing from there
    // walks the screen's own controls rather than the document's first one.
    // The claim being made is about document order — that nothing precedes the
    // skip link — so the walk starts from the top.
    ;(document.activeElement as HTMLElement | null)?.blur()
    await userEvent.tab()
    expect(document.activeElement).toHaveTextContent('Skip to main content')
  })

  it('a route change moves focus to main and announces the change', async () => {
    renderShell({ roles: ['author', 'approver'] })
    await screen.findByRole('heading', { level: 1, name: 'Policies' })

    await userEvent.click(screen.getByRole('link', { name: 'Approval inbox' }))

    await screen.findByRole('heading', { level: 1, name: 'Approval inbox' })
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('main')))
    expect(screen.getByTestId('route-announcer')).toHaveTextContent(
      'Navigated to the Approval inbox screen.',
    )
  })

  it('marks the current screen by something other than colour', async () => {
    renderShell({ roles: ['author', 'approver'] })
    await screen.findByRole('heading', { level: 1, name: 'Policies' })
    expect(
      screen.getByText('Policies', { selector: '[aria-current="page"]' }),
    ).toBeInTheDocument()
  })

  it('the whole shell can be walked with the keyboard alone', async () => {
    renderShell({ roles: ['author', 'approver', 'auditor'] })
    await screen.findByRole('heading', { level: 1 })

    const reachable = new Set<string>()
    for (let i = 0; i < 12; i += 1) {
      await userEvent.tab()
      const active = document.activeElement
      if (active && active !== document.body) reachable.add(active.textContent ?? '')
    }
    expect(reachable.has('Approval inbox')).toBe(true)
    expect(reachable.has('Audit')).toBe(true)
    expect(reachable.has('Sign out')).toBe(true)
  })
})
