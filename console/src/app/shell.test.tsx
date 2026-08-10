/**
 * The shell's own behaviour: who sees what, where a login lands, what an
 * expired token looks like, and whether any of it is reachable with a keyboard.
 */
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { renderShell } from '../test/harness'

describe('역할별 내비게이션과 랜딩', () => {
  it('저작 권한이 있으면 정책 목록으로 랜딩한다', async () => {
    renderShell({ roles: ['author'] })
    expect(await screen.findByRole('heading', { level: 1, name: '정책' })).toBeInTheDocument()
  })

  it('승인 권한만 있으면 승인함으로 랜딩한다', async () => {
    renderShell({ roles: ['approver'] })
    expect(await screen.findByRole('heading', { level: 1, name: '승인함' })).toBeInTheDocument()
  })

  it('감사 권한만 있으면 감사로 랜딩한다', async () => {
    renderShell({ roles: ['auditor'] })
    expect(await screen.findByRole('heading', { level: 1, name: '감사' })).toBeInTheDocument()
  })

  it('역할이 없으면 사유를 설명하는 화면으로 랜딩한다', async () => {
    renderShell({ roles: [] })
    expect(
      await screen.findByRole('heading', { level: 1, name: '사용할 수 있는 화면이 없습니다' }),
    ).toBeInTheDocument()
  })

  it('내비게이션은 가진 역할의 화면만 노출한다', async () => {
    renderShell({ roles: ['approver'] })
    const nav = await screen.findByRole('navigation', { name: '주요' })
    expect(within(nav).getByRole('link', { name: '승인함' })).toBeInTheDocument()
    expect(within(nav).queryByRole('link', { name: '정책' })).toBeNull()
    expect(within(nav).queryByRole('link', { name: '감사' })).toBeNull()
  })
})

describe('권한 없는 라우트 직접 접근', () => {
  it('사유와 접근 가능한 화면 링크를 담은 전용 화면을 보여준다', async () => {
    renderShell({ roles: ['approver'], route: '/policies' })

    expect(
      await screen.findByRole('heading', { level: 1, name: '이 화면에 접근할 권한이 없습니다' }),
    ).toBeInTheDocument()
    // The reason names the role that was missing.
    expect(screen.getByText(/정책 저작/)).toBeInTheDocument()
    // And the way out is a link to a screen this person can actually use,
    // inside the refusal itself rather than only in the navigation.
    const main = screen.getByRole('main')
    expect(within(main).getByRole('link', { name: '승인함' })).toBeInTheDocument()
  })

  it('도달 가능한 화면이 하나도 없으면 그 사실을 말한다', async () => {
    renderShell({ roles: [], route: '/audit' })
    expect(await screen.findByText(/접근할 수 있는 화면이 없습니다/)).toBeInTheDocument()
  })
})

describe('미인증 접근', () => {
  it('로그인 화면을 보여주고, 로그인하면 원래 화면으로 돌아오도록 요청한다', async () => {
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

describe('토큰 만료', () => {
  it('어느 화면에서 401이 오든 셸이 재로그인을 유도한다', async () => {
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
    await userEvent.click(screen.getByRole('button', { name: '다시 로그인' }))
    await waitFor(() =>
      expect(window.sessionStorage.getItem('stamp.console.oidc.flow')).not.toBeNull(),
    )
  })
})

describe('접근성 뼈대', () => {
  it('랜드마크가 하나씩 있고 main이 초점을 받을 수 있다', async () => {
    renderShell({ roles: ['author'] })
    await screen.findByRole('heading', { level: 1 })

    expect(screen.getByRole('banner')).toBeInTheDocument()
    expect(screen.getByRole('contentinfo')).toBeInTheDocument()
    const main = screen.getByRole('main')
    expect(main).toHaveAttribute('id', 'main')
    expect(main).toHaveAttribute('tabindex', '-1')
  })

  it('첫 번째 초점 대상은 본문 건너뛰기 링크다', async () => {
    renderShell({ roles: ['author'] })
    await screen.findByRole('heading', { level: 1 })

    await userEvent.tab()
    expect(document.activeElement).toHaveTextContent('본문으로 건너뛰기')
  })

  it('라우트를 바꾸면 초점이 본문으로 옮겨가고 변경이 안내된다', async () => {
    renderShell({ roles: ['author', 'approver'] })
    await screen.findByRole('heading', { level: 1, name: '정책' })

    await userEvent.click(screen.getByRole('link', { name: '승인함' }))

    await screen.findByRole('heading', { level: 1, name: '승인함' })
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('main')))
    expect(screen.getByTestId('route-announcer')).toHaveTextContent('승인함 화면으로 이동했습니다.')
  })

  it('현재 화면이 색이 아닌 방법으로도 표시된다', async () => {
    renderShell({ roles: ['author', 'approver'] })
    await screen.findByRole('heading', { level: 1, name: '정책' })
    expect(screen.getByText('정책', { selector: '[aria-current="page"]' })).toBeInTheDocument()
  })

  it('전 화면을 키보드만으로 순회할 수 있다', async () => {
    renderShell({ roles: ['author', 'approver', 'auditor'] })
    await screen.findByRole('heading', { level: 1 })

    const reachable = new Set<string>()
    for (let i = 0; i < 12; i += 1) {
      await userEvent.tab()
      const active = document.activeElement
      if (active && active !== document.body) reachable.add(active.textContent ?? '')
    }
    expect(reachable.has('승인함')).toBe(true)
    expect(reachable.has('감사')).toBe(true)
    expect(reachable.has('로그아웃')).toBe(true)
  })
})
