/**
 * The Verification Contract's E2E row: the builder round trip, the approval
 * round trip, and axe over both — in a real browser, contrast included.
 *
 * The two round trips are here because the unit tests stop at the component
 * boundary. What this adds is the whole page in a real engine: the router, the
 * stylesheets, focus, keyboard operation of the disclosures, and the colours,
 * which are the one thing jsdom is structurally unable to judge.
 */
import { expect, test } from '@playwright/test'
import { expectAccessible } from './axe'

const DECISION = '3f1b0f2a-0000-4000-8000-000000000001'
const APPROVAL = `/inbox/${DECISION}/0`

test.describe('승인 왕복', () => {
  test('승인함에서 상세로 들어가 모두 펼치고 승인한다', async ({ page }) => {
    await page.goto('/inbox')
    await expect(page.getByRole('heading', { level: 1, name: '승인함' })).toBeVisible()
    await expect(page.getByTestId('inbox-remaining-' + DECISION)).toContainText('시간')

    await page.getByRole('link', { name: /policy\.revise/ }).click()
    await expect(page.getByRole('heading', { level: 1, name: '승인 상세' })).toBeVisible()

    // R31: the hash, and what it covers.
    await expect(page.getByTestId('binding-hash')).toContainText('f00dbabe')
    await expect(page.getByTestId('binding-not-covered')).toContainText('정족수 임계값')

    // The list arrives in two pieces — the material with the review, the policy
    // entries with the delta.
    const entries = page.getByTestId('entry-list').getByRole('button')
    await expect(entries).toHaveCount(17)

    // R55: the gate is shut, and the button cannot be pressed.
    const approve = page.getByTestId('approve')
    await expect(approve).toBeDisabled()
    await expect(page.getByTestId('approve-gate')).toContainText('아직 펼치지 않은 항목이 16건')

    await page.getByTestId('expand-all').click()
    await expect(approve).toBeEnabled()

    await approve.click()
    await expect(page.getByTestId('submit-result')).toBeVisible()
  })

  test('접힌 항목이 페이지 내 검색과 스크린 리더에 잡힌다', async ({ page }) => {
    await page.goto(APPROVAL)
    await expect(page.getByTestId('entry-list').getByRole('button')).toHaveCount(17)

    // policy-5 is collapsed …
    const trigger = page.getByRole('button', { name: /^policy-5/ })
    await expect(trigger).toHaveAttribute('aria-expanded', 'false')

    // … and its content is still in the document, still laid out, still in the
    // accessibility tree. This is the assertion `display: none` fails.
    const region = page.getByTestId('diff-policy-5-fields')
    await expect(region).toBeVisible()
    await expect(region).toContainText('description')
    await expect(region).toContainText('개정 5')
    const box = await region.boundingBox()
    expect(box?.height ?? 0).toBeGreaterThan(0)

    // The weakening entry's own field is reachable too, and it is the one an
    // approver most needs: the lowered quorum.
    await expect(page.getByTestId('diff-policy-0-fields')).toContainText('challenges[0].threshold')
  })

  test('펼침·접힘이 키보드만으로 조작된다', async ({ page }) => {
    await page.goto(APPROVAL)
    await expect(page.getByTestId('entry-list').getByRole('button')).toHaveCount(17)

    const trigger = page.getByRole('button', { name: /^policy-1\b/ })
    await trigger.focus()
    await page.keyboard.press('Enter')
    await expect(trigger).toHaveAttribute('aria-expanded', 'true')
    await page.keyboard.press('Space')
    await expect(trigger).toHaveAttribute('aria-expanded', 'false')
  })
})

test.describe('빌더 왕복', () => {
  test('정책 목록에서 저작을 시작해 프리플라이트하고 제출한다', async ({ page }) => {
    await page.goto('/policies')
    await expect(page.getByRole('heading', { level: 1, name: '정책' })).toBeVisible()

    await page.getByRole('link', { name: '새 정책 저작 시작' }).click()
    await page.getByRole('button', { name: '2. 발동 조건' }).click()
    await page.getByLabel('정책 식별자').fill('e2e.policy')

    await page.getByRole('button', { name: '7. 제출' }).click()
    // R23: the change diff is drawn by the same renderer the approval uses.
    await page.getByRole('button', { name: /프리플라이트/ }).click()
    await expect(page.getByTestId('revision-preview')).toBeVisible()
    await expect(page.getByTestId('submit-diff-fields')).toContainText('id')

    await page.getByRole('button', { name: '개정 제출' }).click()
    await expect(page.getByTestId('proposal-result')).toContainText('미결')
  })
})

test.describe('axe — 실제 브라우저, 대비 포함', () => {
  test('승인함 목록', async ({ page }) => {
    await expectAccessible(page, async () => {
      await page.goto('/inbox')
      await expect(page.getByTestId('inbox-list')).toBeVisible()
    })
  })

  test('승인 상세 — 접힌 상태', async ({ page }) => {
    await expectAccessible(page, async () => {
      await page.goto(APPROVAL)
      await expect(page.getByTestId('entry-list').getByRole('button')).toHaveCount(17)
    })
  })

  test('승인 상세 — 모두 펼친 상태', async ({ page }) => {
    await expectAccessible(page, async () => {
      await page.goto(APPROVAL)
      await expect(page.getByTestId('entry-list').getByRole('button')).toHaveCount(17)
      await page.getByTestId('expand-all').click()
      await expect(page.getByTestId('approve')).toBeEnabled()
    })
  })

  test('감사 목록', async ({ page }) => {
    await expectAccessible(page, async () => {
      await page.goto('/audit')
      await expect(page.getByTestId('audit-table')).toBeVisible()
    })
  })

  test('감사 결정 상세', async ({ page }) => {
    await expectAccessible(page, async () => {
      await page.goto(`/audit/${DECISION}`)
      await expect(page.getByTestId('policy-version')).toBeVisible()
    })
  })

  test('정책 빌더', async ({ page }) => {
    await expectAccessible(page, async () => {
      await page.goto('/policies/new')
      await expect(page.getByRole('button', { name: '1. 선언' })).toBeVisible()
    })
  })
})
