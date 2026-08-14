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

test.describe('the approval round trip', () => {
  test('enters the detail from the approval inbox, expands everything and approves', async ({ page }) => {
    await page.goto('/inbox')
    await expect(page.getByRole('heading', { level: 1, name: 'Approval inbox' })).toBeVisible()
    await expect(page.getByTestId('inbox-remaining-' + DECISION)).toContainText('hour')

    await page.getByRole('link', { name: /policy\.revise/ }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Approval detail' })).toBeVisible()

    // R31: the hash, and what it covers.
    await expect(page.getByTestId('binding-hash')).toContainText('f00dbabe')
    await expect(page.getByTestId('binding-not-covered')).toContainText('Quorum threshold')

    // The list arrives in two pieces — the material with the review, the policy
    // entries with the delta.
    const entries = page.getByTestId('entry-list').getByRole('button')
    await expect(entries).toHaveCount(17)

    // R55: the gate is shut, and the button cannot be pressed.
    const approve = page.getByTestId('approve')
    await expect(approve).toBeDisabled()
    await expect(page.getByTestId('approve-gate')).toContainText('16 entries have not been expanded')

    await page.getByTestId('expand-all').click()
    await expect(approve).toBeEnabled()

    await approve.click()
    await expect(page.getByTestId('submit-result')).toBeVisible()
  })

  test('collapsed entries are reachable by find-in-page and by a screen reader', async ({ page }) => {
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
    await expect(region).toContainText('revision 5')
    const box = await region.boundingBox()
    expect(box?.height ?? 0).toBeGreaterThan(0)

    // The weakening entry's own field is reachable too, and it is the one an
    // approver most needs: the lowered quorum.
    await expect(page.getByTestId('diff-policy-0-fields')).toContainText('challenges[0].threshold')
  })

  test('expanding and collapsing works from the keyboard alone', async ({ page }) => {
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

test.describe('the builder round trip', () => {
  test('starts authoring from the policy list, previews, and submits', async ({ page }) => {
    await page.goto('/policies')
    await expect(page.getByRole('heading', { level: 1, name: 'Policies' })).toBeVisible()

    await page.getByRole('link', { name: 'Start authoring a new policy' }).click()
    await page.getByRole('button', { name: '2. Trigger conditions' }).click()
    await page.getByLabel('Policy identifier').fill('e2e.policy')

    await page.getByRole('button', { name: '7. Submit' }).click()
    // R23: the change diff is drawn by the same renderer the approval uses.
    await page.getByRole('button', { name: /preflight/ }).click()
    await expect(page.getByTestId('revision-preview')).toBeVisible()
    await expect(page.getByTestId('submit-diff-fields')).toContainText('id')

    await page.getByRole('button', { name: 'Submit revision' }).click()
    await expect(page.getByTestId('proposal-result')).toContainText('Pending')
  })
})

test.describe('axe — a real browser, contrast included', () => {
  test('the approval inbox list', async ({ page }) => {
    await expectAccessible(page, async () => {
      await page.goto('/inbox')
      await expect(page.getByTestId('inbox-list')).toBeVisible()
    })
  })

  test('the approval detail — collapsed', async ({ page }) => {
    await expectAccessible(page, async () => {
      await page.goto(APPROVAL)
      await expect(page.getByTestId('entry-list').getByRole('button')).toHaveCount(17)
    })
  })

  test('the approval detail — fully expanded', async ({ page }) => {
    await expectAccessible(page, async () => {
      await page.goto(APPROVAL)
      await expect(page.getByTestId('entry-list').getByRole('button')).toHaveCount(17)
      await page.getByTestId('expand-all').click()
      await expect(page.getByTestId('approve')).toBeEnabled()
    })
  })

  test('the audit list', async ({ page }) => {
    await expectAccessible(page, async () => {
      await page.goto('/audit')
      await expect(page.getByTestId('audit-table')).toBeVisible()
    })
  })

  test('the audit decision detail', async ({ page }) => {
    await expectAccessible(page, async () => {
      await page.goto(`/audit/${DECISION}`)
      await expect(page.getByTestId('policy-version')).toBeVisible()
    })
  })

  test('the policy builder', async ({ page }) => {
    await expectAccessible(page, async () => {
      await page.goto('/policies/new')
      await expect(page.getByRole('button', { name: '1. Declarations' })).toBeVisible()
    })
  })
})
