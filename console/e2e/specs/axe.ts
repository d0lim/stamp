/**
 * axe, in a real browser, with contrast on.
 *
 * The engine is injected from node_modules rather than fetched, because the
 * console's own rule is that a page reaches no external host — and a test that
 * broke it would be testing a page the deployment does not serve.
 *
 * `color-contrast` is the rule this file exists for. jsdom computes no colours,
 * so U15's suite had to disable it; here it is on, and it runs in both colour
 * schemes because the stylesheet defines two palettes and only one of them is
 * visible at a time.
 */
import { createRequire } from 'node:module'
import { expect, type Page } from '@playwright/test'

const require = createRequire(import.meta.url)
const AXE_PATH = require.resolve('axe-core/axe.min.js')

export interface Violation {
  readonly id: string
  readonly help: string
  readonly nodes: readonly string[]
}

/** Runs axe over the whole document and returns the violations, readably. */
export async function violations(page: Page): Promise<Violation[]> {
  await page.addScriptTag({ path: AXE_PATH })
  return page.evaluate(async () => {
    const engine = (window as unknown as { axe: { run: (ctx: unknown, opts: unknown) => Promise<unknown> } }).axe
    const results = (await engine.run(document, {
      // Everything on, contrast included. This is the pass jsdom cannot do.
      resultTypes: ['violations'],
    })) as {
      violations: { id: string; help: string; nodes: { html: string }[] }[]
    }
    return results.violations.map((v) => ({
      id: v.id,
      help: v.help,
      nodes: v.nodes.map((n) => n.html),
    }))
  })
}

/**
 * Asserts a clean axe pass in both colour schemes.
 *
 * Both, because the palette swaps entirely under `prefers-color-scheme: dark`
 * and a ratio that clears 4.5:1 in one is not evidence about the other.
 */
export async function expectAccessible(page: Page, ready: () => Promise<unknown>) {
  for (const scheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme: scheme })
    await ready()
    const found = await violations(page)
    expect(found, `${scheme} 스킴 axe 위반: ${JSON.stringify(found, null, 2)}`).toEqual([])
  }
}
