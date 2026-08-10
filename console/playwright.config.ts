import { defineConfig, devices } from '@playwright/test'

/**
 * The Verification Contract's E2E gate.
 *
 * U14 deliberately did not scaffold this — an empty harness is something to
 * reshape rather than something to use — and U15 ran axe in jsdom with
 * `color-contrast` disabled, because jsdom computes no colours. That is the
 * hole this closes: a real browser, real stylesheets, and the contrast rule
 * on, in both colour schemes.
 *
 * One browser. The suite is an accessibility gate and two round trips, not a
 * compatibility matrix; three engines would triple the CI minutes to re-check
 * contrast ratios that are a property of the stylesheet.
 */
export default defineConfig({
  testDir: './e2e/specs',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? [['github'], ['list']] : [['list']],
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npx vite --config e2e/vite.config.ts --host 127.0.0.1',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
