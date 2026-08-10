import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

/**
 * The end-to-end page's own Vite root.
 *
 * It is separate from the console's config so that `npm run build` — the one
 * that produces the bundle `go:embed` ships — never sees this directory. The
 * shipped artifact must not contain a test harness, and the cheapest way to
 * guarantee that is for the production build to be unable to reach it.
 *
 * `appType: 'spa'` is what makes a deep link like /inbox/<id>/0 serve the page
 * instead of a 404, which is what the specs navigate to.
 */
export default defineConfig({
  root: import.meta.dirname,
  base: '/',
  appType: 'spa',
  plugins: [react()],
  server: { port: 4173, strictPort: true },
  preview: { port: 4173, strictPort: true },
})
