/// <reference types="vitest/config" />
import { writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'

// The bundle is served from a subtree of the console listener rather than from
// its root, because the console surface is a real API surface too — the dry-run
// endpoint lives under /console/v1. See internal/api/console.go.
const BASE = '/console/'

const GITKEEP = [
  'This directory is where `npm run build` writes the console bundle, and it is',
  'tracked so that the go:embed directive in embed.go always matches something.',
  'A build that has not run the console build embeds this file alone, and the',
  'console role says so at runtime rather than failing to compile.',
  '',
].join('\n')

/**
 * `emptyOutDir` removes everything in dist, including the placeholder that
 * keeps the go:embed directive satisfiable in a checkout that has never run
 * this build. Writing it back is cheaper than the alternatives: leaving dist
 * dirty across builds, or making every Go contributor install Node.
 */
function keepEmbedPlaceholder(): Plugin {
  return {
    name: 'stamp-keep-embed-placeholder',
    apply: 'build',
    closeBundle() {
      writeFileSync(resolve(import.meta.dirname, 'dist/.gitkeep'), GITKEEP)
    },
  }
}

export default defineConfig({
  base: BASE,
  plugins: [react(), keepEmbedPlaceholder()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    // The module preload polyfill is emitted as an *inline* script, and the
    // console's CSP has no 'unsafe-inline' and no hash allowance. Leaving the
    // polyfill on produces a bundle the server's own policy blocks — which is
    // the single most surprising interaction between embedding and the CSP,
    // and the reason this line is not a default.
    modulePreload: { polyfill: false },
    // No source map. The bundle is embedded in the engine binary with
    // go:embed, and the map for this app is five times the size of the app —
    // five megabytes of every stamp image, in every deployment, to serve a
    // debugging aid nobody asked for. `npm run dev` has maps.
    sourcemap: false,
    target: 'es2022',
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}', 'scripts/**/*.test.mjs'],
    css: false,
  },
})
