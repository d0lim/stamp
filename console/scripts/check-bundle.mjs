#!/usr/bin/env node
/**
 * Checks the built bundle against the policy the server will serve it under.
 *
 * The console's CSP is `script-src 'self'; style-src 'self'` with no
 * 'unsafe-inline' and no hashes, which means an inline script or an inline
 * style in the emitted HTML is not a warning — it is a bundle the browser
 * silently refuses to run, on a page that then renders nothing. Vite emits an
 * inline module-preload polyfill by default, so this is a live failure mode and
 * not a hypothetical one; vite.config.ts turns the polyfill off and this runs
 * after every build to make sure nothing else brought one back.
 *
 * It also refuses any absolute external origin in the HTML: the bundle is
 * self-contained, and a CDN reference would be blocked by default-src 'none'
 * at exactly the wrong time.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const DIST = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'dist')

const problems = []

const html = readFileSync(join(DIST, 'index.html'), 'utf8')

// A <script> with no src is an inline one. `type="application/json"` data
// blocks are not executed and not covered by script-src, but the console has
// none, so anything scriptish here is a problem.
for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
  const attributes = match[1] ?? ''
  const body = (match[2] ?? '').trim()
  if (!/\bsrc=/.test(attributes) && body !== '') {
    problems.push(`index.html에 인라인 <script>가 있습니다 (CSP script-src 'self'가 차단합니다): ${body.slice(0, 80)}`)
  }
}
for (const match of html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) {
  if ((match[1] ?? '').trim() !== '') {
    problems.push("index.html에 인라인 <style>이 있습니다 (CSP style-src 'self'가 차단합니다).")
  }
}
if (/\sstyle=/.test(html)) {
  problems.push('index.html에 style 속성이 있습니다 — 인라인 스타일도 CSP가 차단합니다.')
}
for (const match of html.matchAll(/(?:src|href)=["'](https?:\/\/[^"']+)["']/gi)) {
  problems.push(`index.html이 외부 오리진 ${match[1]}을(를) 참조합니다 — 번들은 자기 완결이어야 합니다.`)
}

// Every asset index.html points at has to be in the bundle: a dangling
// reference embeds as a 404 that only shows up in a deployed image.
for (const match of html.matchAll(/(?:src|href)=["']\/console\/([^"']+)["']/gi)) {
  const asset = match[1]
  try {
    statSync(join(DIST, asset))
  } catch {
    problems.push(`index.html이 참조하는 ${asset}이(가) dist에 없습니다.`)
  }
}

const files = []
;(function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) walk(full)
    else files.push(relative(DIST, full))
  }
})(DIST)

// The placeholder has to survive `emptyOutDir`, or a checkout that has not run
// this build stops compiling.
if (!files.includes('.gitkeep')) {
  problems.push('dist/.gitkeep이 없습니다 — go:embed 지시자가 빈 디렉터리를 만나면 컴파일이 깨집니다.')
}

if (problems.length > 0) {
  console.error(`번들 검사 실패: ${problems.length}건`)
  for (const problem of problems) console.error(`  ${problem}`)
  process.exit(1)
}
console.log(`번들 검사 통과 (${files.length}개 파일, 인라인 스크립트·스타일 없음).`)
