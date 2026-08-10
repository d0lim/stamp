#!/usr/bin/env node
/**
 * The console's boundary check.
 *
 * D19 embeds the console in the engine binary and promises that embedding does
 * not foreclose pulling it back out. Two things have to hold for that: the API
 * base address has to be configurable and server-supplied, and the console has
 * to have no private endpoints. D19 also says why this file exists — the second
 * one leaks if it is only a principle, because a BFF grows one convenient
 * handler at a time and each one is defensible on its own. So a machine checks
 * it, on every pull request.
 *
 * Three rules, all enforced by reading the source rather than by running it:
 *
 *   contract  every request target is an endpoint declared in
 *             internal/api/contract.go and exported to
 *             contract/public-endpoints.json.
 *   seam      no network primitive — fetch, XMLHttpRequest, WebSocket,
 *             EventSource, sendBeacon — appears outside the two modules allowed
 *             to hold one. A raw fetch elsewhere is how a call escapes rule one.
 *   origin    the API base address is never read from a source a browser user
 *             controls: localStorage, sessionStorage outside the auth flow,
 *             the query string, the fragment, or a global someone else can set.
 *
 * The parser is TypeScript's own, so this reads the AST rather than grepping —
 * a string in a comment is not a violation and a call spelled across a line
 * break is not a miss.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

const HERE = dirname(fileURLToPath(import.meta.url))
const CONSOLE_ROOT = resolve(HERE, '..')

/** Modules permitted to touch a network primitive, relative to the scan root. */
const NETWORK_SEAM = new Set([
  join('src', 'api', 'client.ts'),
  join('src', 'auth', 'oidc.ts'),
  join('src', 'config', 'runtime-config.ts'),
])

/** Modules permitted to touch sessionStorage: the redirect flow, and only it. */
const STORAGE_SEAM = new Set([join('src', 'auth', 'oidc.ts')])

/** Modules permitted to read the query string: the OIDC callback, and only it. */
const QUERY_SEAM = new Set([join('src', 'app', 'CallbackScreen.tsx')])

const NETWORK_IDENTIFIERS = new Set([
  'fetch',
  'XMLHttpRequest',
  'WebSocket',
  'EventSource',
  'sendBeacon',
  'importScripts',
])

/** Reading any of these is a browser-controlled configuration source. */
const FORBIDDEN_SOURCES = ['localStorage']
/** The members of the browser's own location that carry user-supplied text. */
const QUERY_MEMBERS = new Set(['search', 'hash'])
/** The roots that reach the browser's location rather than the router's. */
const BROWSER_GLOBALS = new Set(['window', 'globalThis', 'document', 'self', 'top', 'parent'])

/** The function through which every request is made, and its parameter index. */
const REQUEST_CALL = { object: 'api', method: 'request', endpointArgument: 0 }

export function loadContract(root = CONSOLE_ROOT) {
  const raw = readFileSync(join(root, 'contract', 'public-endpoints.json'), 'utf8')
  const document = JSON.parse(raw)
  return {
    version: document.version,
    names: new Set(document.endpoints.filter((e) => e.group === 'api').map((e) => e.name)),
    all: document.endpoints,
  }
}

function sourceFiles(dir) {
  const out = []
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'dist' || entry.startsWith('.')) continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      out.push(...sourceFiles(full))
      continue
    }
    // Tests are skipped, and the reason is narrow: nothing under here reaches
    // the bundle Vite builds — only what main.tsx transitively imports does —
    // and these files exist to assert the very rules being checked, which
    // means naming a forbidden endpoint and a forbidden storage key on purpose.
    if (isTestPath(full)) continue
    if (/\.(ts|tsx|mts|js|mjs|jsx)$/.test(entry)) out.push(full)
  }
  return out
}

function positionOf(file, node) {
  const { line, character } = file.getLineAndCharacterOfPosition(node.getStart(file))
  return `${line + 1}:${character + 1}`
}

/**
 * Checks one console tree and returns the violations found.
 *
 * It takes a root so the checker can be pointed at a fixture, which is the only
 * honest way to know a check of this kind still fails when it should.
 */
export function checkConsole({ root = CONSOLE_ROOT, scanDir = 'src', contract } = {}) {
  const declared = contract ?? loadContract(root)
  const violations = []
  const scanRoot = join(root, scanDir)
  const files = sourceFiles(scanRoot)

  for (const path of files) {
    const relativePath = relative(root, path)
    const seamKey = relativePath.split(sep).join(sep)
    const text = readFileSync(path, 'utf8')
    const file = ts.createSourceFile(path, text, ts.ScriptTarget.ES2022, true, scriptKindOf(path))

    const report = (rule, node, message) =>
      violations.push({ rule, file: relativePath, at: positionOf(file, node), message })

    const visit = (node) => {
      // --- seam: a network primitive outside the modules that may hold one ---
      if (ts.isIdentifier(node) && NETWORK_IDENTIFIERS.has(node.text) && !isDeclarationName(node)) {
        if (!NETWORK_SEAM.has(seamKey) && !isTypePosition(node)) {
          report(
            'seam',
            node,
            `${node.text}은(는) API 클라이언트 밖에서 쓸 수 없습니다. ` +
              `모든 호출은 src/api/client.ts를 지나야 계약 검사가 성립합니다.`,
          )
        }
      }

      // --- origin: browser-controlled configuration sources -----------------
      if (ts.isIdentifier(node) && FORBIDDEN_SOURCES.includes(node.text) && !isDeclarationName(node)) {
        report(
          'origin',
          node,
          `${node.text}은(는) 콘솔에서 읽지 않습니다 (R50). ` +
            `설정은 서버가 내려주는 문서에서만 옵니다.`,
        )
      }
      if (ts.isIdentifier(node) && node.text === 'sessionStorage' && !isDeclarationName(node)) {
        if (!STORAGE_SEAM.has(seamKey)) {
          report(
            'origin',
            node,
            'sessionStorage는 OIDC 리다이렉트 왕복 상태에만 쓰입니다 (src/auth/oidc.ts).',
          )
        }
      }
      if (ts.isPropertyAccessExpression(node) && QUERY_MEMBERS.has(node.name.text)) {
        // Only the *browser's* location counts. React Router hands screens a
        // location object of its own, which is derived from the URL the router
        // already owns and is not a channel anyone can write from outside.
        // Reaching the real one takes window, globalThis, document, or the
        // bare global — which is why nothing in this console names a local
        // variable `location`.
        if (isBrowserLocation(node.expression) && !QUERY_SEAM.has(seamKey)) {
          report(
            'origin',
            node,
            `window.location.${node.name.text}은(는) OIDC 콜백 화면에서만 읽습니다. ` +
              `질의 문자열과 조각은 설정 채널이 아닙니다 (R50).`,
          )
        }
      }

      // --- contract: every request names a declared endpoint -----------------
      if (ts.isCallExpression(node)) {
        const callee = node.expression
        if (
          ts.isPropertyAccessExpression(callee) &&
          callee.name.text === REQUEST_CALL.method &&
          calleeMentions(callee, REQUEST_CALL.object)
        ) {
          const argument = node.arguments[REQUEST_CALL.endpointArgument]
          if (!argument) {
            report('contract', node, 'request() 호출에 엔드포인트 이름이 없습니다.')
          } else if (!ts.isStringLiteral(argument) && !ts.isNoSubstitutionTemplateLiteral(argument)) {
            report(
              'contract',
              argument,
              '엔드포인트 이름은 문자열 리터럴이어야 합니다. ' +
                '변수로 계산하면 호출 대상이 정적으로 검사되지 않습니다.',
            )
          } else if (!declared.names.has(argument.text)) {
            report(
              'contract',
              argument,
              `"${argument.text}"은(는) 공개 계약에 없습니다. ` +
                `internal/api/contract.go에 선언한 뒤 계약 문서를 다시 생성하십시오.`,
            )
          }
        }
      }

      // --- contract: an absolute URL literal is a call outside the contract --
      if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
        if (/^https?:\/\//i.test(node.text) && !isAllowedURLLiteral()) {
          report(
            'contract',
            node,
            `절대 주소 ${node.text}이(가) 소스에 박혀 있습니다. ` +
              `호출 대상은 계약과 서버가 내려준 기준 주소에서만 옵니다.`,
          )
        }
      }

      ts.forEachChild(node, visit)
    }

    ts.forEachChild(file, visit)
  }

  return violations
}

function scriptKindOf(path) {
  if (path.endsWith('.tsx')) return ts.ScriptKind.TSX
  if (path.endsWith('.jsx')) return ts.ScriptKind.JSX
  if (path.endsWith('.mjs') || path.endsWith('.js')) return ts.ScriptKind.JS
  return ts.ScriptKind.TS
}

/** The identifier being declared, not used — `const fetch = ...` is caught, a
 *  parameter named `fetchImpl` is not this, and `{ fetch }` in a type is. */
function isDeclarationName(node) {
  const parent = node.parent
  if (!parent) return false
  return (
    (ts.isVariableDeclaration(parent) && parent.name === node) ||
    (ts.isParameter(parent) && parent.name === node) ||
    (ts.isPropertySignature(parent) && parent.name === node) ||
    (ts.isPropertyAssignment(parent) && parent.name === node) ||
    (ts.isPropertyDeclaration(parent) && parent.name === node) ||
    (ts.isBindingElement(parent) && parent.name === node) ||
    ts.isImportSpecifier(parent) ||
    (ts.isFunctionDeclaration(parent) && parent.name === node) ||
    (ts.isMethodSignature(parent) && parent.name === node)
  )
}

/**
 * Whether an expression is the browser's `location`.
 *
 * `location.search`, `window.location.search`, `document.location.hash` — yes.
 * `routerLocation.search` from useLocation — no.
 */
function isBrowserLocation(expression) {
  if (ts.isIdentifier(expression)) return expression.text === 'location'
  if (ts.isPropertyAccessExpression(expression)) {
    return (
      expression.name.text === 'location' &&
      ts.isIdentifier(expression.expression) &&
      BROWSER_GLOBALS.has(expression.expression.text)
    )
  }
  return false
}

/** `typeof fetch` in a type annotation is a type, not a call. */
function isTypePosition(node) {
  let cursor = node.parent
  while (cursor) {
    if (ts.isTypeQueryNode(cursor) || ts.isTypeReferenceNode(cursor)) return true
    if (ts.isStatement(cursor) || ts.isSourceFile(cursor)) return false
    cursor = cursor.parent
  }
  return false
}

/** Whether a member access chain mentions the API client object. */
function calleeMentions(callee, name) {
  let cursor = callee.expression
  for (;;) {
    if (ts.isIdentifier(cursor)) return cursor.text === name
    if (ts.isPropertyAccessExpression(cursor)) {
      if (cursor.name.text === name) return true
      cursor = cursor.expression
      continue
    }
    if (ts.isCallExpression(cursor)) {
      cursor = cursor.expression
      continue
    }
    return false
  }
}

/** Test sources and the test harness: never bundled, so never a call target. */
function isTestPath(path) {
  return (
    /\.test\.(ts|tsx|mts|js|mjs|jsx)$/.test(path) ||
    path.includes(`${sep}src${sep}test${sep}`) ||
    path.endsWith(`${sep}setup.ts`)
  )
}

function isAllowedURLLiteral() {
  return false
}

export function formatViolations(violations) {
  const byRule = new Map()
  for (const v of violations) {
    if (!byRule.has(v.rule)) byRule.set(v.rule, [])
    byRule.get(v.rule).push(v)
  }
  const lines = []
  for (const [rule, items] of byRule) {
    lines.push(`\n[${rule}] ${items.length}건`)
    for (const item of items) {
      lines.push(`  ${item.file}:${item.at}  ${item.message}`)
    }
  }
  return lines.join('\n')
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  const violations = checkConsole()
  if (violations.length === 0) {
    const contract = loadContract()
    console.log(
      `콘솔 계약 경계: 위반 없음 (공개 계약 엔드포인트 ${contract.names.size}개, 문서 버전 ${contract.version}).`,
    )
    process.exit(0)
  }
  console.error(`콘솔 계약 경계 검사 실패: ${violations.length}건${formatViolations(violations)}`)
  console.error(
    '\n공개 계약 밖을 호출해야 한다면 그 엔드포인트를 먼저 공개 계약으로 만드십시오 — ' +
      '콘솔 전용 엔드포인트를 만드는 것이 D19가 막으려는 바로 그 일입니다.',
  )
  process.exit(1)
}
