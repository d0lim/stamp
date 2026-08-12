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
 * Four rules, all enforced by reading the source rather than by running it:
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
 *   codes     the `error` code of a response body is read in exactly one
 *             module, src/api/error-codes.ts. It is the seam rule again, for a
 *             different reason: the vocabulary comparison below is only worth
 *             something if the console's half of it is complete.
 *
 * The parser is TypeScript's own, so this reads the AST rather than grepping —
 * a string in a comment is not a violation and a call spelled across a line
 * break is not a miss.
 *
 * # The vocabulary comparison
 *
 * checkErrorVocabulary is the second half of this file and it closes a
 * different hole from the four rules above. #51 removed `403 not_an_approver`
 * from the server; the console kept branching on it and stayed green, because
 * the console's tests stub responses. Nothing compared the two sides. The
 * endpoint *set* has been compared since #44 — a Go test renders the mounted
 * routes and internal/release diffs them against the contract document — and
 * the `error` vocabulary, the axis that actually broke, had no such check.
 *
 * It is not a type generation problem, which is why no generator was added.
 * The console's types were internally consistent the entire time the branch was
 * dead. What catches it is a set difference, taken in both directions:
 *
 *   dead        the console branches on a code the server cannot emit — the
 *               #51 incident. Always a failure, with no exemption: there is no
 *               such thing as a defensible dead branch.
 *   off-surface the server emits it, but only on a listener the console never
 *               calls. Also dead, and worth naming separately because the fix
 *               is different: the branch is not stale, it was never reachable.
 *   unhandled   the server emits it on a surface the console calls and no
 *               screen words it. A failure unless contract/
 *               error-code-exemptions.json names the code and says why.
 *
 * The asymmetry is deliberate. Without exemptions a developer would be told to
 * write copy for the ingest listener's refusals, and a check that demands work
 * nobody needs is a check somebody turns off — at which point it is noise
 * rather than a guard. With them, the exemption file becomes the reviewable
 * artifact: adding a code to it is a diff somebody reads.
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

/**
 * The one module permitted to read the `error` code out of a response body.
 *
 * ApiError carries its body as `unknown`, so reaching the field takes a cast —
 * which is what makes this rule complete rather than a heuristic. Every way of
 * getting at the code goes through a type this rule can see.
 */
const ERROR_CODE_SEAM = new Set([join('src', 'api', 'error-codes.ts')])

/** The module the console's half of the vocabulary is declared in. */
const ERROR_CODE_MODULE = join('src', 'api', 'error-codes.ts')
/** The array in it that the comparison reads. */
const CONSUMED_DECLARATION = 'CONSUMED_ERROR_CODES'

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

      // --- codes: the wire body's `error` field is read in one module -------
      if (!ERROR_CODE_SEAM.has(seamKey)) {
        if (ts.isAsExpression(node) && namesWireErrorShape(node.type)) {
          report(
            'codes',
            node,
            '응답 본문의 error 코드는 src/api/error-codes.ts에서만 읽습니다. ' +
              'errorCodeOf()를 쓰십시오 — 코드 어휘가 한 곳에 모여 있어야 ' +
              '서버가 낼 수 있는 코드와 대조할 수 있습니다.',
          )
        }
        if (ts.isAsExpression(node) && node.type.kind === ts.SyntaxKind.AnyKeyword && isResponseBody(node.expression)) {
          report(
            'codes',
            node,
            'ApiError의 body를 any로 열면 코드 어휘 대조를 빠져나갑니다. ' +
              'src/api/error-codes.ts의 errorCodeOf()·errorMessageOf()를 쓰십시오.',
          )
        }
        if (
          ts.isPropertyAccessExpression(node) &&
          node.name.text === 'error' &&
          isResponseBody(node.expression)
        ) {
          report(
            'codes',
            node,
            'ApiError의 body에서 error를 직접 읽지 마십시오. ' +
              'src/api/error-codes.ts의 errorCodeOf()가 유일한 통로입니다.',
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

/**
 * Whether a type names the shape of a refusal body — the thing that carries the
 * `error` code.
 *
 * Two forms, because the console has written both: an inline `{ error?: string
 * }` at the cast, and the declared `ErrorResponse` from api-types. A union is
 * unwrapped because the casts are written `as { ... } | undefined`.
 *
 * An interface *declaration* with an `error` member is not this. api-types.ts
 * declares several — the dry-run trace carries an `error`, and so does the
 * diagnostics response — and they are field names on a payload rather than a
 * refusal code. Flagging them would make this rule cry wolf on its first run,
 * which is how a rule gets deleted.
 */
function namesWireErrorShape(type) {
  if (ts.isUnionTypeNode(type)) return type.types.some(namesWireErrorShape)
  if (ts.isParenthesizedTypeNode(type)) return namesWireErrorShape(type.type)
  if (ts.isTypeLiteralNode(type)) {
    return type.members.some(
      (member) => member.name !== undefined && ts.isIdentifier(member.name) && member.name.text === 'error',
    )
  }
  if (ts.isTypeReferenceNode(type) && ts.isIdentifier(type.typeName)) {
    return type.typeName.text === 'ErrorResponse'
  }
  return false
}

/** Whether an expression is an ApiError's `body`. */
function isResponseBody(expression) {
  return ts.isPropertyAccessExpression(expression) && expression.name.text === 'body'
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

// ---------------------------------------------------------------------------
// the vocabulary comparison
// ---------------------------------------------------------------------------

/** The document shape this file knows how to read. */
const ERROR_CODE_DOCUMENT_VERSION = 1
/** The exemption file's shape. */
const EXEMPTION_DOCUMENT_VERSION = 1

/**
 * The server's half: every code internal/api can put on the wire, with the
 * listeners it can reach.
 */
export function loadServedErrorCodes(root = CONSOLE_ROOT) {
  const raw = readFileSync(join(root, 'contract', 'error-codes.json'), 'utf8')
  const document = JSON.parse(raw)
  if (document.version !== ERROR_CODE_DOCUMENT_VERSION) {
    throw new Error(
      `contract/error-codes.json은 version ${document.version}인데 이 검사는 ` +
        `${ERROR_CODE_DOCUMENT_VERSION}을 읽습니다. 문서 모양이 바뀌었습니다.`,
    )
  }
  const served = new Map()
  for (const entry of document.codes ?? []) {
    served.set(entry.code, { statuses: entry.statuses ?? [], surfaces: entry.surfaces ?? [] })
  }
  return served
}

/** The exemption list, flattened to code → reason. */
export function loadErrorCodeExemptions(root = CONSOLE_ROOT) {
  const raw = readFileSync(join(root, 'contract', 'error-code-exemptions.json'), 'utf8')
  return parseErrorCodeExemptions(JSON.parse(raw))
}

/**
 * Flattens the exemption document, reporting the ways it is malformed rather
 * than throwing.
 *
 * A group with no reason is the failure this shape exists to prevent: the whole
 * value of the file is that a reader can see why a code goes unhandled, and an
 * empty reason turns it back into the bare list of codes it replaced.
 */
export function parseErrorCodeExemptions(document) {
  const problems = []
  const exempt = new Map()
  if (document.version !== EXEMPTION_DOCUMENT_VERSION) {
    problems.push({
      rule: 'vocabulary',
      file: 'contract/error-code-exemptions.json',
      at: 'version',
      message:
        `면제 목록이 version ${document.version}인데 이 검사는 ` +
        `${EXEMPTION_DOCUMENT_VERSION}을 읽습니다.`,
    })
  }
  for (const group of document.codes ?? []) {
    const reason = typeof group.reason === 'string' ? group.reason.trim() : ''
    const codes = group.codes ?? []
    if (reason === '') {
      problems.push(violation(`면제 묶음 [${codes.join(', ')}]에 이유가 없습니다. ` +
        '이유 없는 면제는 목록을 다시 그냥 목록으로 만듭니다.'))
    }
    if (codes.length === 0) {
      problems.push(violation('코드가 하나도 없는 면제 묶음이 있습니다.'))
    }
    for (const code of codes) {
      if (exempt.has(code)) {
        problems.push(violation(`"${code}"이(가) 두 묶음에 면제로 적혀 있습니다 — ` +
          '어느 이유가 참인지 파일이 답하지 못합니다.'))
        continue
      }
      exempt.set(code, reason)
    }
  }
  return { exempt, problems }
}

function violation(message, at = '-') {
  return { rule: 'vocabulary', file: 'contract/error-code-exemptions.json', at, message }
}

/**
 * The console's half: the codes declared in src/api/error-codes.ts.
 *
 * Read out of the module's syntax tree rather than imported, because this
 * checker runs on plain Node with no TypeScript compilation step — and rather
 * than grepped, because a grep over src/ would match the code names in the
 * comments that explain them and in the tests that stub them, and report a
 * vocabulary larger than the one the console actually branches on.
 */
export function loadConsumedErrorCodes(root = CONSOLE_ROOT, modulePath = ERROR_CODE_MODULE) {
  const path = join(root, modulePath)
  const text = readFileSync(path, 'utf8')
  const file = ts.createSourceFile(path, text, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS)

  let found
  const visit = (node) => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === CONSUMED_DECLARATION
    ) {
      found = node.initializer
    }
    ts.forEachChild(node, visit)
  }
  ts.forEachChild(file, visit)

  if (found === undefined) {
    throw new Error(`${modulePath}에 ${CONSUMED_DECLARATION} 선언이 없습니다.`)
  }
  // `[...] as const` is an as-expression around the array.
  const array = ts.isAsExpression(found) ? found.expression : found
  if (!ts.isArrayLiteralExpression(array)) {
    throw new Error(`${CONSUMED_DECLARATION}이(가) 배열 리터럴이 아닙니다 — ` +
      '계산된 목록은 정적으로 읽을 수 없고, 읽을 수 없으면 대조도 없습니다.')
  }
  const codes = []
  for (const element of array.elements) {
    if (!ts.isStringLiteral(element) && !ts.isNoSubstitutionTemplateLiteral(element)) {
      throw new Error(`${CONSUMED_DECLARATION}의 원소는 문자열 리터럴이어야 합니다.`)
    }
    codes.push(element.text)
  }
  return new Set(codes)
}

/**
 * Compares the two vocabularies and returns everything they disagree about.
 *
 * It takes both sides so a test can hand it planted drift and watch the same
 * code report it — the comparison itself is the thing that has to be known to
 * work, and a comparison that has only ever agreed is not known to compare
 * anything.
 */
export function checkErrorVocabulary({
  root = CONSOLE_ROOT,
  served = undefined,
  consumed = undefined,
  exemptions = undefined,
} = {}) {
  const servedCodes = served ?? loadServedErrorCodes(root)
  const consumedCodes = consumed ?? loadConsumedErrorCodes(root)
  const { exempt, problems } = exemptions ?? loadErrorCodeExemptions(root)
  const violations = [...problems]
  const report = (message) =>
    violations.push({ rule: 'vocabulary', file: 'contract/error-codes.json', at: '-', message })

  for (const code of consumedCodes) {
    const entry = servedCodes.get(code)
    if (entry === undefined) {
      report(
        `"${code}": 콘솔이 분기하는데 서버는 어디서도 내지 않습니다. 죽은 분기입니다 — ` +
          'src/api/error-codes.ts에서 지우고, 그 코드를 쓰던 화면의 문구도 함께 지우십시오. ' +
          '(#51의 not_an_approver가 정확히 이 상태였습니다.)',
      )
      continue
    }
    if (!entry.surfaces.includes('console')) {
      report(
        `"${code}": 서버가 내기는 하지만 ${entry.surfaces.join('·')} 리스너에서만 냅니다. ` +
          '콘솔은 console 리스너만 부르므로 이 분기에는 도달할 수 없습니다.',
      )
    }
  }

  for (const [code, entry] of servedCodes) {
    if (consumedCodes.has(code) || exempt.has(code)) continue
    report(
      `"${code}" (${entry.statuses.join('·')}, ${entry.surfaces.join('·')}): 서버가 내는데 ` +
        '콘솔에 처리가 없습니다. src/api/error-codes.ts에 더해 문구를 쓰거나, ' +
        'contract/error-code-exemptions.json에 이유와 함께 적으십시오.',
    )
  }

  for (const [code] of exempt) {
    if (!servedCodes.has(code)) {
      violations.push(
        violation(`"${code}"은(는) 서버가 더 이상 내지 않는데 면제 목록에 남아 있습니다. ` +
          '면제가 그것이 설명하던 코드보다 오래 살았습니다.'),
      )
    }
    if (consumedCodes.has(code)) {
      violations.push(
        violation(`"${code}"은(는) 콘솔이 실제로 처리하는데 면제 목록에도 있습니다. ` +
          '둘 중 하나는 거짓입니다.'),
      )
    }
  }

  return violations
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
  // Both halves run before either reports, so one pull request is told
  // everything that is wrong rather than one thing at a time.
  const violations = [...checkConsole(), ...checkErrorVocabulary()]
  if (violations.length === 0) {
    const contract = loadContract()
    const served = loadServedErrorCodes()
    const consumed = loadConsumedErrorCodes()
    console.log(
      `콘솔 계약 경계: 위반 없음 (공개 계약 엔드포인트 ${contract.names.size}개, 문서 버전 ${contract.version}).`,
    )
    console.log(
      `error 코드 어휘: 양방향 일치 (서버 ${served.size}개, 콘솔이 분기하는 것 ${consumed.size}개, ` +
        `면제 ${served.size - consumed.size}개).`,
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
