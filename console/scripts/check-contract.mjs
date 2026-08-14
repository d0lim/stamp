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
            `${node.text} cannot be used outside the API client. ` +
              `Every call has to pass through src/api/client.ts for the contract check to mean anything.`,
          )
        }
      }

      // --- origin: browser-controlled configuration sources -----------------
      if (ts.isIdentifier(node) && FORBIDDEN_SOURCES.includes(node.text) && !isDeclarationName(node)) {
        report(
          'origin',
          node,
          `${node.text} is never read by the console (R50). ` +
            `Configuration comes only from the document the server supplies.`,
        )
      }
      if (ts.isIdentifier(node) && node.text === 'sessionStorage' && !isDeclarationName(node)) {
        if (!STORAGE_SEAM.has(seamKey)) {
          report(
            'origin',
            node,
            'sessionStorage carries the OIDC redirect round trip and nothing else (src/auth/oidc.ts).',
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
            `window.location.${node.name.text} is read on the OIDC callback screen alone. ` +
              `The query string and the fragment are not configuration channels (R50).`,
          )
        }
      }

      // --- codes: the wire body's `error` field is read in one module -------
      if (!ERROR_CODE_SEAM.has(seamKey)) {
        if (ts.isAsExpression(node) && namesWireErrorShape(node.type)) {
          report(
            'codes',
            node,
            "The response body's error code is read in src/api/error-codes.ts alone. " +
              'Use errorCodeOf() — the code vocabulary has to sit in one place to be ' +
              'comparable against what the server can emit.',
          )
        }
        if (ts.isAsExpression(node) && node.type.kind === ts.SyntaxKind.AnyKeyword && isResponseBody(node.expression)) {
          report(
            'codes',
            node,
            "Opening an ApiError's body as any slips past the code vocabulary comparison. " +
              'Use errorCodeOf() and errorMessageOf() from src/api/error-codes.ts.',
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
            "Do not read error directly off an ApiError's body. " +
              'errorCodeOf() in src/api/error-codes.ts is the only way through.',
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
            report('contract', node, 'this request() call names no endpoint.')
          } else if (!ts.isStringLiteral(argument) && !ts.isNoSubstitutionTemplateLiteral(argument)) {
            report(
              'contract',
              argument,
              'An endpoint name has to be a string literal. ' +
                'Computed into a variable, the call target is never statically checked.',
            )
          } else if (!declared.names.has(argument.text)) {
            report(
              'contract',
              argument,
              `"${argument.text}" is not in the public contract. ` +
                `Declare it in internal/api/contract.go and regenerate the contract document.`,
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
            `The absolute address ${node.text} is hard-coded in the source. ` +
              `Call targets come only from the contract and from the base address the server supplied.`,
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
      `contract/error-codes.json states version ${document.version} and this check reads ` +
        `${ERROR_CODE_DOCUMENT_VERSION}. The document's shape has changed.`,
    )
  }
  const served = new Map()
  for (const entry of document.codes ?? []) {
    served.set(entry.code, { statuses: entry.statuses ?? [], surfaces: entry.surfaces ?? [] })
  }
  return served
}

/** The exemption list, flattened to code → reason and endpoint → reason. */
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
        `the exemption list states version ${document.version} and this check reads ` +
        `${EXEMPTION_DOCUMENT_VERSION}.`,
    })
  }
  for (const group of document.codes ?? []) {
    const reason = typeof group.reason === 'string' ? group.reason.trim() : ''
    const codes = group.codes ?? []
    if (reason === '') {
      problems.push(violation(`the exemption group [${codes.join(', ')}] states no reason. ` +
        'An exemption with no reason turns the list back into the bare list it replaced.'))
    }
    if (codes.length === 0) {
      problems.push(violation('an exemption group holds no codes at all.'))
    }
    for (const code of codes) {
      if (exempt.has(code)) {
        problems.push(violation(`"${code}" is exempted in two groups — ` +
          'the file cannot say which of the two reasons is the true one.'))
        continue
      }
      exempt.set(code, reason)
    }
  }

  const unimplemented = new Map()
  for (const entry of document.endpoints ?? []) {
    const reason = typeof entry.reason === 'string' ? entry.reason.trim() : ''
    if (typeof entry.name !== 'string' || entry.name === '') {
      problems.push(violation('an unimplemented endpoint entry states no name.'))
      continue
    }
    if (reason === '') {
      problems.push(violation(`"${entry.name}" is listed as unimplemented with no reason.`))
    }
    if (unimplemented.has(entry.name)) {
      problems.push(violation(`"${entry.name}" is listed twice.`))
      continue
    }
    unimplemented.set(entry.name, reason)
  }

  return { exempt, unimplemented, problems }
}

function violation(message, at = '-', rule = 'vocabulary') {
  return { rule, file: 'contract/error-code-exemptions.json', at, message }
}

function coverage(message, at = '-') {
  return violation(message, at, 'coverage')
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
    throw new Error(`${modulePath} has no ${CONSUMED_DECLARATION} declaration.`)
  }
  // `[...] as const` is an as-expression around the array.
  const array = ts.isAsExpression(found) ? found.expression : found
  if (!ts.isArrayLiteralExpression(array)) {
    throw new Error(`${CONSUMED_DECLARATION} is not an array literal — ` +
      'a computed list cannot be read statically, and what cannot be read cannot be compared.')
  }
  const codes = []
  for (const element of array.elements) {
    if (!ts.isStringLiteral(element) && !ts.isNoSubstitutionTemplateLiteral(element)) {
      throw new Error(`every element of ${CONSUMED_DECLARATION} has to be a string literal.`)
    }
    codes.push(element.text)
  }
  return new Set(codes)
}

/**
 * The contract endpoints some screen actually calls.
 *
 * The `contract` rule already refuses a request target that is not a string
 * literal, so this walk is exhaustive by construction: every call names its
 * endpoint in the source or the check has already failed.
 */
export function calledEndpoints({ root = CONSOLE_ROOT, scanDir = 'src' } = {}) {
  const called = new Set()
  for (const path of sourceFiles(join(root, scanDir))) {
    const text = readFileSync(path, 'utf8')
    const file = ts.createSourceFile(path, text, ts.ScriptTarget.ES2022, true, scriptKindOf(path))
    const visit = (node) => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === REQUEST_CALL.method &&
        calleeMentions(node.expression, REQUEST_CALL.object)
      ) {
        const argument = node.arguments[REQUEST_CALL.endpointArgument]
        if (argument && (ts.isStringLiteral(argument) || ts.isNoSubstitutionTemplateLiteral(argument))) {
          called.add(argument.text)
        }
      }
      ts.forEachChild(node, visit)
    }
    ts.forEachChild(file, visit)
  }
  return called
}

/**
 * Compares the declared API surface against the one the console actually calls.
 *
 * The list of endpoints with no console caller is written down, in the same
 * file as the code exemptions and for the same reason: an unimplemented surface
 * that nobody wrote down is one nobody knows about, and `delay-cancel` was
 * exactly that — the server grew a per-authority budget, a 429 and a
 * `Retry-After` for it, and there is no screen to render any of them.
 *
 * Checked in both directions, because a one-directional check is the
 * hand-written list this round exists to avoid. A declared endpoint no screen
 * calls and no entry names is a gap nobody decided on; an entry naming an
 * endpoint some screen does call is a claim that stopped being true.
 */
export function checkEndpointCoverage({
  root = CONSOLE_ROOT,
  scanDir = 'src',
  contract = undefined,
  unimplemented = undefined,
  called = undefined,
} = {}) {
  const declared = contract ?? loadContract(root)
  const listed = unimplemented ?? loadErrorCodeExemptions(root).unimplemented
  const reached = called ?? calledEndpoints({ root, scanDir })
  const violations = []

  for (const name of declared.names) {
    if (reached.has(name) || listed.has(name)) continue
    violations.push(
      coverage(
        `"${name}" is in the public contract, no console screen calls it, and the ` +
          'unimplemented list does not name it. Build the screen, or write it down with a ' +
          'reason — an unimplemented surface nobody wrote down is one nobody knows about.',
        name,
      ),
    )
  }
  for (const [name] of listed) {
    if (!declared.names.has(name)) {
      violations.push(
        coverage(`"${name}" is in the unimplemented list and is not an API endpoint of the public contract.`, name),
      )
      continue
    }
    if (reached.has(name)) {
      violations.push(
        coverage(`"${name}" is one the console actually calls, and it is still in the unimplemented list.`, name),
      )
    }
  }
  return violations
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
        `"${code}": the console branches on it and the server emits it nowhere. A dead branch — ` +
          'delete it from src/api/error-codes.ts, and delete the copy on whichever screen worded it. ' +
          '(not_an_approver in #51 was exactly this.)',
      )
      continue
    }
    if (!entry.surfaces.includes('console')) {
      report(
        `"${code}": the server does emit it, but only on the ${entry.surfaces.join(', ')} listener. ` +
          'The console calls the console listener alone, so this branch is unreachable.',
      )
    }
  }

  for (const [code, entry] of servedCodes) {
    if (consumedCodes.has(code) || exempt.has(code)) continue
    report(
      `"${code}" (${entry.statuses.join(', ')}, ${entry.surfaces.join(', ')}): the server emits it ` +
        'and the console does not handle it. Add it to src/api/error-codes.ts and word it, or ' +
        'write it into contract/error-code-exemptions.json with a reason.',
    )
  }

  for (const [code] of exempt) {
    if (!servedCodes.has(code)) {
      violations.push(
        violation(`"${code}" is exempted and the server no longer emits it. ` +
          'The exemption outlived the code it explained.'),
      )
    }
    if (consumedCodes.has(code)) {
      violations.push(
        violation(`"${code}" is handled by the console and exempted at the same time — ` +
          'one of the two is false.'),
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
    lines.push(`\n[${rule}] ${items.length}`)
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
  const violations = [...checkConsole(), ...checkErrorVocabulary(), ...checkEndpointCoverage()]
  if (violations.length === 0) {
    const contract = loadContract()
    const served = loadServedErrorCodes()
    const consumed = loadConsumedErrorCodes()
    const { unimplemented } = loadErrorCodeExemptions()
    console.log(
      `console contract boundary: no violations (${contract.names.size} public contract endpoints, document version ${contract.version}).`,
    )
    console.log(
      `error code vocabulary: agrees in both directions (${served.size} served, ` +
        `${consumed.size} branched on by the console, ${served.size - consumed.size} exempt).`,
    )
    console.log(
      `surface coverage: the console calls ${contract.names.size - unimplemented.size} of ` +
        `${contract.names.size} contract endpoints, and ${unimplemented.size} are written down ` +
        `as unimplemented with a reason.`,
    )
    process.exit(0)
  }
  console.error(`console contract boundary check failed: ${violations.length}${formatViolations(violations)}`)
  console.error(
    '\nIf you have to call outside the public contract, make that endpoint part of the public ' +
      'contract first — growing a console-only endpoint is the exact thing D19 exists to prevent.',
  )
  process.exit(1)
}
