/**
 * The console's `error` code vocabulary: every code it branches on, in one
 * place, and the only module that reads the code out of a response body.
 *
 * It exists because of an incident. #51 removed `403 not_an_approver` from the
 * approval surface and the console went on branching on it — and stayed green,
 * because the console's tests stub responses and a stub answers whatever the
 * test wrote. The TypeScript was internally consistent the whole time. Nothing
 * was wrong with any type; the branch was simply dead, and only a comparison
 * against what the server can actually emit would have said so.
 *
 * `internal/api/errorcodes_test.go` renders the server's half into
 * `contract/error-codes.json` by reading its own syntax tree.
 * `scripts/check-contract.mjs` compares the two sets in both directions:
 *
 *   - a code here that the server cannot emit is a dead branch, and fails;
 *   - a code the server emits that is not here fails unless
 *     `contract/error-code-exemptions.json` names it and says why.
 *
 * That comparison is only worth anything if this array really is the whole set.
 * Two things hold it:
 *
 *   - [ConsumedErrorCode] is derived from the array, so every branch is typed
 *     against it and a comparison with a code that is not in the array is a
 *     compile error rather than a branch that never runs;
 *   - the `codes` rule in the boundary check refuses any other module reading
 *     `error` off a response body, so a screen cannot quietly grow a seventh
 *     branch that no set knows about.
 *
 * Neither is a grep. A regular expression over the source would match the code
 * names in comments and in test fixtures and report branches that do not exist,
 * and the one thing worse than an unenforced vocabulary is an enforced one that
 * cries wolf — the next person turns it off.
 */
import { ApiError } from './client'

/**
 * The codes the console words differently from the generic failure.
 *
 * A code belongs here when a screen says something specific because of it. A
 * code the console meets and words by status alone — `401` is a session, `500`
 * is an outage — does not belong here, and is exempted on the other side with
 * that reason.
 */
export const CONSUMED_ERROR_CODES = [
  /** The decision's deadline passed. The approval was not recorded. */
  'expired',
  /**
   * The decision changed since it was shown, so the binding hash the approver
   * read no longer covers what is there (R31).
   */
  'material_changed',
  /** The quorum closed or the decision settled; no further submission counts. */
  'not_collecting',
  /**
   * No such decision — or it is not yours. The server answers both with the
   * same bytes on purpose (#38), so a screen that reads this cannot tell which
   * happened and must not write copy that claims to know.
   */
  'not_found',
  /**
   * A budget refused the request rather than a rule (R43). It is a wait, and
   * the screens that word it read `Retry-After` for the number.
   */
  'rate_limited',
  /** A second open revision proposal, which U9 refuses. */
  'revision_pending',
] as const

/**
 * A code the console has words for.
 *
 * Derived from the array rather than written beside it: a union and a list that
 * are maintained separately drift, and this one is load-bearing — it is what
 * makes `code === 'not_an_approver'` a type error instead of a branch that
 * compiles, passes its stubbed test, and never runs again.
 */
export type ConsumedErrorCode = (typeof CONSUMED_ERROR_CODES)[number]

const CONSUMED: ReadonlySet<string> = new Set(CONSUMED_ERROR_CODES)

/** The shape every refusal on this API carries: `api.ErrorResponse`. */
interface WireError {
  readonly error?: unknown
  readonly message?: unknown
}

function wireErrorOf(cause: unknown): WireError | undefined {
  if (!(cause instanceof ApiError)) return undefined
  const body = cause.body
  if (typeof body !== 'object' || body === null) return undefined
  return body as WireError
}

/**
 * The failure's code, when it is one this console has words for.
 *
 * A code the server sent that is not in the declared set comes back as
 * `undefined`, which sends the caller down its generic branch. That is the
 * fail-soft direction and it is deliberate: a deployment running a newer engine
 * than its console should show the server's own message, not a blank screen.
 * The set difference in CI is what makes sure that state is temporary — it is
 * not a substitute for the check, it is what the check buys time for.
 */
export function errorCodeOf(cause: unknown): ConsumedErrorCode | undefined {
  const code = wireErrorOf(cause)?.error
  if (typeof code !== 'string') return undefined
  return CONSUMED.has(code) ? (code as ConsumedErrorCode) : undefined
}

/**
 * The server's own sentence about the failure, when it sent one.
 *
 * Undefined rather than a fallback, so the caller decides what to say instead —
 * usually [ApiError]'s status-derived message, which is the one thing available
 * when the body could not be read at all.
 */
export function errorMessageOf(cause: unknown): string | undefined {
  const message = wireErrorOf(cause)?.message
  if (typeof message !== 'string' || message === '') return undefined
  return message
}
