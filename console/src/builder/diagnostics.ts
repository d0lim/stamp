/**
 * Server diagnostics, placed on the fields that caused them.
 *
 * internal/policy validates a document and returns `{pointer, code, message}`.
 * The dry-run endpoint passes those through unchanged, and its comment says why:
 * rewording them here would give the console two vocabularies for the same
 * mistake depending on which door the policy came through. So the message text
 * is the server's, and what the console adds is placement and a stable Korean
 * label for the code.
 *
 * The console never validates a policy itself. It could — it knows the declared
 * types and could refuse a string compared against an int before the request is
 * made — and it deliberately does not, because a second validator is a second
 * opinion, and the one that matters is the one that guards the door into the
 * engine. What the console does instead is make the server's answer land
 * somewhere useful.
 */
import type { FieldError } from '../a11y/ErrorSummary'
import { placementFor, renderedPointers } from './fields'
import type { Draft } from './model'
import { fieldId } from './pointer'

/** One structured validation failure, as policy.Diagnostic serializes. */
export interface Diagnostic {
  readonly pointer: string
  readonly code: string
  readonly message: string
}

/** The id the summary anchors a diagnostic to when no field owns it. */
export const UNPLACED_ANCHOR_ID = 'bf-unplaced'

/**
 * The stable codes, in Korean.
 *
 * The code is the machine-readable half of the contract and the message is the
 * human half; the label is what turns "type_mismatch" into something an author
 * reads without knowing the code exists. An unknown code falls through to the
 * message alone rather than to a wrong label — codes are stable, but a console
 * built against an older engine should degrade quietly.
 */
const CODE_LABELS: Readonly<Record<string, string>> = {
  invalid_yaml: '문서 형식 오류',
  invalid_document: '문서 구조 오류',
  unknown_api_version: '알 수 없는 apiVersion',
  unknown_kind: '알 수 없는 kind',
  unknown_key: '알 수 없는 항목',
  missing_field: '필수 항목 누락',
  invalid_name: '이름 규칙 위반',
  invalid_value: '값 오류',
  unknown_type: '알 수 없는 타입',
  duplicate: '중복',
  unknown_entity: '선언되지 않은 entity',
  unknown_action: '선언되지 않은 action',
  unknown_attribute: '선언되지 않은 속성',
  unbound_role: '바인딩되지 않은 역할',
  unknown_source: '선언되지 않은 source',
  type_mismatch: '타입 불일치',
  arity_mismatch: '인자 개수 불일치',
  invalid_operand: '피연산자 오류',
  invalid_operator: '연산자 오류',
  limit_exceeded: '한도 초과',
  unknown_challenge: '알 수 없는 challenge',
  unsupported: '미지원',
  cel_compile: '컴파일 실패',
}

/** The label for a code, or an empty string when the code is unfamiliar. */
export function codeLabel(code: string): string {
  return CODE_LABELS[code] ?? ''
}

/** One line an author reads: the label, then the validator's own message. */
export function describe(diagnostic: Diagnostic): string {
  const label = codeLabel(diagnostic.code)
  return label === '' ? diagnostic.message : `${label}: ${diagnostic.message}`
}

export interface PlacedDiagnostics {
  /** Diagnostics grouped by the pointer whose control shows them. */
  readonly byPointer: ReadonlyMap<string, readonly Diagnostic[]>
  /** Diagnostics no rendered field owns — a document-level failure. */
  readonly unplaced: readonly Diagnostic[]
  /** The top-of-form summary R19 requires, in document order. */
  readonly summary: readonly FieldError[]
}

export const NO_DIAGNOSTICS: PlacedDiagnostics = {
  byPointer: new Map(),
  unplaced: [],
  summary: [],
}

/**
 * Places diagnostics on the draft's fields.
 *
 * Order follows the form rather than the response: an author reading the
 * summary top to bottom walks the form top to bottom, and the validator's own
 * order is the order it happened to check things in.
 */
export function placeDiagnostics(
  diagnostics: readonly Diagnostic[],
  draft: Draft,
): PlacedDiagnostics {
  if (diagnostics.length === 0) return NO_DIAGNOSTICS

  const order = renderedPointers(draft)
  const rendered = new Set(order)
  const byPointer = new Map<string, Diagnostic[]>()
  const unplaced: Diagnostic[] = []

  for (const diagnostic of diagnostics) {
    const placement = placementFor(diagnostic.pointer, rendered)
    if (placement === null) {
      unplaced.push(diagnostic)
      continue
    }
    const bucket = byPointer.get(placement)
    if (bucket) bucket.push(diagnostic)
    else byPointer.set(placement, [diagnostic])
  }

  const summary: FieldError[] = []
  for (const pointer of order) {
    for (const diagnostic of byPointer.get(pointer) ?? []) {
      summary.push({ fieldId: fieldId(pointer), message: describe(diagnostic) })
    }
  }
  for (const diagnostic of unplaced) {
    summary.push({ fieldId: UNPLACED_ANCHOR_ID, message: describe(diagnostic) })
  }

  return { byPointer, unplaced, summary }
}

/** The diagnostics attached to one pointer. */
export function at(placed: PlacedDiagnostics, pointer: string): readonly Diagnostic[] {
  return placed.byPointer.get(pointer) ?? []
}

/** Reads a diagnostics payload out of an error body, when the failure carried one. */
export function diagnosticsOf(body: unknown): readonly Diagnostic[] {
  if (typeof body !== 'object' || body === null) return []
  const raw = (body as { diagnostics?: unknown }).diagnostics
  if (!Array.isArray(raw)) return []
  return raw.filter(
    (item): item is Diagnostic =>
      typeof item === 'object' &&
      item !== null &&
      typeof (item as Diagnostic).pointer === 'string' &&
      typeof (item as Diagnostic).code === 'string' &&
      typeof (item as Diagnostic).message === 'string',
  )
}
