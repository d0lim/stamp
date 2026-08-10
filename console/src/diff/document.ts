/**
 * An exchange-format document, read as fields at pointers.
 *
 * This exists because U16 needs a field-level diff and U15 was explicit that
 * there must not be a second renderer: what an approver reads in an approval
 * and what an author reads before submitting have to be the same thing, or the
 * "the hash covers what you were shown" promise is about two different
 * renderings. So the diff is extracted here, in a module both own, and both
 * screens call it.
 *
 * It reads the *document*, not a draft. That is the only thing it can read: a
 * revision delta carries each side as an exchange-format document (R10), and
 * one of those sides is frequently a policy this console never authored — a
 * file-authored one, or one written before this build existed. `serialize.ts`
 * goes draft → document; this goes document → fields, and the pointers are the
 * same scheme (`pointer.ts`), so a field the form renders and a field the diff
 * shows are the same field by construction rather than by convention.
 *
 * It is not a YAML parser and must not become one. The exchange format is
 * emitted canonically by exactly two writers — internal/policy's encoder and
 * this console's serializer — and both write the same restricted subset: two
 * space indentation, block maps, block sequences, and flow collections that
 * never span a line. This reads that subset and treats anything else as an
 * opaque line, which is the failure direction that shows an approver too much
 * rather than too little.
 */
import { jptr } from '../builder/pointer'

/** One leaf of a document: a scalar or a flow collection, at its pointer. */
export interface DocumentField {
  /** RFC 6901 pointer into the document, in `pointer.ts`'s scheme. */
  readonly pointer: string
  /** The pointer rendered for a person: `challenges[0].threshold`. */
  readonly label: string
  /** The value as written, verbatim. */
  readonly value: string
}

interface Frame {
  /** The indentation this frame's children are written at. */
  readonly childIndent: number
  readonly pointer: string
  /** How many sequence items have been seen in this frame. */
  count: number
}

const CONTAINER_KEY = /^([^\s:][^:]*):$/
const KEYED_VALUE = /^([^\s:][^:]*):\s+(.*)$/

/**
 * Reads a document into its leaf fields, in document order.
 *
 * Containers produce no field of their own. A removed subtree therefore shows
 * as its removed leaves, which is what an approver has to see — "challenges was
 * removed" is a summary, and the question is which challenge.
 */
export function readDocumentFields(text: string): DocumentField[] {
  const out: DocumentField[] = []
  let stack: Frame[] = [{ childIndent: 0, pointer: '', count: 0 }]
  let documentIndex = 0

  const reset = () => {
    stack = [{ childIndent: 0, pointer: documentIndex === 0 ? '' : jptr(String(documentIndex)), count: 0 }]
  }

  for (const raw of text.split('\n')) {
    const line = raw.replace(/\s+$/, '')
    if (line === '') continue
    const trimmed = line.trimStart()
    // A comment line carries no field. The canonical writers emit none, but a
    // file-authored document that reached the store keeps the author's.
    if (trimmed.startsWith('#')) continue
    if (trimmed === '---' || trimmed === '...') {
      documentIndex += 1
      reset()
      continue
    }

    const indent = line.length - trimmed.length
    emitLine(out, stack, indent, trimmed)
  }
  return out
}

function emitLine(out: DocumentField[], stack: Frame[], indent: number, content: string) {
  popTo(stack, indent)
  const frame = stack[stack.length - 1]
  if (frame === undefined) return

  if (content.startsWith('- ') || content === '-') {
    const index = frame.count
    frame.count += 1
    const itemPointer = child(frame.pointer, index)
    // The item's own children are written two columns in from the dash.
    stack.push({ childIndent: indent + 2, pointer: itemPointer, count: 0 })
    const rest = content === '-' ? '' : content.slice(2).trimStart()
    if (rest === '') return
    const keyed = KEYED_VALUE.exec(rest) ?? CONTAINER_KEY.exec(rest)
    if (keyed) {
      emitLine(out, stack, indent + 2, rest)
      return
    }
    // A scalar sequence item: the item *is* the value.
    out.push(field(itemPointer, rest))
    return
  }

  const container = CONTAINER_KEY.exec(content)
  if (container) {
    const key = unquote(container[1] ?? '')
    stack.push({ childIndent: indent + 2, pointer: child(frame.pointer, key), count: 0 })
    return
  }

  const keyed = KEYED_VALUE.exec(content)
  if (keyed) {
    const key = unquote(keyed[1] ?? '')
    out.push(field(child(frame.pointer, key), (keyed[2] ?? '').trim()))
    return
  }

  // Anything this subset does not describe is kept whole rather than dropped.
  out.push(field(child(frame.pointer, String(frame.count++)), content))
}

/**
 * Pops frames until the top is the one whose children live at `indent`.
 *
 * A frame is kept when its children are written at exactly this column. Keeping
 * one whose children are written further in would attach this line to a subtree
 * it has already left.
 */
function popTo(stack: Frame[], indent: number) {
  while (stack.length > 1) {
    const top = stack[stack.length - 1]
    if (top !== undefined && top.childIndent <= indent) return
    stack.pop()
  }
}

/**
 * A child pointer.
 *
 * `jptr` treats a segment that already starts with `/` as a prefix, which is
 * how the Go side composes pointers — so the root, which is the empty string,
 * has to be passed as no segment at all rather than as one.
 */
function child(parent: string, key: string | number): string {
  return parent === '' ? jptr(key) : jptr(parent, key)
}

function field(pointer: string, value: string): DocumentField {
  return { pointer, label: labelFor(pointer), value }
}

/** `/challenges/0/threshold` reads as `challenges[0].threshold`. */
export function labelFor(pointer: string): string {
  const tokens = pointer
    .split('/')
    .slice(1)
    .map((token) => token.replace(/~1/g, '/').replace(/~0/g, '~'))
  let out = ''
  for (const token of tokens) {
    if (/^\d+$/.test(token)) out += `[${token}]`
    else out += out === '' ? token : `.${token}`
  }
  return out === '' ? '(문서)' : out
}

/** Strips the quoting the console's own serializer applies to every key. */
function unquote(key: string): string {
  const trimmed = key.trim()
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed
      .slice(1, -1)
      .replace(/\\"/g, '"')
      .replace(/\\\\/g, '\\')
  }
  return trimmed
}

/** How one field differs between two documents. */
export type ChangeKind = 'added' | 'removed' | 'changed' | 'unchanged'

/** One field's difference. */
export interface FieldChange {
  readonly pointer: string
  readonly label: string
  readonly kind: ChangeKind
  readonly before?: string
  readonly after?: string
}

/**
 * Diffs two exchange-format documents, field by field.
 *
 * An absent side means the whole document is new or gone, which is how a policy
 * addition and a policy deletion arrive in a delta. The result keeps the
 * *after* document's order, with removed fields sitting where they used to be,
 * so an approver reads the policy rather than a list of changes in hash order.
 */
export function diffDocuments(before: string | undefined, after: string | undefined): FieldChange[] {
  const beforeFields = before === undefined ? [] : readDocumentFields(before)
  const afterFields = after === undefined ? [] : readDocumentFields(after)
  const afterByPointer = new Map(afterFields.map((f) => [f.pointer, f]))
  const beforeByPointer = new Map(beforeFields.map((f) => [f.pointer, f]))

  const out: FieldChange[] = []
  const emitted = new Set<string>()
  let cursor = 0

  const emitAfter = (index: number) => {
    const f = afterFields[index]
    if (f === undefined || emitted.has(f.pointer)) return
    emitted.add(f.pointer)
    const previous = beforeByPointer.get(f.pointer)
    if (previous === undefined) {
      out.push({ pointer: f.pointer, label: f.label, kind: 'added', after: f.value })
      return
    }
    out.push({
      pointer: f.pointer,
      label: f.label,
      kind: previous.value === f.value ? 'unchanged' : 'changed',
      before: previous.value,
      after: f.value,
    })
  }

  for (const b of beforeFields) {
    if (afterByPointer.has(b.pointer)) {
      while (cursor < afterFields.length && afterFields[cursor]?.pointer !== b.pointer) {
        emitAfter(cursor)
        cursor += 1
      }
      emitAfter(cursor)
      cursor += 1
      continue
    }
    if (emitted.has(b.pointer)) continue
    emitted.add(b.pointer)
    out.push({ pointer: b.pointer, label: b.label, kind: 'removed', before: b.value })
  }
  while (cursor < afterFields.length) {
    emitAfter(cursor)
    cursor += 1
  }
  return out
}

/** How many fields actually differ. */
export function countChanged(changes: readonly FieldChange[]): number {
  return changes.filter((change) => change.kind !== 'unchanged').length
}
