/**
 * JSON Pointers, which are the seam between the server's diagnostics and this
 * form's fields.
 *
 * internal/policy returns `Diagnostic{Pointer, Code, Message}` where Pointer is
 * an RFC 6901 pointer into the policy set as the exchange format encodes it.
 * The comment on that type says why it exists: "so a form can map an error back
 * to the field that caused it". This module is the form's half of that promise.
 *
 * The rule is that a rendered input's identity *is* its pointer. Nothing
 * registers a field; nothing keeps a lookup table that could go stale. A field
 * knows the pointer it occupies because the component that renders it is walking
 * the same tree the serializer walks, and the id is a pure function of that
 * pointer. So an error at `/policies/0/challenges/0/threshold` lands on the
 * threshold input for the same reason the threshold input exists at all.
 *
 * The pointer builder mirrors `jptr` in internal/policy/validate.go, escaping
 * included, because a mismatch here would be invisible until an author saw an
 * error attached to nothing.
 */

/** The index the single policy a form authors occupies in its document. */
export const POLICY_INDEX = 0

/** RFC 6901 token escaping: `~` becomes `~0`, `/` becomes `~1`. */
function escapeToken(token: string): string {
  return token.replace(/~/g, '~0').replace(/\//g, '~1')
}

/**
 * Builds a pointer from segments. A segment that already starts with `/` is
 * treated as a prefix and not escaped, which is how the Go side composes them.
 */
export function jptr(...segments: readonly (string | number)[]): string {
  let out = ''
  for (const segment of segments) {
    if (typeof segment === 'string' && segment.startsWith('/')) {
      out += segment
      continue
    }
    out += '/' + escapeToken(String(segment))
  }
  return out
}

/** The pointer at the policy this form authors. */
export function policyPointer(): string {
  return jptr('policies', POLICY_INDEX)
}

/**
 * The DOM id for a field at a pointer.
 *
 * Slashes become dots so the id is a single token an `href="#..."` anchor and
 * `getElementById` both accept, and the mapping stays injective — two different
 * pointers cannot produce the same id, which a "replace everything unsafe with
 * a dash" scheme would not guarantee.
 */
export function fieldId(pointer: string): string {
  return 'bf' + pointer.replace(/\//g, '.')
}

/**
 * Rewrites a dry-run trace pointer into the space diagnostics use.
 *
 * engine.NodeTrace documents its pointers as "the same scheme the validator's
 * diagnostics use", and they are — except that a trace is taken of one policy
 * and so is rooted at `/condition`, while a diagnostic is taken of a document
 * and is rooted at `/policies/N/condition`. The two meet here rather than in
 * every component that wants to put a node's result on the row that node
 * occupies.
 */
export function fromTracePointer(pointer: string): string {
  if (pointer === '' || pointer.startsWith(policyPointer())) return pointer
  return policyPointer() + pointer
}

/** Every proper ancestor of a pointer, nearest first, ending at the root. */
export function ancestors(pointer: string): readonly string[] {
  const out: string[] = []
  let cursor = pointer
  while (cursor.includes('/')) {
    cursor = cursor.slice(0, cursor.lastIndexOf('/'))
    out.push(cursor)
  }
  return out
}
