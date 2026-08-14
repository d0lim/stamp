/**
 * The serializer, against the format the engine actually parses.
 *
 * The golden document below is not a snapshot of whatever this file happens to
 * emit. It was fed to internal/policy's own `Decode` + `Validate` — the
 * validator that finishes by compiling the condition through cel-go — and then
 * re-encoded, and the canonical re-encoding is the shape the Go encoder writes
 * for the same policy. So this test pins the console's output to a document the
 * engine accepts, not to itself.
 */
import { describe, expect, it } from 'vitest'
import { sampleDraft } from './fixtures'
import type { Draft, LiteralOperand } from './model'
import { serializeDraft, serializePolicy } from './serialize'

const GOLDEN = `apiVersion: "stamp/v1"
kind: "Schema"
entities:
  - name: "user"
    attributes:
      "id": "string"
  - name: "todo"
    attributes:
      "id": "string"
      "owner_id": "string"
actions:
  - name: "can_update_todo"
  - name: "can_delete_todo"
    description: "Deletes a todo."
sources:
  - name: "role_members"
    kind: "http"
    params:
      - {"role": "string"}
    returns: "list<string>"
    on_error: "deny"
  - name: "user_email"
    kind: "http"
    params:
      - {"user_id": "string"}
    returns: "string"
    on_error: "deny"
---
apiVersion: "stamp/v1"
kind: "Policy"
id: "todo.owner-write"
description: "An editor may update or delete a todo they own."
subject: "user"
resource: "todo"
actions: ["can_update_todo", "can_delete_todo"]
condition:
  all:
    - left: {field: "subject.id"}
      in: {source: "role_members", args: [{value: "editor", type: "string"}]}
    - left: {source: "user_email", args: [{field: "subject.id"}]}
      op: "eq"
      right: {field: "resource.owner_id"}
challenges:
  - type: "quorum"
    threshold: 2
    approvers: {members: ["alice", "bob"]}
`

/** Replaces the sample policy's right-hand constant, keeping everything else. */
function withRightConstant(draft: Draft, constant: LiteralOperand): Draft {
  return {
    ...draft,
    policy: {
      ...draft.policy,
      condition: {
        kind: 'compare',
        left: { kind: 'field', role: 'resource', attribute: 'owner_id' },
        op: 'eq',
        right: constant,
      },
    },
  }
}

describe('exchange format serialization', () => {
  it('writes the declarations and the policy as one document stream', () => {
    expect(serializeDraft(sampleDraft())).toBe(GOLDEN)
  })

  it('omits the schema document when there are no declarations, borrowing the ones in force', () => {
    const draft = sampleDraft()
    const bare: Draft = { schema: { entities: [], actions: [], sources: [] }, policy: draft.policy }
    expect(serializeDraft(bare)).not.toContain('kind: "Schema"')
    expect(serializeDraft(bare)).toBe(serializePolicy(draft.policy))
  })

  it('always writes a constant as an explicit {value, type} — never through tag inference', () => {
    const cases: readonly LiteralOperand[] = [
      { kind: 'literal', type: 'int', values: ['010'] },
      { kind: 'literal', type: 'bool', values: ['true'] },
      { kind: 'literal', type: 'timestamp', values: ['2026-01-01T00:00:00Z'] },
      { kind: 'literal', type: 'duration', values: ['1h30m'] },
      { kind: 'literal', type: 'list<string>', values: ['admin', 'editor'] },
    ]
    const expected = [
      'right: {value: "010", type: "int"}',
      'right: {value: "true", type: "bool"}',
      'right: {value: "2026-01-01T00:00:00Z", type: "timestamp"}',
      'right: {value: "1h30m", type: "duration"}',
      'right: {value: ["admin", "editor"], type: "list<string>"}',
    ]
    cases.forEach((constant, index) => {
      const document = serializePolicy(withRightConstant(sampleDraft(), constant).policy)
      expect(document).toContain(expected[index])
    })
  })

  /**
   * The form has one free-text surface — the value box — and this is what keeps
   * it from being an expression box. Text that reads as a reference, and text
   * that tries to close the mapping it is written inside, both come out as
   * quoted string content.
   */
  it('text typed into the value box cannot become structure', () => {
    const asReference = serializePolicy(
      withRightConstant(sampleDraft(), {
        kind: 'literal',
        type: 'string',
        values: ['{field: subject.id}'],
      }).policy,
    )
    expect(asReference).toContain('right: {value: "{field: subject.id}", type: "string"}')

    const breakout = serializePolicy(
      withRightConstant(sampleDraft(), {
        kind: 'literal',
        type: 'string',
        values: ['x", type: "int'],
      }).policy,
    )
    expect(breakout).toContain('right: {value: "x\\", type: \\"int", type: "string"}')
    // One `type:` key in the operand, and it is the declared one.
    expect(breakout.match(/type: "int"/g)).toBeNull()
  })

  it('traps control characters and newlines inside the scalar too', () => {
    const document = serializePolicy(
      withRightConstant(sampleDraft(), {
        kind: 'literal',
        type: 'string',
        values: ['a\nb\tc' + String.fromCharCode(7)],
      }).policy,
    )
    expect(document).toContain('right: {value: "a\\nb\\tc\\x07", type: "string"}')
    // The document gained no line: a newline in a value is not a new mapping.
    expect(document.split('\n').filter((line) => /^\s*right:/.test(line))).toHaveLength(1)
  })
})
