/**
 * The pointer scheme, pinned to the pointers the engine actually produces.
 *
 * GO_DIAGNOSTICS below is not invented. It is the output of
 * `policy.Validate` — the real validator, cel-go compile and all — run over the
 * document this console's serializer writes for `brokenDraft()`:
 *
 *   /policies/0/resource                 unknown_entity
 *   /policies/0/actions/0                unknown_action
 *   /policies/0/challenges/0/threshold   invalid_value
 *   /policies/0/condition/all/0/left     unknown_attribute
 *   /policies/0/condition/all/1/right    type_mismatch
 *
 * Recording them here is what makes "a diagnostic lands on the field that caused
 * it" checkable without a Go toolchain in the console's test run. If the
 * validator's pointer scheme ever moves, this file is where the console finds
 * out — and the failure will be a diagnostic landing nowhere, which is exactly
 * the failure that would otherwise be invisible.
 */
import { describe, expect, it } from 'vitest'
import { placeDiagnostics, type Diagnostic } from './diagnostics'
import { placementFor, renderedPointers } from './fields'
import { brokenDraft } from './fixtures'
import { fieldId, fromTracePointer, jptr } from './pointer'

const GO_DIAGNOSTICS: readonly Diagnostic[] = [
  {
    pointer: '/policies/0/resource',
    code: 'unknown_entity',
    message: 'entity type "ledger" is not declared',
  },
  {
    pointer: '/policies/0/actions/0',
    code: 'unknown_action',
    message: 'action "can_wire_money" is not declared',
  },
  {
    pointer: '/policies/0/challenges/0/threshold',
    code: 'invalid_value',
    message: 'a quorum needs a threshold of at least 1, got 0',
  },
  {
    pointer: '/policies/0/condition/all/0/left',
    code: 'unknown_attribute',
    message: 'entity "user" declares no attribute "department"',
  },
  {
    pointer: '/policies/0/condition/all/1/right',
    code: 'type_mismatch',
    message: 'cannot compare string with int',
  },
]

describe('where a diagnostic pointer lands', () => {
  it('all five pointers the validator actually emitted land on a field', () => {
    const placed = placeDiagnostics(GO_DIAGNOSTICS, brokenDraft())
    expect(placed.unplaced).toEqual([])
    expect([...placed.byPointer.keys()]).toEqual([
      '/policies/0/resource',
      // The form has one control for the whole action set, so an error about
      // one action lands on the set rather than nowhere.
      '/policies/0/actions',
      '/policies/0/challenges/0/threshold',
      '/policies/0/condition/all/0/left',
      '/policies/0/condition/all/1/right',
    ])
  })

  it('lists the summary in form order rather than in response order', () => {
    const placed = placeDiagnostics(GO_DIAGNOSTICS, brokenDraft())
    expect(placed.summary.map((entry) => entry.fieldId)).toEqual([
      'bf.policies.0.resource',
      'bf.policies.0.actions',
      'bf.policies.0.condition.all.0.left',
      'bf.policies.0.condition.all.1.right',
      'bf.policies.0.challenges.0.threshold',
    ])
  })

  it("takes the summary's link and the field's id from the same function", () => {
    const placed = placeDiagnostics(GO_DIAGNOSTICS, brokenDraft())
    for (const entry of placed.summary) {
      expect(entry.fieldId).toBe(fieldId(entry.fieldId.slice(2).replace(/\./g, '/')))
    }
  })

  it('does not let a pointer with no ancestor disappear quietly', () => {
    const rendered = new Set(renderedPointers(brokenDraft()))
    expect(placementFor('/policies/0/challenges/0/threshold', rendered)).toBe(
      '/policies/0/challenges/0/threshold',
    )
    expect(placementFor('/nowhere/at/all', rendered)).toBeNull()

    const placed = placeDiagnostics(
      [{ pointer: '/nowhere/at/all', code: 'invalid_value', message: 'nowhere at all' }],
      brokenDraft(),
    )
    expect(placed.unplaced).toHaveLength(1)
    expect(placed.summary).toHaveLength(1)
  })
})

describe('pointer notation', () => {
  it("escapes per RFC 6901 exactly as the validator's own jptr does", () => {
    expect(jptr('policies', 0, 'condition')).toBe('/policies/0/condition')
    expect(jptr('schema', 'entities', 0, 'attributes', 'a/b')).toBe(
      '/schema/entities/0/attributes/a~1b',
    )
    expect(jptr('schema', 'entities', 0, 'attributes', 'a~b')).toBe(
      '/schema/entities/0/attributes/a~0b',
    )
    // A segment that is already a pointer is a prefix, as it is on the Go side.
    expect(jptr('/policies/0', 'id')).toBe('/policies/0/id')
  })

  it('turns distinct pointers into distinct ids', () => {
    const pointers = renderedPointers(brokenDraft())
    expect(new Set(pointers.map(fieldId)).size).toBe(new Set(pointers).size)
  })

  it('moves a trace pointer to the policy root, and never moves it twice', () => {
    expect(fromTracePointer('/condition/all/0')).toBe('/policies/0/condition/all/0')
    expect(fromTracePointer('/policies/0/condition/all/0')).toBe('/policies/0/condition/all/0')
    expect(fromTracePointer('')).toBe('')
  })
})
