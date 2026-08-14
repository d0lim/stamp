/**
 * The field reader and the diff.
 *
 * The document these read is the exchange format as internal/policy's encoder
 * writes it — the sample below is that encoder's actual output, not a
 * hand-written approximation — because the whole point of reading fields out of
 * a document rather than out of a draft is that most of the documents an
 * approver sees were never authored in this console.
 */
import { describe, expect, it } from 'vitest'
import { diffDocuments, readDocumentFields, labelFor, countChanged } from './document'

/** internal/policy's canonical output for the repository's sample policy. */
const CANONICAL = `apiVersion: stamp/v1
kind: Policy
id: high-value-transfer
subject: user
resource: transfer
actions: [approve]
condition:
  all:
    - left: {field: resource.amount}
      op: gt
      right: 10000.0
    - left: {field: subject.department}
      not_in: [contractors]
challenges:
  - type: quorum
    threshold: 2
    approvers: {members: [alice, bob, carol]}
  - type: mfa
`

describe('reading a document\'s fields', () => {
  it('reads nested maps and sequences by pointer', () => {
    const byPointer = new Map(readDocumentFields(CANONICAL).map((f) => [f.pointer, f.value]))

    expect(byPointer.get('/id')).toBe('high-value-transfer')
    expect(byPointer.get('/actions')).toBe('[approve]')
    expect(byPointer.get('/condition/all/0/op')).toBe('gt')
    expect(byPointer.get('/condition/all/0/left')).toBe('{field: resource.amount}')
    expect(byPointer.get('/condition/all/1/not_in')).toBe('[contractors]')
    expect(byPointer.get('/challenges/0/threshold')).toBe('2')
    expect(byPointer.get('/challenges/1/type')).toBe('mfa')
  })

  it('a scalar sequence item is its own value', () => {
    const fields = readDocumentFields('actions:\n  - approve\n  - reject\n')
    expect(fields.map((f) => [f.pointer, f.value])).toEqual([
      ['/actions/0', 'approve'],
      ['/actions/1', 'reject'],
    ])
  })

  it('a second document after the separator gets pointers that do not collide', () => {
    const fields = readDocumentFields('id: a\n---\nid: b\n')
    expect(fields.map((f) => f.pointer)).toEqual(['/id', '/1/id'])
  })

  it('turns a pointer into a name a person reads', () => {
    expect(labelFor('/challenges/0/threshold')).toBe('challenges[0].threshold')
    expect(labelFor('/id')).toBe('id')
    expect(labelFor('')).toBe('(document)')
  })
})

describe('the document diff', () => {
  it('classifies only the changed field as changed and leaves the rest unchanged', () => {
    const after = CANONICAL.replace('threshold: 2', 'threshold: 3')
    const changes = diffDocuments(CANONICAL, after)

    const changed = changes.filter((c) => c.kind !== 'unchanged')
    expect(changed).toHaveLength(1)
    expect(changed[0]).toMatchObject({
      pointer: '/challenges/0/threshold',
      kind: 'changed',
      before: '2',
      after: '3',
    })
    // The rest of the policy is still in the result, marked unchanged, so a
    // caller that wants context has it without a second read.
    expect(changes.length).toBeGreaterThan(1)
  })

  it('the whole document is added or removed when one side is missing', () => {
    const added = diffDocuments(undefined, CANONICAL)
    expect(added.every((c) => c.kind === 'added')).toBe(true)
    expect(countChanged(added)).toBe(added.length)

    const removed = diffDocuments(CANONICAL, undefined)
    expect(removed.every((c) => c.kind === 'removed')).toBe(true)
  })

  it('tells an added field from a removed one', () => {
    const before = 'id: a\ndescription: text\n'
    const after = 'id: a\nsubject: user\n'
    const changes = diffDocuments(before, after)
    const byPointer = new Map(changes.map((c) => [c.pointer, c.kind]))
    expect(byPointer.get('/id')).toBe('unchanged')
    expect(byPointer.get('/description')).toBe('removed')
    expect(byPointer.get('/subject')).toBe('added')
  })

  it('a removed field stays where it was, so document order survives', () => {
    const before = 'a: 1\nb: 2\nc: 3\n'
    const after = 'a: 1\nc: 3\n'
    expect(diffDocuments(before, after).map((c) => c.pointer)).toEqual(['/a', '/b', '/c'])
  })

  it('does not drop a line it cannot parse', () => {
    // A document written by something other than the two canonical writers
    // still has to be shown. Dropping a line an approver was meant to read is
    // the failure direction this must not take.
    const fields = readDocumentFields('id: a\n>>> unparsable line\n')
    expect(fields.some((f) => f.value === '>>> unparsable line')).toBe(true)
  })
})
