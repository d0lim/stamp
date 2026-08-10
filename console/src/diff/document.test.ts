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

describe('문서 필드 읽기', () => {
  it('중첩 맵과 시퀀스를 포인터로 읽는다', () => {
    const byPointer = new Map(readDocumentFields(CANONICAL).map((f) => [f.pointer, f.value]))

    expect(byPointer.get('/id')).toBe('high-value-transfer')
    expect(byPointer.get('/actions')).toBe('[approve]')
    expect(byPointer.get('/condition/all/0/op')).toBe('gt')
    expect(byPointer.get('/condition/all/0/left')).toBe('{field: resource.amount}')
    expect(byPointer.get('/condition/all/1/not_in')).toBe('[contractors]')
    expect(byPointer.get('/challenges/0/threshold')).toBe('2')
    expect(byPointer.get('/challenges/1/type')).toBe('mfa')
  })

  it('스칼라 시퀀스 항목은 항목 자체가 값이다', () => {
    const fields = readDocumentFields('actions:\n  - approve\n  - reject\n')
    expect(fields.map((f) => [f.pointer, f.value])).toEqual([
      ['/actions/0', 'approve'],
      ['/actions/1', 'reject'],
    ])
  })

  it('문서 구분자 뒤의 두 번째 문서는 포인터가 겹치지 않는다', () => {
    const fields = readDocumentFields('id: a\n---\nid: b\n')
    expect(fields.map((f) => f.pointer)).toEqual(['/id', '/1/id'])
  })

  it('포인터를 사람이 읽는 이름으로 옮긴다', () => {
    expect(labelFor('/challenges/0/threshold')).toBe('challenges[0].threshold')
    expect(labelFor('/id')).toBe('id')
    expect(labelFor('')).toBe('(문서)')
  })
})

describe('문서 diff', () => {
  it('바뀐 필드만 수정으로 분류하고 나머지는 동일로 남긴다', () => {
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

  it('한쪽이 없으면 문서 전체가 추가이거나 삭제다', () => {
    const added = diffDocuments(undefined, CANONICAL)
    expect(added.every((c) => c.kind === 'added')).toBe(true)
    expect(countChanged(added)).toBe(added.length)

    const removed = diffDocuments(CANONICAL, undefined)
    expect(removed.every((c) => c.kind === 'removed')).toBe(true)
  })

  it('추가된 필드와 삭제된 필드를 구분한다', () => {
    const before = 'id: a\ndescription: 설명\n'
    const after = 'id: a\nsubject: user\n'
    const changes = diffDocuments(before, after)
    const byPointer = new Map(changes.map((c) => [c.pointer, c.kind]))
    expect(byPointer.get('/id')).toBe('unchanged')
    expect(byPointer.get('/description')).toBe('removed')
    expect(byPointer.get('/subject')).toBe('added')
  })

  it('삭제된 필드가 있던 자리에 남아 문서 순서가 보존된다', () => {
    const before = 'a: 1\nb: 2\nc: 3\n'
    const after = 'a: 1\nc: 3\n'
    expect(diffDocuments(before, after).map((c) => c.pointer)).toEqual(['/a', '/b', '/c'])
  })

  it('이해하지 못하는 줄도 버리지 않는다', () => {
    // A document written by something other than the two canonical writers
    // still has to be shown. Dropping a line an approver was meant to read is
    // the failure direction this must not take.
    const fields = readDocumentFields('id: a\n>>> 알 수 없는 줄\n')
    expect(fields.some((f) => f.value === '>>> 알 수 없는 줄')).toBe(true)
  })
})
