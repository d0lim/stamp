/**
 * A check nobody has watched fail is a check nobody knows still works.
 *
 * Each case below feeds the boundary checker a directory that reproduces one
 * way D19's promise breaks, and asserts the rule that is supposed to catch it
 * actually does. The compliant fixture is the control: without it, a checker
 * that reported everything would pass every one of these.
 */
import { describe, expect, it } from 'vitest'
import {
  checkConsole,
  checkErrorVocabulary,
  loadConsumedErrorCodes,
  loadContract,
  loadErrorCodeExemptions,
  loadServedErrorCodes,
  parseErrorCodeExemptions,
} from './check-contract.mjs'

const FIXTURES = 'scripts/__fixtures__'

function check(fixture) {
  return checkConsole({ scanDir: `${FIXTURES}/${fixture}` })
}

describe('콘솔 계약 경계 검사', () => {
  it('공개 계약 안의 호출만 있는 코드는 통과한다', () => {
    expect(check('compliant')).toEqual([])
  })

  it('실제 콘솔 소스에 위반이 없다', () => {
    const violations = checkConsole({ scanDir: 'src' })
    expect(violations, JSON.stringify(violations, null, 2)).toEqual([])
  })

  it('계약에 없는 엔드포인트를 부르면 실패한다', () => {
    const violations = check('violating-undeclared-endpoint')
    expect(violations).toHaveLength(1)
    expect(violations[0].rule).toBe('contract')
    expect(violations[0].message).toContain('console-inbox-summary')
  })

  it('클라이언트 밖의 raw fetch는 실패한다', () => {
    const violations = check('violating-raw-fetch')
    expect(violations.map((v) => v.rule)).toContain('seam')
  })

  it('localStorage나 질의 문자열에서 기준 주소를 읽으면 실패한다', () => {
    const violations = check('violating-config-source')
    const rules = violations.map((v) => v.rule)
    expect(rules).toContain('origin')
    // Both channels are caught, not just the first one encountered.
    expect(violations.filter((v) => v.rule === 'origin').length).toBeGreaterThanOrEqual(2)
    expect(violations.some((v) => v.message.includes('localStorage'))).toBe(true)
    expect(violations.some((v) => v.message.includes('location.search'))).toBe(true)
  })

  it('소스에 박힌 절대 주소는 실패한다', () => {
    const violations = check('violating-absolute-url')
    expect(violations).toHaveLength(1)
    expect(violations[0].rule).toBe('contract')
    expect(violations[0].message).toContain('telemetry.example.net')
  })

  it('런타임에 계산한 엔드포인트 이름은 실패한다', () => {
    const violations = check('violating-computed-endpoint')
    expect(violations).toHaveLength(1)
    expect(violations[0].rule).toBe('contract')
    expect(violations[0].message).toContain('문자열 리터럴')
  })

  it('응답 본문의 error 코드를 다른 모듈에서 읽으면 실패한다', () => {
    const violations = check('violating-error-code-read')
    const codes = violations.filter((v) => v.rule === 'codes')
    // Three ways out of the one module, and all three are caught: the inline
    // shape, the declared ErrorResponse, and the `any` that would slip past a
    // rule written only against type literals.
    expect(codes.length).toBeGreaterThanOrEqual(3)
    expect(codes.every((v) => v.message.includes('error-codes.ts'))).toBe(true)
  })

  it('계약 문서는 Go가 생성한 것과 같은 버전을 쓴다', () => {
    const contract = loadContract()
    expect(contract.version).toBe(1)
    // The names the console addresses endpoints by are the Go route names.
    expect(contract.names.has('policy-list')).toBe(true)
    expect(contract.names.has('approval-submit')).toBe(true)
    // The serving documents are not callable API endpoints.
    expect(contract.names.has('console-config')).toBe(false)
  })
})

/**
 * The two-way error code comparison.
 *
 * The interesting cases are the planted ones. A comparison that has only ever
 * been run against a tree it agrees with is not known to compare anything, and
 * this one was written because a comparison nobody was running let a dead
 * `not_an_approver` branch survive a release.
 *
 * The inputs are handed in rather than read off disk, so each case is one
 * disagreement and nothing else. The real tree is checked too, by the first
 * case, which is the control: if the comparison had stopped reporting
 * altogether, everything below would still pass and only that one would notice
 * nothing had changed.
 */
describe('error 코드 어휘 대조', () => {
  const served = new Map([
    ['expired', { statuses: [409], surfaces: ['console'] }],
    ['not_found', { statuses: [404], surfaces: ['console', 'pep'] }],
    ['rejected', { statuses: [403], surfaces: ['callback'] }],
    ['unauthenticated', { statuses: [401], surfaces: ['callback', 'console', 'pep'] }],
  ])
  const exemptions = (entries) => parseErrorCodeExemptions({ version: 1, codes: entries })
  const compare = (consumed, entries) =>
    checkErrorVocabulary({
      served,
      consumed: new Set(consumed),
      exemptions: exemptions(entries),
    })

  const covering = [{ reason: '상태 코드가 답이다.', codes: ['rejected', 'unauthenticated'] }]

  it('현행 트리는 양방향으로 일치한다', () => {
    const violations = checkErrorVocabulary()
    expect(violations, JSON.stringify(violations, null, 2)).toEqual([])
  })

  it('두 쪽 다 아무 문제 없는 입력은 통과한다', () => {
    expect(compare(['expired', 'not_found'], covering)).toEqual([])
  })

  it('콘솔에만 있는 코드는 실패하고 그 코드를 이름한다', () => {
    const violations = compare(['expired', 'not_found', 'not_an_approver'], covering)
    expect(violations).toHaveLength(1)
    expect(violations[0].message).toContain('not_an_approver')
    expect(violations[0].message).toContain('죽은 분기')
  })

  it('콘솔이 부르지 않는 리스너의 코드를 분기하면 실패한다', () => {
    const violations = compare(['expired', 'not_found', 'rejected'], [
      { reason: '상태 코드가 답이다.', codes: ['unauthenticated'] },
    ])
    expect(violations).toHaveLength(1)
    expect(violations[0].message).toContain('rejected')
    expect(violations[0].message).toContain('callback')
  })

  it('서버에만 있는 코드는 면제되지 않으면 실패한다', () => {
    const violations = compare(['expired', 'not_found'], [
      { reason: '상태 코드가 답이다.', codes: ['unauthenticated'] },
    ])
    expect(violations).toHaveLength(1)
    expect(violations[0].message).toContain('rejected')
    expect(violations[0].message).toContain('콘솔에 처리가 없습니다')
  })

  it('면제 목록의 코드는 실패시키지 않는다', () => {
    expect(compare(['expired', 'not_found'], covering)).toEqual([])
  })

  it('서버가 더 이상 내지 않는 코드의 면제는 실패한다', () => {
    const violations = compare(['expired', 'not_found'], [
      { reason: '상태 코드가 답이다.', codes: ['rejected', 'unauthenticated', 'not_an_approver'] },
    ])
    expect(violations).toHaveLength(1)
    expect(violations[0].message).toContain('not_an_approver')
    expect(violations[0].message).toContain('오래 살았습니다')
  })

  it('콘솔이 처리하는 코드의 면제는 실패한다', () => {
    const violations = compare(['expired', 'not_found'], [
      { reason: '상태 코드가 답이다.', codes: ['rejected', 'unauthenticated', 'expired'] },
    ])
    expect(violations).toHaveLength(1)
    expect(violations[0].message).toContain('expired')
    expect(violations[0].message).toContain('둘 중 하나는 거짓')
  })

  it('이유 없는 면제는 실패한다', () => {
    const violations = compare(['expired', 'not_found'], [
      { reason: '   ', codes: ['rejected', 'unauthenticated'] },
    ])
    expect(violations.some((v) => v.message.includes('이유가 없습니다'))).toBe(true)
  })

  it('한 코드가 두 묶음에 면제로 적히면 실패한다', () => {
    const violations = compare(['expired', 'not_found'], [
      { reason: '첫째 이유.', codes: ['rejected', 'unauthenticated'] },
      { reason: '둘째 이유.', codes: ['rejected'] },
    ])
    expect(violations.some((v) => v.message.includes('두 묶음에'))).toBe(true)
  })

  it('콘솔의 어휘는 선언 모듈에서 정적으로 읽힌다', () => {
    const consumed = loadConsumedErrorCodes()
    expect(consumed.has('not_found')).toBe(true)
    expect(consumed.has('rate_limited')).toBe(true)
    // The code #51 deleted. If it ever comes back into the module without
    // coming back into the server, the first case in this block fails.
    expect(consumed.has('not_an_approver')).toBe(false)
    // The comment in src/api/error-codes.ts names `not_an_approver` twice and
    // the tests below stub several codes. A grep would have found them; the
    // parser does not.
    expect(consumed.size).toBe(6)
  })

  it('정적으로 읽을 수 없는 어휘 선언은 거절된다', () => {
    expect(() =>
      loadConsumedErrorCodes(undefined, 'scripts/__fixtures__/error-codes-computed/error-codes.ts'),
    ).toThrow(/배열 리터럴/)
  })

  it('서버 문서와 면제 목록은 디스크에서 읽힌다', () => {
    const document = loadServedErrorCodes()
    expect(document.size).toBeGreaterThan(0)
    expect(document.get('not_found').surfaces).toContain('console')
    const { exempt, problems } = loadErrorCodeExemptions()
    expect(problems).toEqual([])
    expect(exempt.size).toBeGreaterThan(0)
    for (const [, reason] of exempt) expect(reason.length).toBeGreaterThan(0)
  })
})
