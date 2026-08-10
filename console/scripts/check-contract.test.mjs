/**
 * A check nobody has watched fail is a check nobody knows still works.
 *
 * Each case below feeds the boundary checker a directory that reproduces one
 * way D19's promise breaks, and asserts the rule that is supposed to catch it
 * actually does. The compliant fixture is the control: without it, a checker
 * that reported everything would pass every one of these.
 */
import { describe, expect, it } from 'vitest'
import { checkConsole, loadContract } from './check-contract.mjs'

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
