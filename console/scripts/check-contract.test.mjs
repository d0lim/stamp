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
  calledEndpoints,
  checkConsole,
  checkEndpointCoverage,
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

describe('the console contract boundary check', () => {
  it('code whose calls are all inside the public contract passes', () => {
    expect(check('compliant')).toEqual([])
  })

  it('the real console source has no violations', () => {
    const violations = checkConsole({ scanDir: 'src' })
    expect(violations, JSON.stringify(violations, null, 2)).toEqual([])
  })

  it('calling an endpoint that is not in the contract fails', () => {
    const violations = check('violating-undeclared-endpoint')
    expect(violations).toHaveLength(1)
    expect(violations[0].rule).toBe('contract')
    expect(violations[0].message).toContain('console-inbox-summary')
  })

  it('a raw fetch outside the client fails', () => {
    const violations = check('violating-raw-fetch')
    expect(violations.map((v) => v.rule)).toContain('seam')
  })

  it('reading the base address from localStorage or the query string fails', () => {
    const violations = check('violating-config-source')
    const rules = violations.map((v) => v.rule)
    expect(rules).toContain('origin')
    // Both channels are caught, not just the first one encountered.
    expect(violations.filter((v) => v.rule === 'origin').length).toBeGreaterThanOrEqual(2)
    expect(violations.some((v) => v.message.includes('localStorage'))).toBe(true)
    expect(violations.some((v) => v.message.includes('location.search'))).toBe(true)
  })

  it('an absolute address hard-coded in the source fails', () => {
    const violations = check('violating-absolute-url')
    expect(violations).toHaveLength(1)
    expect(violations[0].rule).toBe('contract')
    expect(violations[0].message).toContain('telemetry.example.net')
  })

  it('an endpoint name computed at runtime fails', () => {
    const violations = check('violating-computed-endpoint')
    expect(violations).toHaveLength(1)
    expect(violations[0].rule).toBe('contract')
    expect(violations[0].message).toContain('string literal')
  })

  it('reading the response body error code from another module fails', () => {
    const violations = check('violating-error-code-read')
    const codes = violations.filter((v) => v.rule === 'codes')
    // Three ways out of the one module, and all three are caught: the inline
    // shape, the declared ErrorResponse, and the `any` that would slip past a
    // rule written only against type literals.
    expect(codes.length).toBeGreaterThanOrEqual(3)
    expect(codes.every((v) => v.message.includes('error-codes.ts'))).toBe(true)
  })

  it('the contract document states the same version Go generated', () => {
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
describe('the error code vocabulary comparison', () => {
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

  const covering = [{ reason: 'the status is the answer.', codes: ['rejected', 'unauthenticated'] }]

  it('the current tree agrees in both directions', () => {
    const violations = checkErrorVocabulary()
    expect(violations, JSON.stringify(violations, null, 2)).toEqual([])
  })

  it('input with nothing wrong on either side passes', () => {
    expect(compare(['expired', 'not_found'], covering)).toEqual([])
  })

  it('a code the console alone has fails, and is named', () => {
    const violations = compare(['expired', 'not_found', 'not_an_approver'], covering)
    expect(violations).toHaveLength(1)
    expect(violations[0].message).toContain('not_an_approver')
    expect(violations[0].message).toContain('dead branch')
  })

  it('branching on a code from a listener the console never calls fails', () => {
    const violations = compare(['expired', 'not_found', 'rejected'], [
      { reason: 'the status is the answer.', codes: ['unauthenticated'] },
    ])
    expect(violations).toHaveLength(1)
    expect(violations[0].message).toContain('rejected')
    expect(violations[0].message).toContain('callback')
  })

  it('a code the server alone has fails unless it is exempted', () => {
    const violations = compare(['expired', 'not_found'], [
      { reason: 'the status is the answer.', codes: ['unauthenticated'] },
    ])
    expect(violations).toHaveLength(1)
    expect(violations[0].message).toContain('rejected')
    expect(violations[0].message).toContain('the console does not handle it')
  })

  it('a code on the exemption list does not fail', () => {
    expect(compare(['expired', 'not_found'], covering)).toEqual([])
  })

  it('an exemption for a code the server no longer emits fails', () => {
    const violations = compare(['expired', 'not_found'], [
      { reason: 'the status is the answer.', codes: ['rejected', 'unauthenticated', 'not_an_approver'] },
    ])
    expect(violations).toHaveLength(1)
    expect(violations[0].message).toContain('not_an_approver')
    expect(violations[0].message).toContain('outlived')
  })

  it('an exemption for a code the console handles fails', () => {
    const violations = compare(['expired', 'not_found'], [
      { reason: 'the status is the answer.', codes: ['rejected', 'unauthenticated', 'expired'] },
    ])
    expect(violations).toHaveLength(1)
    expect(violations[0].message).toContain('expired')
    expect(violations[0].message).toContain('one of the two is false')
  })

  it('an exemption with no reason fails', () => {
    const violations = compare(['expired', 'not_found'], [
      { reason: '   ', codes: ['rejected', 'unauthenticated'] },
    ])
    expect(violations.some((v) => v.message.includes('states no reason'))).toBe(true)
  })

  it('one code exempted in two groups fails', () => {
    const violations = compare(['expired', 'not_found'], [
      { reason: 'the first reason.', codes: ['rejected', 'unauthenticated'] },
      { reason: 'the second reason.', codes: ['rejected'] },
    ])
    expect(violations.some((v) => v.message.includes('in two groups'))).toBe(true)
  })

  it("the console's vocabulary is read statically from the declaring module", () => {
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

  it('a vocabulary declaration that cannot be read statically is refused', () => {
    expect(() =>
      loadConsumedErrorCodes(undefined, 'scripts/__fixtures__/error-codes-computed/error-codes.ts'),
    ).toThrow(/array literal/)
  })

  it('the server document and the exemption list are read from disk', () => {
    const document = loadServedErrorCodes()
    expect(document.size).toBeGreaterThan(0)
    expect(document.get('not_found').surfaces).toContain('console')
    const { exempt, problems } = loadErrorCodeExemptions()
    expect(problems).toEqual([])
    expect(exempt.size).toBeGreaterThan(0)
    for (const [, reason] of exempt) expect(reason.length).toBeGreaterThan(0)
  })
})

/**
 * The declared surface against the one the console actually calls.
 *
 * `delay-cancel` is why this exists: it is in the public contract, the server
 * grew a budget, a 429 and a Retry-After for it, and no screen calls it — a
 * fact nobody had written down, so nobody knew it. The comparison is
 * bidirectional because a one-way check would let the written list be wrong in
 * the same direction as the thing it describes.
 */
describe('surfaces the console does not call', () => {
  const declared = { names: new Set(['policy-list', 'delay-cancel', 'schema-read']) }
  const compare = (called, entries) =>
    checkEndpointCoverage({
      contract: declared,
      called: new Set(called),
      unimplemented: new Map(entries),
    })

  it('in the current tree the contract and the screens agree', () => {
    const violations = checkEndpointCoverage()
    expect(violations, JSON.stringify(violations, null, 2)).toEqual([])
  })

  it('what is called plus what is written down covering the contract passes', () => {
    expect(
      compare(['policy-list'], [
        ['delay-cancel', 'there is no screen.'],
        ['schema-read', 'the builder starts from an empty schema.'],
      ]),
    ).toEqual([])
  })

  it('an endpoint nobody calls and nobody wrote down fails', () => {
    const violations = compare(['policy-list'], [['delay-cancel', 'there is no screen.']])
    expect(violations).toHaveLength(1)
    expect(violations[0].rule).toBe('coverage')
    expect(violations[0].message).toContain('schema-read')
  })

  it('an endpoint the console actually calls but is written down as unimplemented fails', () => {
    const violations = compare(['policy-list', 'schema-read'], [
      ['delay-cancel', 'there is no screen.'],
      ['schema-read', 'the builder starts from an empty schema.'],
    ])
    expect(violations).toHaveLength(1)
    expect(violations[0].message).toContain('actually calls')
  })

  it('a name that is not in the contract sitting on the unimplemented list fails', () => {
    const violations = compare(['policy-list'], [
      ['delay-cancel', 'there is no screen.'],
      ['schema-read', 'the builder starts from an empty schema.'],
      ['console-config', 'this is a serving document, not an API endpoint.'],
    ])
    expect(violations).toHaveLength(1)
    expect(violations[0].message).toContain('console-config')
  })

  it('an unimplemented entry with no reason fails', () => {
    const { problems } = parseErrorCodeExemptions({
      version: 1,
      codes: [],
      endpoints: [{ name: 'delay-cancel', reason: '  ' }],
    })
    expect(problems.some((p) => p.message.includes('with no reason'))).toBe(true)
  })

  it('the endpoints actually called are read statically from the source', () => {
    const called = calledEndpoints()
    expect(called.has('policy-list')).toBe(true)
    expect(called.has('approval-submit')).toBe(true)
    // The endpoint whose absence this whole block is about. It appears in
    // src/api/client.test.ts, which is not a call site — and the walk skips
    // tests, which is why it is not counted as one.
    expect(called.has('delay-cancel')).toBe(false)
  })
})
