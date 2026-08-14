import { describe, expect, it } from 'vitest'
import { defaultLanding, rolesFromClaims } from './roles'

describe('deriving roles from a token claim', () => {
  it('reads an array claim', () => {
    const roles = rolesFromClaims({ roles: ['author', 'auditor'] }, 'roles')
    expect([...roles].sort()).toEqual(['auditor', 'author'])
  })

  it('reads a space separated string claim', () => {
    expect([...rolesFromClaims({ groups: 'approver auditor' }, 'groups')].sort()).toEqual([
      'approver',
      'auditor',
    ])
  })

  it('strips the namespace prefix', () => {
    expect([...rolesFromClaims({ roles: ['stamp:approver'] }, 'roles')]).toEqual(['approver'])
  })

  it('an unrecognised value becomes no role at all', () => {
    // The failure direction: an unrecognised group grants nothing.
    expect(rolesFromClaims({ roles: ['admin', 'root', '*'] }, 'roles').size).toBe(0)
  })

  it('reads only the configured claim name', () => {
    expect(rolesFromClaims({ roles: ['author'] }, 'groups').size).toBe(0)
  })
})

describe('the default landing', () => {
  it('the policy list when the token can author', () => {
    expect(defaultLanding(new Set(['author', 'approver', 'auditor']))).toBe('/policies')
  })

  it('the approval inbox when the token cannot author but can approve', () => {
    expect(defaultLanding(new Set(['approver', 'auditor']))).toBe('/inbox')
  })

  it('audit when the token can only audit', () => {
    expect(defaultLanding(new Set(['auditor']))).toBe('/audit')
  })

  it('the screen that explains the reason when the token has no role', () => {
    expect(defaultLanding(new Set())).toBe('/no-access')
  })
})
