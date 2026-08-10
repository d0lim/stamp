import { describe, expect, it } from 'vitest'
import { defaultLanding, rolesFromClaims } from './roles'

describe('토큰 claim에서 역할 유도', () => {
  it('배열 claim을 읽는다', () => {
    const roles = rolesFromClaims({ roles: ['author', 'auditor'] }, 'roles')
    expect([...roles].sort()).toEqual(['auditor', 'author'])
  })

  it('공백으로 구분된 문자열 claim을 읽는다', () => {
    expect([...rolesFromClaims({ groups: 'approver auditor' }, 'groups')].sort()).toEqual([
      'approver',
      'auditor',
    ])
  })

  it('네임스페이스 접두사를 벗긴다', () => {
    expect([...rolesFromClaims({ roles: ['stamp:approver'] }, 'roles')]).toEqual(['approver'])
  })

  it('모르는 값은 역할이 되지 않는다', () => {
    // The failure direction: an unrecognised group grants nothing.
    expect(rolesFromClaims({ roles: ['admin', 'root', '*'] }, 'roles').size).toBe(0)
  })

  it('설정된 claim 이름만 본다', () => {
    expect(rolesFromClaims({ roles: ['author'] }, 'groups').size).toBe(0)
  })
})

describe('기본 랜딩', () => {
  it('저작 권한이 있으면 정책 목록', () => {
    expect(defaultLanding(new Set(['author', 'approver', 'auditor']))).toBe('/policies')
  })

  it('저작 권한이 없고 승인 권한이 있으면 승인함', () => {
    expect(defaultLanding(new Set(['approver', 'auditor']))).toBe('/inbox')
  })

  it('감사 권한만 있으면 감사', () => {
    expect(defaultLanding(new Set(['auditor']))).toBe('/audit')
  })

  it('역할이 없으면 사유 화면', () => {
    expect(defaultLanding(new Set())).toBe('/no-access')
  })
})
