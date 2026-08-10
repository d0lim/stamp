/**
 * A draft that exercises every shape the AST has, for the tests.
 *
 * It is deliberately the AuthZEN interop scenario's schema and one of its
 * policies (testdata/conformance/policies), plus a quorum challenge. Reusing a
 * set that already exists in the repository means the golden document below can
 * be read against a document the Go side already round-trips, rather than
 * against something invented here to match whatever this serializer happens to
 * emit.
 */
import type { Draft } from './model'

/**
 * The same draft with five different mistakes in it, one per shape of failure
 * the validator reports at a distinct pointer.
 *
 * It exists so that the pointers this console renders can be compared against
 * the pointers internal/policy actually emits, rather than against the console's
 * own idea of what they should be.
 */
export function brokenDraft(): Draft {
  const base = sampleDraft()
  return {
    ...base,
    policy: {
      ...base.policy,
      // An entity type nobody declared.
      resource: 'ledger',
      // An action nobody declared.
      actions: ['can_wire_money'],
      condition: {
        kind: 'logic',
        op: 'all',
        operands: [
          {
            // An attribute the declared entity does not have.
            kind: 'compare',
            left: { kind: 'field', role: 'subject', attribute: 'department' },
            op: 'eq',
            right: { kind: 'literal', type: 'string', values: ['ops'] },
          },
          {
            // A string field compared against an int constant.
            kind: 'compare',
            left: { kind: 'field', role: 'subject', attribute: 'id' },
            op: 'eq',
            right: { kind: 'literal', type: 'int', values: ['7'] },
          },
        ],
      },
      challenges: [
        {
          type: 'quorum',
          threshold: 0,
          approvers: {
            mode: 'members',
            members: ['alice'],
            claim: '',
            source: { kind: 'source', name: '', args: [] },
          },
        },
      ],
    },
  }
}

export function sampleDraft(): Draft {
  return {
    schema: {
      entities: [
        { name: 'user', attributes: [{ name: 'id', type: 'string' }] },
        {
          name: 'todo',
          attributes: [
            { name: 'id', type: 'string' },
            { name: 'owner_id', type: 'string' },
          ],
        },
      ],
      actions: [
        { name: 'can_update_todo', description: '' },
        { name: 'can_delete_todo', description: '할 일을 지운다' },
      ],
      sources: [
        {
          name: 'role_members',
          kind: 'http',
          params: [{ name: 'role', type: 'string' }],
          returns: 'list<string>',
          onError: 'deny',
        },
        {
          name: 'user_email',
          kind: 'http',
          params: [{ name: 'user_id', type: 'string' }],
          returns: 'string',
          onError: 'deny',
        },
      ],
    },
    policy: {
      id: 'todo.owner-write',
      description: '편집자는 자기 소유의 할 일을 고칠 수 있다',
      subject: 'user',
      resource: 'todo',
      context: '',
      actions: ['can_update_todo', 'can_delete_todo'],
      condition: {
        kind: 'logic',
        op: 'all',
        operands: [
          {
            kind: 'member',
            left: { kind: 'field', role: 'subject', attribute: 'id' },
            collection: {
              kind: 'source',
              name: 'role_members',
              args: [{ kind: 'literal', type: 'string', values: ['editor'] }],
            },
            negate: false,
          },
          {
            kind: 'compare',
            left: {
              kind: 'source',
              name: 'user_email',
              args: [{ kind: 'field', role: 'subject', attribute: 'id' }],
            },
            op: 'eq',
            right: { kind: 'field', role: 'resource', attribute: 'owner_id' },
          },
        ],
      },
      challenges: [
        {
          type: 'quorum',
          threshold: 2,
          approvers: {
            mode: 'members',
            members: ['alice', 'bob'],
            claim: '',
            source: { kind: 'source', name: '', args: [] },
          },
        },
      ],
    },
  }
}
