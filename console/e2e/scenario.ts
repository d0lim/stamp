/**
 * The engine, as the end-to-end page sees it.
 *
 * One stub for every endpoint the three screens call, answering the way a real
 * deployment would: a policy set with one policy, a governance mode of quorum,
 * an inbox with one twelve-policy revision waiting, and the audit history that
 * decision lands in.
 *
 * It is a stub rather than a live engine on purpose. This suite exists to run
 * axe in a real browser — contrast is the check jsdom cannot do — and to walk
 * the two round trips end to end. Standing up Postgres to do that would make
 * the accessibility gate depend on a database being reachable, which is how a
 * gate stops running.
 */

const DECISION_ID = '3f1b0f2a-0000-4000-8000-000000000001'
const PROPOSAL_ID = 'rev-e2e-1'
const DELTA_DIGEST = 'd1ge57'
const SERVER_NOW = '2026-08-10T12:00:00Z'

/** The identifiers the specs navigate to. */
export const IDS = { decision: DECISION_ID, proposal: PROPOSAL_ID, serverNow: SERVER_NOW }

function policyDocument(id: string, threshold: number, description: string): string {
  return [
    'apiVersion: stamp/v1',
    'kind: Policy',
    `id: ${id}`,
    `description: ${description}`,
    'subject: user',
    'resource: transfer',
    'actions: [approve]',
    'condition:',
    '  all:',
    '    - left: {field: resource.amount}',
    '      op: gt',
    '      right: 10000.0',
    'challenges:',
    '  - type: quorum',
    `    threshold: ${threshold}`,
    '',
  ].join('\n')
}

const DELTA = {
  changes: Array.from({ length: 12 }, (_, index) => ({
    kind: 'modify' as const,
    policy_id: `policy-${index}`,
    before: policyDocument(`policy-${index}`, 3, `이전 ${index}`),
    after: policyDocument(`policy-${index}`, index === 0 ? 1 : 3, `개정 ${index}`),
  })),
}

const FINDINGS = [
  { subject: 'policy-0', reason: 'quorum_lowered', detail: '정족수가 3에서 1로 낮아집니다' },
]

const AUDIT_ROW = {
  id: DECISION_ID,
  caller_id: 'workload:https://idp.test#payments',
  policy_id: 'stamp.governance',
  policy_version: 3,
  subject_id: 'alice',
  resource_id: 'default',
  action: 'policy.revise',
  state: 'pending',
  created_at: '2026-08-10T11:00:00Z',
  expires_at: '2026-08-10T13:00:00Z',
}

const RESPONSES: Readonly<Record<string, unknown>> = {
  '/policies': {
    policies: [
      {
        id: 'policy-0',
        version: 3,
        origin: 'form',
        reserved: false,
        document: policyDocument('policy-0', 3, '이전 0'),
      },
    ],
  },
  '/governance': { mode: 'quorum' },
  '/decisions/inbox': {
    items: [
      {
        decision_id: DECISION_ID,
        ordinal: 0,
        policy_id: 'stamp.governance',
        subject_id: 'alice',
        resource_id: 'default',
        action: 'policy.revise',
        have: 1,
        need: 2,
        mode: 'members',
        submitted: false,
        created_at: '2026-08-10T11:00:00Z',
        expires_at: '2026-08-10T13:00:00Z',
      },
    ],
    server_time: SERVER_NOW,
  },
  '/audit/decisions': {
    decisions: [AUDIT_ROW],
    query: { limit: 50, order: 'created_at desc' },
  },
}

const REVIEW = {
  ordinal: 0,
  state: 'pending',
  have: 1,
  need: 2,
  approvers: ['bob', 'carol'],
  mode: 'members',
  issuer: 'https://idp.test',
  binding_hash: 'f00dbabe0000000000000000000000000000000000000000000000000000cafe',
  decision: {
    id: DECISION_ID,
    caller_id: 'stamp',
    subject_id: 'alice',
    resource_id: 'default',
    action: 'policy.revise',
    policy_id: 'stamp.governance',
    request: {
      action: 'policy.revise',
      subject: { type: 'admin', id: 'alice' },
      resource: { type: 'policy_set', id: 'default' },
      context: {
        type: 'revision',
        id: PROPOSAL_ID,
        attributes: { delta_digest: DELTA_DIGEST, weakening: true, change_count: 12 },
      },
    },
    // The payload the audit and approval screens have to render inert.
    fact_snapshot: { note: '<script>alert(1)</script>', risk: 0.42 },
    obligations: [{ type: 'notify', attributes: { channel: '#sec' } }],
    created_at: '2026-08-10T11:00:00Z',
    expires_at: '2026-08-10T13:00:00Z',
  },
}

const PROPOSAL = {
  id: PROPOSAL_ID,
  decision_id: DECISION_ID,
  proposer_id: 'alice',
  delta: DELTA,
  delta_digest: DELTA_DIGEST,
  application_mode: 'revaluate',
  state: 'pending',
  weakening: true,
  findings: FINDINGS,
  threshold: 2,
  created_at: '2026-08-10T11:00:00Z',
}

const AUDIT_DETAIL = {
  ...AUDIT_ROW,
  request: REVIEW.decision.request,
  fact_snapshot: REVIEW.decision.fact_snapshot,
  obligations: REVIEW.decision.obligations,
  policy_document: policyDocument('stamp.governance', 2, '거버넌스 정책'),
  policy_origin: 'form',
  challenges: [{ ordinal: 0, kind: 'quorum', state: 'pending' }],
  approvals: [
    {
      ordinal: 0,
      approver_id: 'bob',
      verdict: 'approve',
      binding_hash: REVIEW.binding_hash,
      submitted_at: '2026-08-10T11:20:00Z',
    },
  ],
  via_auditor_standing: true,
}

const PREVIEW = {
  mode: 'quorum',
  weakening: true,
  findings: FINDINGS,
  threshold: 2,
  approvers: ['bob', 'carol'],
  exclude_proposer: true,
  affected_decisions: 3,
}

/** A fetch that answers the whole public contract this console calls. */
export function scenarioFetch(): typeof fetch {
  const impl = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), window.location.origin)
    const method = init?.method ?? 'GET'
    const answer = (status: number, payload: unknown) =>
      new Response(JSON.stringify(payload), {
        status,
        headers: { 'Content-Type': 'application/json' },
      })

    const path = url.pathname
    if (path === '/decisions/inbox') return answer(200, RESPONSES['/decisions/inbox'])
    if (path.endsWith('/approval')) return answer(200, REVIEW)
    if (path.endsWith('/approvals')) {
      return answer(200, {
        id: DECISION_ID,
        state: 'pending',
        reason: 'challenge_pending',
        challenges: [{ ordinal: 0, kind: 'quorum', state: 'pending', have: 2, need: 2 }],
      })
    }
    if (path === '/audit/decisions') return answer(200, RESPONSES['/audit/decisions'])
    if (path.startsWith('/audit/decisions/')) return answer(200, AUDIT_DETAIL)
    if (path.startsWith('/policies/revisions/')) return answer(200, PROPOSAL)
    if (path === '/policies/revisions/preview') return answer(200, PREVIEW)
    if (path === '/policies/revisions' && method === 'POST') return answer(202, PROPOSAL)
    if (path === '/policies') return answer(200, RESPONSES['/policies'])
    if (path === '/governance') return answer(200, RESPONSES['/governance'])
    if (path === '/console/v1/policies/dry-run') {
      return answer(200, {
        policy_id: 'policy-0',
        matched: true,
        holds: true,
        decision: 'allow',
        reason: '',
        conditions: [{ pointer: '/condition', kind: 'all', result: true }],
        challenges: [],
        stored: false,
      })
    }
    return answer(404, { error: 'not_found', message: `no stub for ${method} ${path}` })
  }
  return impl as unknown as typeof fetch
}
