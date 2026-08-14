/**
 * The shapes the audit console reads.
 *
 * Read-only mirrors of api.AuditDecisionRow, api.AuditDecisionListResponse and
 * api.AuditDecisionDetail. The frozen JSON members arrive as `unknown` because
 * that is what they are — a request body and a fact snapshot are whatever the
 * caller sent, and the audit view renders them as text rather than reading
 * fields out of them.
 */

/** api.AuditDecisionRow. */
export interface AuditDecisionRow {
  readonly id: string
  readonly caller_id: string
  readonly policy_id: string
  readonly policy_version: number
  readonly subject_id: string
  readonly resource_id: string
  readonly action: string
  readonly state: string
  readonly created_at: string
  readonly expires_at: string
  readonly resolved_at?: string
}

/** api.AuditQueryEcho — the axes as the server parsed them. */
export interface AuditQueryEcho {
  readonly from?: string
  readonly to?: string
  readonly policy?: string
  readonly subject?: string
  readonly state?: string
  readonly limit: number
  readonly order: string
}

/** api.AuditDecisionListResponse. */
export interface AuditDecisionListResponse {
  readonly decisions: readonly AuditDecisionRow[]
  readonly next_cursor?: string
  readonly query: AuditQueryEcho
}

/** api.AuditChallenge. */
export interface AuditChallenge {
  readonly ordinal: number
  readonly kind: string
  readonly state: string
  readonly deadline?: string
  readonly satisfied_at?: string
}

/** api.AuditApproval. */
export interface AuditApproval {
  readonly ordinal: number
  readonly approver_id: string
  readonly verdict: string
  readonly binding_hash: string
  readonly submitted_at: string
}

/** api.AuditDecisionDetail. */
export interface AuditDecisionDetail extends AuditDecisionRow {
  readonly request: unknown
  readonly fact_snapshot: unknown
  readonly obligations: unknown
  readonly policy_document: string
  readonly policy_origin: string
  readonly challenges: readonly AuditChallenge[]
  readonly approvals: readonly AuditApproval[]
  readonly via_auditor_standing: boolean
}

/** The four axes, as the screen holds them. */
export interface AuditQuery {
  readonly from: string
  readonly to: string
  readonly policy: string
  readonly subject: string
  readonly state: string
}

export const EMPTY_QUERY: AuditQuery = { from: '', to: '', policy: '', subject: '', state: '' }

/** The decision states, for the state axis. */
export const DECISION_STATES = ['pending', 'allowed', 'denied', 'expired', 'cancelled'] as const

export const STATE_LABELS: Readonly<Record<string, string>> = {
  pending: 'Pending',
  allowed: 'Allowed',
  denied: 'Denied',
  expired: 'Expired',
  cancelled: 'Cancelled',
}
