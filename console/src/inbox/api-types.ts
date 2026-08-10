/**
 * The shapes the approval endpoints return.
 *
 * Like `builder/api-types.ts` these are read-only mirrors of Go types —
 * api.InboxResponse, challenge.InboxItem, challenge.QuorumReview,
 * decision.Result — declared rather than inferred so that a field the console
 * reads is a field somebody wrote down. Nothing here validates a response; the
 * contract check already fixes which endpoint produced it.
 */

/** challenge.ResolutionMode. */
export type ResolutionMode = 'members' | 'claim' | 'source'

/** challenge.InboxItem. */
export interface InboxItem {
  readonly decision_id: string
  readonly ordinal: number
  readonly policy_id: string
  readonly subject_id: string
  readonly resource_id: string
  readonly action: string
  readonly have: number
  readonly need: number
  readonly mode: ResolutionMode
  readonly submitted: boolean
  readonly created_at: string
  readonly expires_at: string
}

/** api.InboxResponse. */
export interface InboxResponse {
  readonly items: readonly InboxItem[]
  /** The server's clock. Time remaining is computed against this, never the browser's. */
  readonly server_time: string
}

/** challenge.QuorumReviewDecision — the decision as it was frozen. */
export interface ReviewDecision {
  readonly id: string
  readonly caller_id: string
  readonly subject_id: string
  readonly resource_id: string
  readonly action: string
  readonly policy_id: string
  readonly request: unknown
  readonly fact_snapshot: unknown
  readonly obligations: unknown
  readonly created_at: string
  readonly expires_at: string
}

/** challenge.QuorumReview. */
export interface QuorumReview {
  readonly ordinal: number
  readonly state: string
  readonly have: number
  readonly need: number
  readonly approvers?: readonly string[]
  readonly mode: ResolutionMode
  readonly issuer: string
  readonly claim?: string
  readonly source?: string
  /** R31's digest. It is echoed back on submission, verbatim. */
  readonly binding_hash: string
  readonly decision: ReviewDecision
}

/** decision.ChallengeView. */
export interface ChallengeView {
  readonly ordinal: number
  readonly kind: string
  readonly state: string
  readonly have?: number
  readonly need?: number
  readonly deadline?: string
}

/** decision.Result, as a submission returns it. */
export interface DecisionResult {
  readonly id?: string
  readonly state: string
  readonly reason: string
  readonly challenges?: readonly ChallengeView[]
  readonly expires_at?: string
}
