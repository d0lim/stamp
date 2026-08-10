/**
 * The shapes the authoring endpoints return.
 *
 * These are read-only mirrors of Go types — api.PolicyListResponse,
 * api.DryRunResponse, api.GovernanceView, revision.Preview, revision.Proposal —
 * and they are typed here rather than inferred at each call site so that a field
 * the console reads is a field somebody wrote down. They are declarations, not
 * parsers: nothing here validates a response, because the contract check already
 * fixes which endpoint produced it.
 */
import type { Diagnostic } from './diagnostics'

/** store.Origin: which authoring path owns a policy. */
export type Origin = 'form' | 'file'

/** api.PolicyView. */
export interface PolicyView {
  readonly id: string
  readonly version: number
  readonly origin: Origin
  readonly reserved: boolean
  readonly document: string
}

/** api.PolicyListResponse. */
export interface PolicyListResponse {
  readonly policies: readonly PolicyView[]
}

/** engine.NodeTrace. Result is null when the node could not be evaluated. */
export interface NodeTrace {
  readonly pointer: string
  readonly kind: string
  readonly result: boolean | null
  readonly error?: string
}

/** api.ChallengeSummary. */
export interface ChallengeSummary {
  readonly type: string
  readonly detail?: Readonly<Record<string, unknown>>
}

/** api.DryRunResponse. */
export interface DryRunResponse {
  readonly policy_id: string
  readonly matched: boolean
  readonly holds: boolean
  readonly decision: string
  readonly reason: string
  readonly conditions: readonly NodeTrace[]
  readonly challenges: readonly ChallengeSummary[]
  readonly sources?: readonly string[]
  /** Always false. It is in the response so "stores nothing" is assertable. */
  readonly stored: boolean
  readonly error?: string
}

/** api.DiagnosticsResponse. */
export interface DiagnosticsResponse {
  readonly error: string
  readonly diagnostics: readonly Diagnostic[]
}

/** revision.Mode. */
export type GovernanceMode = 'solo_admin' | 'quorum'

/** revision.State. */
export type ProposalState = 'pending' | 'applied' | 'withdrawn' | 'rejected'

/** revision.Finding. */
export interface Finding {
  readonly subject: string
  readonly reason: string
  readonly detail: string
}

/** revision.Change, as the delta serializes it: each side is a document. */
export interface DeltaChange {
  readonly kind: 'add' | 'modify' | 'delete' | 'take_ownership'
  readonly policy_id: string
  readonly before?: string
  readonly after?: string
  readonly from_origin?: Origin
  readonly to_origin?: Origin
}

/** revision.Delta. */
export interface Delta {
  readonly changes: readonly DeltaChange[]
  readonly schema_before?: string
  readonly schema_after?: string
}

/** decision.ApplicationMode. */
export type ApplicationMode = 'revaluate' | 'grandfather'

/** revision.Proposal. */
export interface Proposal {
  readonly id: string
  readonly decision_id?: string
  readonly proposer_id: string
  readonly delta: Delta
  readonly delta_digest: string
  readonly application_mode: ApplicationMode
  readonly state: ProposalState
  readonly weakening: boolean
  readonly findings: readonly Finding[]
  readonly threshold: number
  readonly created_at: string
  readonly resolved_at?: string
}

/** revision.BootstrapStatus, as api.GovernanceView embeds it. */
export interface BootstrapStatus {
  readonly [key: string]: unknown
}

/** api.GovernanceView. */
export interface GovernanceView {
  readonly mode: GovernanceMode
  readonly bootstrap?: BootstrapStatus
  readonly pending_revision?: Proposal
}

/**
 * revision.Preview — R23's pre-submission answer.
 *
 * Every field on it is something an author has to be told before spending a
 * quorum's attention: what the change is classified as, how many approvals it
 * will need, whether their own counts, how many open decisions it touches, and
 * which operator floors it breaks.
 */
export interface Preview {
  readonly mode: GovernanceMode
  readonly weakening: boolean
  readonly findings: readonly Finding[]
  readonly threshold: number
  readonly approvers?: readonly string[]
  readonly exclude_proposer: boolean
  readonly affected_decisions: number
  readonly violations?: readonly string[]
}

/** api.ErrorResponse. */
export interface ErrorResponse {
  readonly error: string
  readonly message: string
}
