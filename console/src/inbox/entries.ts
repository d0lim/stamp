/**
 * What an approver is being asked to read, as a list of entries.
 *
 * The list is computed rather than registered. Every entry is derived from the
 * review the server sent and the proposal it points at, so "how many things
 * must be read before this button opens" is a pure function of the material —
 * not a count that components increment as they mount, which would make the
 * gate depend on render order and on nothing having failed to mount.
 *
 * Two orderings are load-bearing. Weakening entries come first and start
 * expanded, because R23 puts them there and because an approver who reads one
 * thing must read that one. Material entries — the inputs of the binding hash —
 * come after the policy changes but are entries all the same: R31 asks the
 * screen to display every input the hash covers, and an input rendered inside a
 * collapsed region nobody opened has been displayed to nobody.
 */
import type { Delta, DeltaChange, Finding } from '../builder/api-types'
import type { QuorumReview } from './api-types'

/** The kinds of entry, which decide how one is drawn. */
export type EntryKind = 'policy' | 'material'

/** One thing an approver has to have opened. */
export interface ReviewEntry {
  readonly id: string
  readonly kind: EntryKind
  /** The one-line summary, visible while the entry is collapsed. */
  readonly title: string
  /** Extra summary text, also visible while collapsed. */
  readonly meta: string
  /** Weakening entries start expanded and sort first. */
  readonly weakening: boolean
  /** For a policy entry: the change it draws. */
  readonly change?: DeltaChange
  /** For a policy entry: the findings that classified it as weakening. */
  readonly findings?: readonly Finding[]
  /** For a material entry: the value it renders, as text. */
  readonly value?: string
}

const CHANGE_KIND_LABELS: Readonly<Record<string, string>> = {
  add: 'Added',
  modify: 'Modified',
  delete: 'Deleted',
  take_ownership: 'Ownership path adoption',
}

/**
 * Renders a JSON value as the text the screen shows.
 *
 * Two-space JSON and never markup. R22 fixes this for the audit view and the
 * same reason holds here: a fact snapshot is data a caller supplied, and the
 * one thing an approval screen must not do is interpret it.
 */
export function asText(value: unknown): string {
  if (value === undefined || value === null) return '(none)'
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

/** How a policy entry states the findings that classified it as weakening. */
function weakeningFindings(count: number): string {
  return `${count} weakening finding${count === 1 ? '' : 's'}`
}

/** Does a finding name this policy? */
function findingsFor(findings: readonly Finding[], policyID: string): Finding[] {
  return findings.filter(
    (finding) => finding.subject === policyID || finding.subject.startsWith(`${policyID}.`),
  )
}

/**
 * The material entries: the inputs of the binding hash, one entry each.
 *
 * The threshold and the policy version are deliberately *not* here. R31
 * excludes both from the hash so that raising a quorum does not evaporate
 * collected approvals, and an entry that displayed them beside the covered
 * material would tell an approver they had signed for something they had not.
 * They are shown on the screen, outside this list, labelled as not covered.
 */
export function materialEntries(review: QuorumReview): ReviewEntry[] {
  const d = review.decision
  return [
    {
      id: 'material:decision',
      kind: 'material',
      title: 'Decision identity',
      meta: `${d.action} · ${d.resource_id}`,
      weakening: false,
      value: asText({
        id: d.id,
        caller_id: d.caller_id,
        subject_id: d.subject_id,
        resource_id: d.resource_id,
        action: d.action,
        policy_id: d.policy_id,
      }),
    },
    {
      id: 'material:request',
      kind: 'material',
      title: 'Request',
      meta: 'The request frozen when the decision was created',
      weakening: false,
      value: asText(d.request),
    },
    {
      id: 'material:facts',
      kind: 'material',
      title: 'Fact snapshot',
      meta: 'The facts the evaluation used, exactly as they stood',
      weakening: false,
      value: asText(d.fact_snapshot),
    },
    {
      id: 'material:obligations',
      kind: 'material',
      title: 'Obligations',
      meta: 'What the caller enforces if the decision allows',
      weakening: false,
      value: asText(d.obligations),
    },
    {
      id: 'material:approvers',
      kind: 'material',
      title: 'Approver set',
      meta: `resolution mode: ${review.mode}`,
      weakening: false,
      value: asText({
        mode: review.mode,
        issuer: review.issuer,
        ...(review.claim === undefined ? {} : { claim: review.claim }),
        ...(review.source === undefined ? {} : { source: review.source }),
        ...(review.approvers === undefined ? {} : { members: review.approvers }),
      }),
    },
  ]
}

/** The policy entries of a revision delta, weakening first. */
export function policyEntries(delta: Delta, findings: readonly Finding[]): ReviewEntry[] {
  const entries: ReviewEntry[] = delta.changes.map((change) => {
    const own = findingsFor(findings, change.policy_id)
    return {
      id: `policy:${change.policy_id}`,
      kind: 'policy' as const,
      title: `${change.policy_id}`,
      meta: `${CHANGE_KIND_LABELS[change.kind] ?? change.kind}${own.length === 0 ? '' : ` · ${weakeningFindings(own.length)}`}`,
      weakening: own.length > 0,
      change,
      findings: own,
    }
  })
  if (delta.schema_before !== undefined || delta.schema_after !== undefined) {
    const own = findingsFor(findings, 'schema')
    entries.push({
      id: 'policy:schema',
      kind: 'policy',
      title: 'Schema declarations',
      meta: `Modified${own.length === 0 ? '' : ` · ${weakeningFindings(own.length)}`}`,
      weakening: own.length > 0,
      change: {
        kind: 'modify',
        policy_id: 'schema',
        ...(delta.schema_before === undefined ? {} : { before: delta.schema_before }),
        ...(delta.schema_after === undefined ? {} : { after: delta.schema_after }),
      },
      findings: own,
    })
  }
  return sortWeakeningFirst(entries)
}

/**
 * Weakening first, then the rest, each group keeping the delta's own order.
 *
 * A stable sort matters: two approvers looking at the same proposal have to be
 * looking at the same list in the same order, or "the third one down" is not a
 * thing they can say to each other.
 */
export function sortWeakeningFirst(entries: readonly ReviewEntry[]): ReviewEntry[] {
  return [...entries].sort((a, b) => Number(b.weakening) - Number(a.weakening))
}

/** The summary a collapsed list still has to show (R23). */
export interface DeltaSummary {
  readonly policies: number
  readonly weakening: number
}

export function summarize(entries: readonly ReviewEntry[]): DeltaSummary {
  const policies = entries.filter((entry) => entry.kind === 'policy')
  return {
    policies: policies.length,
    weakening: policies.filter((entry) => entry.weakening).length,
  }
}

/**
 * The proposal a governance decision is about, read out of the frozen request.
 *
 * U9 puts the proposal identifier and the delta digest in the decision's
 * context rather than the delta itself, which is right: the hash covers the
 * request, so it covers the digest, and the delta is fetched separately and
 * checked against it. This is the console's half of that — it finds the
 * identifier, and the screen refuses to show a delta whose digest does not
 * match.
 */
export interface RevisionRef {
  readonly proposalID: string
  readonly deltaDigest: string
}

export function revisionRefOf(request: unknown): RevisionRef | null {
  if (typeof request !== 'object' || request === null) return null
  const context = (request as { context?: unknown }).context
  if (typeof context !== 'object' || context === null) return null
  const record = context as { type?: unknown; id?: unknown; attributes?: unknown }
  if (record.type !== 'revision' || typeof record.id !== 'string' || record.id === '') return null
  const attributes = record.attributes
  const digest =
    typeof attributes === 'object' && attributes !== null
      ? (attributes as { delta_digest?: unknown }).delta_digest
      : undefined
  return {
    proposalID: record.id,
    deltaDigest: typeof digest === 'string' ? digest : '',
  }
}
