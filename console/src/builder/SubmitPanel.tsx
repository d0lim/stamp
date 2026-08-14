/**
 * Submission, and the gap between "submitted" and "in effect".
 *
 * A form submission is a one-element revision delta and not a special path
 * (U9). That is the whole reason this panel is small: it builds a delta, asks
 * the preview endpoint what the delta would cost, and posts it. Nothing here
 * writes a policy, because nothing on the server's side of this call can either.
 *
 * The part that is not plumbing is what an author is told before they press the
 * button. Post-lock, a revision does not take effect on submission — it becomes
 * a decision that a quorum has to satisfy, and the proposer's own approval does
 * not count toward it. A form that showed a success toast and returned to the
 * list would be lying about what just happened. So:
 *
 *   - the preview runs first and its answer is displayed, and the submit button
 *     does not exist in an enabled state until it has been displayed. An author
 *     cannot submit without having been shown the quorum, the weakening
 *     classification and the pending decisions the change would touch;
 *   - a revision that breaks an operator floor keeps the button disabled, which
 *     is R23's rule and also just the truth — that revision is refused at
 *     submission anyway;
 *   - after submission the screen says the proposal is pending and what it is
 *     waiting for, rather than reporting success.
 */
import { useState } from 'react'
import { ApiError, type ApiClient } from '../api/client'
import { errorCodeOf, errorMessageOf } from '../api/error-codes'
import { DocumentDiff } from '../diff/FieldDiff'
import type { ApplicationMode, Delta, Preview, Proposal } from './api-types'
import { hasNoDeclarations, type Draft } from './model'
import { serializePolicy, serializeSchema } from './serialize'

/** Builds the one-element delta a form edit produces (revision.Single). */
export function draftDelta(draft: Draft): Delta {
  const changes = [
    {
      kind: 'add' as const,
      policy_id: draft.policy.id,
      after: serializePolicy(draft.policy),
    },
  ]
  if (hasNoDeclarations(draft.schema)) return { changes }
  return { changes, schema_after: serializeSchema(draft.schema) }
}

const MODE_LABELS: Readonly<Record<ApplicationMode, string>> = {
  revaluate: 'revalidation — pending decisions are judged again against the new policy (default)',
  grandfather:
    'grandfathering — pending decisions finish under the version in force when they were created',
}

export function SubmitPanel({
  api,
  draft,
  onPendingRevision,
}: {
  readonly api: ApiClient
  readonly draft: Draft
  /** Raised when the server refuses because another revision is open. */
  readonly onPendingRevision: () => void
}) {
  const [mode, setMode] = useState<ApplicationMode>('revaluate')
  const [preview, setPreview] = useState<Preview | null>(null)
  const [proposal, setProposal] = useState<Proposal | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const violations = preview?.violations ?? []
  const blocked = violations.length > 0
  const submittable = preview !== null && !blocked && proposal === null

  async function runPreview() {
    setBusy(true)
    setFailure(null)
    setProposal(null)
    try {
      setPreview(
        await api.request<Preview>('revision-preview', { body: { delta: draftDelta(draft) } }),
      )
    } catch (error) {
      setPreview(null)
      setFailure(explain(error, onPendingRevision))
    } finally {
      setBusy(false)
    }
  }

  async function submit() {
    setBusy(true)
    setFailure(null)
    try {
      setProposal(
        await api.request<Proposal>('revision-submit', {
          body: { delta: draftDelta(draft), application_mode: mode },
        }),
      )
    } catch (error) {
      setFailure(explain(error, onPendingRevision))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="submit">
      <fieldset className="group">
        <legend className="group__legend">Application mode</legend>
        <p className="field__hint" data-testid="affected-decisions">
          Pending decisions this revision would affect:{' '}
          {preview === null ? 'unknown before the preflight' : preview.affected_decisions}
        </p>
        {(['revaluate', 'grandfather'] as const).map((value) => (
          <div className="field field--inline" key={value}>
            <input
              id={`application-mode-${value}`}
              className="control"
              type="radio"
              name="application-mode"
              value={value}
              checked={mode === value}
              onChange={() => setMode(value)}
            />
            <label className="field__label" htmlFor={`application-mode-${value}`}>
              {MODE_LABELS[value]}
            </label>
          </div>
        ))}
      </fieldset>

      {hasNoDeclarations(draft.schema) ? null : (
        <p className="notice notice--warning" data-testid="schema-submission-warning">
          This revision carries the declarations (schema) as well. The console has no way to read
          the declarations currently in force, so it cannot send the previous ones alongside them,
          and a weakening that turns a fact source's failure behaviour from deny into allow is not
          caught by the automatic classification. An approver has to check it directly.
        </p>
      )}

      <button type="button" className="button" onClick={runPreview} disabled={busy}>
        Check before submitting (preflight)
      </button>

      {failure === null ? null : (
        <p className="notice notice--warning" role="alert" data-testid="submit-failure">
          {failure}
        </p>
      )}

      {preview === null ? null : (
        <div className="preview" data-testid="revision-preview">
          <h3>What happens if you submit</h3>

          {/*
            R23 asks for the change diff beside the classification. It is drawn
            by the renderer the approval screen uses (src/diff/), so what an
            author reads before submitting and what an approver reads before
            approving are the same rendering of the same delta rather than two
            components that happen to agree today.
          */}
          <h4>Changes</h4>
          <DocumentDiff idPrefix="submit-diff" after={serializePolicy(draft.policy)} />

          <dl className="summary-list">
            <dt>Governance</dt>
            <dd>{preview.mode === 'quorum' ? 'locked (quorum)' : 'unlocked (solo_admin)'}</dd>
            <dt>Weakening classification</dt>
            <dd>
              {preview.weakening ? 'classified as a weakening' : 'not a weakening'}
              {preview.findings.length === 0
                ? ''
                : ` · ${preview.findings.length} finding${preview.findings.length === 1 ? '' : 's'}`}
            </dd>
            <dt>Pending decisions affected</dt>
            <dd>{preview.affected_decisions}</dd>
          </dl>

          {preview.findings.length === 0 ? null : (
            <ul className="trace" data-testid="weakening-findings">
              {preview.findings.map((finding, index) => (
                <li key={`${finding.subject}-${index}`}>
                  <strong>{finding.subject}</strong> · {finding.reason} — {finding.detail}
                </li>
              ))}
            </ul>
          )}

          {preview.mode === 'quorum' ? (
            <p className="notice notice--warning" data-testid="quorum-notice">
              Submitting does not put this in force. The revision takes effect only once a quorum of{' '}
              {preview.threshold} approvers is reached, and
              {preview.exclude_proposer
                ? " the proposer's own approval does not count toward the quorum."
                : " the proposer's own approval counts toward the quorum as well."}
              {preview.approvers === undefined || preview.approvers.length === 0
                ? ''
                : ` Resolved approvers: ${preview.approvers.join(', ')}.`}
            </p>
          ) : (
            <p className="notice notice--warning" data-testid="unlocked-notice">
              This installation's governance is not locked yet (solo_admin). A revision takes effect
              without a quorum, and that holds until the installation is locked.
            </p>
          )}

          {blocked ? (
            <div className="notice notice--warning" data-testid="floor-violations">
              <p className="notice__text">
                This cannot be submitted because it violates an operator floor. Submission opens
                once the items below are resolved.
              </p>
              <ul>
                {violations.map((violation) => (
                  <li key={violation}>{violation}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      )}

      <p id="submit-gate" className="field__hint">
        {preview === null
          ? 'The preflight has to run before this can be submitted — submission does not open until you have been shown what the revision demands.'
          : blocked
            ? 'A revision that violates an operator floor cannot be submitted.'
            : 'You have seen the preflight result. Submitting creates a revision proposal.'}
      </p>
      <button
        type="button"
        className="button button--primary"
        onClick={submit}
        disabled={!submittable || busy}
        aria-describedby="submit-gate"
      >
        Submit revision
      </button>

      {proposal === null ? null : (
        <div className="proposal" role="status" data-testid="proposal-result">
          <h3>Revision proposal received</h3>
          <dl className="summary-list">
            <dt>Proposal identifier</dt>
            <dd>{proposal.id}</dd>
            <dt>State</dt>
            <dd>{proposal.state === 'pending' ? 'pending — not in force yet' : proposal.state}</dd>
            <dt>Approvals required</dt>
            <dd>{proposal.threshold}</dd>
          </dl>
          <p>
            {proposal.state === 'pending'
              ? 'It takes effect once approvers reach the quorum. Until then the policies in force do not change.'
              : 'This proposal is already closed.'}
          </p>
        </div>
      )}
    </div>
  )
}

/**
 * Turns a failure into something an author can act on.
 *
 * A pending revision is not an error to narrate — U9 refuses a second open
 * proposal, and the answer to that is the banner that names the one already
 * open, with its withdrawal action. Everything else is shown as the server
 * worded it.
 */
function explain(error: unknown, onPendingRevision: () => void): string {
  if (!(error instanceof ApiError)) {
    return error instanceof Error ? error.message : String(error)
  }
  if (errorCodeOf(error) === 'revision_pending') {
    onPendingRevision()
    return 'A revision proposal is already open. See the banner above.'
  }
  return errorMessageOf(error) ?? error.message
}
