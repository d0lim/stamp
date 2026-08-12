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
  revaluate: '재평가 — 미결 결정을 새 정책으로 다시 판정합니다 (기본)',
  grandfather: '유예 — 미결 결정은 만들어질 때의 버전으로 끝냅니다',
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
        <legend className="group__legend">적용 방식</legend>
        <p className="field__hint" data-testid="affected-decisions">
          이 개정이 영향을 줄 미결 결정:{' '}
          {preview === null ? '프리플라이트 전에는 알 수 없습니다' : `${preview.affected_decisions}건`}
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
          이 개정에는 선언(schema)도 함께 실립니다. 콘솔은 현재 발효 중인 선언을 읽을 수단이 없어
          이전 선언을 함께 보내지 못하므로, fact source 실패 동작이 deny에서 allow로 바뀌는 완화는
          자동 분류에 잡히지 않습니다. 승인자가 직접 확인해야 합니다.
        </p>
      )}

      <button type="button" className="button" onClick={runPreview} disabled={busy}>
        제출 전 확인 (프리플라이트)
      </button>

      {failure === null ? null : (
        <p className="notice notice--warning" role="alert" data-testid="submit-failure">
          {failure}
        </p>
      )}

      {preview === null ? null : (
        <div className="preview" data-testid="revision-preview">
          <h3>제출하면 무슨 일이 일어나는가</h3>

          {/*
            R23 asks for the change diff beside the classification. It is drawn
            by the renderer the approval screen uses (src/diff/), so what an
            author reads before submitting and what an approver reads before
            approving are the same rendering of the same delta rather than two
            components that happen to agree today.
          */}
          <h4>변경 내용</h4>
          <DocumentDiff idPrefix="submit-diff" after={serializePolicy(draft.policy)} />

          <dl className="summary-list">
            <dt>거버넌스</dt>
            <dd>{preview.mode === 'quorum' ? '잠김 (quorum)' : '미잠금 (solo_admin)'}</dd>
            <dt>완화 분류</dt>
            <dd>
              {preview.weakening ? '완화로 분류됨' : '완화 아님'}
              {preview.findings.length === 0 ? '' : ` · ${preview.findings.length}건`}
            </dd>
            <dt>영향받는 미결 결정</dt>
            <dd>{preview.affected_decisions}건</dd>
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
              제출해도 바로 발효되지 않습니다. 이 개정은 승인자 {preview.threshold}명의 정족수를
              채워야 발효되며,
              {preview.exclude_proposer
                ? ' 제안자 본인의 승인은 정족수에 포함되지 않습니다.'
                : ' 제안자 본인의 승인도 정족수에 포함됩니다.'}
              {preview.approvers === undefined || preview.approvers.length === 0
                ? ''
                : ` 해석된 승인자: ${preview.approvers.join(', ')}.`}
            </p>
          ) : (
            <p className="notice notice--warning" data-testid="unlocked-notice">
              이 설치는 아직 거버넌스가 잠기지 않았습니다 (solo_admin). 개정이 정족수 없이 발효되며,
              이는 잠금 전까지의 상태입니다.
            </p>
          )}

          {blocked ? (
            <div className="notice notice--warning" data-testid="floor-violations">
              <p className="notice__text">
                운영자 하한을 위반해 제출할 수 없습니다. 아래 항목을 해소해야 제출이 열립니다.
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
          ? '먼저 프리플라이트를 실행해야 제출할 수 있습니다 — 무엇을 요구하는 개정인지 보기 전에는 제출이 열리지 않습니다.'
          : blocked
            ? '운영자 하한을 위반하는 개정은 제출할 수 없습니다.'
            : '프리플라이트 결과를 확인했습니다. 제출하면 개정 제안이 만들어집니다.'}
      </p>
      <button
        type="button"
        className="button button--primary"
        onClick={submit}
        disabled={!submittable || busy}
        aria-describedby="submit-gate"
      >
        개정 제출
      </button>

      {proposal === null ? null : (
        <div className="proposal" role="status" data-testid="proposal-result">
          <h3>개정 제안이 접수되었습니다</h3>
          <dl className="summary-list">
            <dt>제안 식별자</dt>
            <dd>{proposal.id}</dd>
            <dt>상태</dt>
            <dd>{proposal.state === 'pending' ? '미결 — 아직 발효되지 않았습니다' : proposal.state}</dd>
            <dt>필요한 승인 수</dt>
            <dd>{proposal.threshold}</dd>
          </dl>
          <p>
            {proposal.state === 'pending'
              ? '승인자가 정족수를 채우면 발효됩니다. 그 전까지 발효 중인 정책은 바뀌지 않습니다.'
              : '이 제안은 이미 종결되었습니다.'}
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
    return '이미 열려 있는 개정 제안이 있습니다. 위 배너에서 확인하십시오.'
  }
  return errorMessageOf(error) ?? error.message
}
