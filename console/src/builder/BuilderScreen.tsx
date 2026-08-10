/**
 * The guided authoring flow.
 *
 * R19 fixes the order — trigger, source binding, rule, challenge — and this adds
 * declarations before it and trial evaluation and submission after it, because
 * the first is what the form renders from and the last two are what an author
 * needs before a quorum spends attention on the result.
 *
 * The steps are a `nav` of real buttons rather than a wizard that only moves
 * forward. Every step is reachable at any time and the whole flow is completable
 * with a keyboard, which R19 requires and which also happens to be how anyone
 * fixes a mistake three steps back after the validator points at it.
 *
 * All of the form's state is one `Draft`, and the draft is the AST. Nothing here
 * holds a document string that the form and the AST could disagree about — the
 * document is computed from the draft at the moment of a request, which is why
 * "what you submitted is what you saw" needs no reconciliation step.
 *
 * The draft is not persisted. The plan asks for a session-storage snapshot that
 * survives re-login; U14's boundary check refuses `sessionStorage` outside the
 * OIDC redirect flow, and that refusal is load-bearing (R50), so restoring a
 * draft needs a decision about where drafts live rather than an exception here.
 */
import { useMemo, useState } from 'react'
import { ErrorSummary } from '../a11y/ErrorSummary'
import { RouteAnnouncer } from '../a11y/RouteAnnouncer'
import { useAuth } from '../auth/AuthProvider'
import { ChallengeEditor } from './ChallengeEditor'
import { ConditionEditor } from './ConditionEditor'
import { DeclarationsEditor, KIND_NOTES } from './DeclarationsEditor'
import { DryRunPanel, emptySample, type SampleInput } from './DryRunPanel'
import { Field, FieldGroup } from './Field'
import { GovernanceBanner, useGovernance } from './GovernanceBanner'
import { SubmitPanel } from './SubmitPanel'
import {
  NO_DIAGNOSTICS,
  placeDiagnostics,
  UNPLACED_ANCHOR_ID,
  describe,
  type Diagnostic,
} from './diagnostics'
import {
  emptyDraft,
  hasNoDeclarations,
  ROLES,
  type ConditionNode,
  type Draft,
  type Operand,
  type Role,
} from './model'
import { jptr, policyPointer } from './pointer'
import { serializeDraft } from './serialize'

const STEPS = [
  { key: 'declarations', title: '선언' },
  { key: 'binding', title: '발동 조건' },
  { key: 'sources', title: 'source 바인딩' },
  { key: 'rule', title: '규칙' },
  { key: 'challenges', title: 'challenge' },
  { key: 'dry-run', title: '시험 평가' },
  { key: 'submit', title: '제출' },
] as const

/**
 * Which step owns a pointer.
 *
 * A diagnostic that lands on a field two steps back is only *placed* if the
 * author can see it. The summary's links are in-page anchors, and an anchor to
 * a field on a step that is not rendered goes nowhere — so receiving
 * diagnostics moves the flow to the step that owns the first one. The mapping is
 * from the pointer's own prefix rather than from a lookup, because the steps are
 * carved along the document's own structure.
 */
function stepForPointer(pointer: string): number | null {
  const policy = policyPointer()
  if (pointer.startsWith('/schema/')) return indexOfStep('declarations')
  if (!pointer.startsWith(policy)) return null
  const rest = pointer.slice(policy.length)
  if (rest.startsWith('/condition')) return indexOfStep('rule')
  if (rest.startsWith('/challenges')) return indexOfStep('challenges')
  return indexOfStep('binding')
}

function indexOfStep(key: (typeof STEPS)[number]['key']): number {
  return STEPS.findIndex((step) => step.key === key)
}

/** The fact sources a condition actually calls, so the binding step can say so. */
function referencedSources(node: ConditionNode | null, out: Set<string> = new Set()): Set<string> {
  if (node === null) return out
  const operand = (value: Operand) => {
    if (value.kind !== 'source') return
    out.add(value.name)
    value.args.forEach(operand)
  }
  switch (node.kind) {
    case 'logic':
      node.operands.forEach((child) => referencedSources(child, out))
      return out
    case 'compare':
      operand(node.left)
      operand(node.right)
      return out
    case 'member':
      operand(node.left)
      operand(node.collection)
      return out
  }
}

export function BuilderScreen() {
  const { api, session } = useAuth()
  const [draft, setDraft] = useState<Draft>(emptyDraft)
  const [diagnostics, setDiagnostics] = useState<readonly Diagnostic[]>([])
  const [sample, setSample] = useState<SampleInput>(emptySample)
  const [step, setStep] = useState(0)
  const governance = useGovernance(api)

  const placed = useMemo(
    () => (diagnostics.length === 0 ? NO_DIAGNOSTICS : placeDiagnostics(diagnostics, draft)),
    [diagnostics, draft],
  )
  const policy = policyPointer()
  const current = STEPS[step] ?? STEPS[0]
  const referenced = referencedSources(draft.policy.condition)

  /** Takes the server's diagnostics and puts the author where they landed. */
  function receiveDiagnostics(next: readonly Diagnostic[]) {
    setDiagnostics(next)
    if (next.length === 0) return
    const placement = placeDiagnostics(next, draft)
    for (const [pointer] of placement.byPointer) {
      const target = stepForPointer(pointer)
      if (target !== null && target >= 0) {
        setStep(target)
        return
      }
    }
  }

  return (
    <div className="panel builder">
      <RouteAnnouncer title="정책 저작" />
      <h1>정책 저작</h1>

      <GovernanceBanner
        api={api}
        state={governance}
        subjectId={typeof session?.claims?.sub === 'string' ? session.claims.sub : null}
      />

      <ErrorSummary errors={placed.summary} />
      <p id={UNPLACED_ANCHOR_ID} tabIndex={-1} className="field__hint">
        {placed.unplaced.length === 0
          ? '서버가 보고한 오류는 각 필드에 붙습니다.'
          : placed.unplaced.map(describe).join(' · ')}
      </p>

      <nav aria-label="저작 단계">
        <ol className="steps">
          {STEPS.map((entry, index) => (
            <li key={entry.key}>
              <button
                type="button"
                className={index === step ? 'button button--primary' : 'button'}
                aria-current={index === step ? 'step' : undefined}
                onClick={() => setStep(index)}
              >
                {index + 1}. {entry.title}
              </button>
            </li>
          ))}
        </ol>
      </nav>

      <section aria-label={current.title}>
        <h2>{current.title}</h2>

        {current.key === 'declarations' ? (
          <DeclarationsEditor
            schema={draft.schema}
            placed={placed}
            onChange={(schema) => setDraft({ ...draft, schema })}
          />
        ) : null}

        {current.key === 'binding' ? (
          <>
            <Field
              pointer={jptr(policy, 'id')}
              label="정책 식별자"
              hint="정책의 정체성은 이 값이며 파일 이름이 아닙니다."
              placed={placed}
            >
              {(props) => (
                <input
                  {...props}
                  className="control"
                  type="text"
                  value={draft.policy.id}
                  onChange={(event) =>
                    setDraft({ ...draft, policy: { ...draft.policy, id: event.target.value } })
                  }
                />
              )}
            </Field>
            <Field pointer={jptr(policy, 'description')} label="설명" placed={placed}>
              {(props) => (
                <input
                  {...props}
                  className="control"
                  type="text"
                  value={draft.policy.description}
                  onChange={(event) =>
                    setDraft({
                      ...draft,
                      policy: { ...draft.policy, description: event.target.value },
                    })
                  }
                />
              )}
            </Field>

            {hasNoDeclarations(draft.schema) ? (
              <p className="notice notice--warning" data-testid="binding-needs-declarations">
                선언된 entity가 없어 바인딩할 대상이 없습니다. 1단계 선언에서 entity를 먼저
                선언하십시오.
              </p>
            ) : null}

            {ROLES.map((role) => (
              <Field
                key={role}
                pointer={jptr(policy, role)}
                label={`${role} entity`}
                placed={placed}
              >
                {(props) => (
                  <select
                    {...props}
                    className="control"
                    value={
                      role === 'subject'
                        ? draft.policy.subject
                        : role === 'resource'
                          ? draft.policy.resource
                          : draft.policy.context
                    }
                    onChange={(event) => setDraft(bindRole(draft, role, event.target.value))}
                  >
                    <option value="">{role === 'context' ? '바인딩하지 않음' : '선택하십시오'}</option>
                    {draft.schema.entities.map((entity) => (
                      <option key={entity.name} value={entity.name}>
                        {entity.name}
                      </option>
                    ))}
                  </select>
                )}
              </Field>
            ))}

            <FieldGroup pointer={jptr(policy, 'actions')} legend="적용 action" placed={placed}>
              {draft.schema.actions.length === 0 ? (
                <p>선언된 action이 없습니다. 1단계 선언에서 action을 선언하십시오.</p>
              ) : null}
              {draft.schema.actions.map((action) => (
                <div className="field field--inline" key={action.name}>
                  <input
                    id={`action-${action.name}`}
                    className="control"
                    type="checkbox"
                    checked={draft.policy.actions.includes(action.name)}
                    onChange={(event) =>
                      setDraft(toggleAction(draft, action.name, event.target.checked))
                    }
                  />
                  <label className="field__label" htmlFor={`action-${action.name}`}>
                    {action.name}
                    {action.description === '' ? '' : ` — ${action.description}`}
                  </label>
                </div>
              ))}
            </FieldGroup>
          </>
        ) : null}

        {current.key === 'sources' ? (
          <div className="sources">
            <p>
              조건이 부르는 fact source의 서명과 실패 동작을 확인합니다. 호출 대상·TTL·스트림 정의는
              선언이 아니라 배포의 fact plane 설정이므로 여기서 편집하지 않습니다.
            </p>
            {draft.schema.sources.length === 0 ? (
              <p data-testid="sources-empty">
                선언된 fact source가 없습니다. 조건이 외부 사실을 읽어야 한다면 1단계 선언에서 source를
                선언하십시오.
              </p>
            ) : null}
            <ul className="source-list">
              {draft.schema.sources.map((source) => (
                <li key={source.name}>
                  <strong>{source.name}</strong> · {source.kind} ·{' '}
                  {source.params.map((p) => `${p.name}: ${p.type}`).join(', ') || '인자 없음'} →{' '}
                  {source.returns} · 실패 시 {source.onError}
                  <p className="field__hint">{KIND_NOTES[source.kind]}</p>
                  <p className="field__hint">
                    {referenced.has(source.name)
                      ? '이 정책의 조건이 호출합니다.'
                      : '이 정책의 조건은 호출하지 않습니다.'}
                  </p>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {current.key === 'rule' ? (
          <ConditionEditor
            draft={draft}
            placed={placed}
            pointer={jptr(policy, 'condition')}
            onChange={(condition) => setDraft({ ...draft, policy: { ...draft.policy, condition } })}
          />
        ) : null}

        {current.key === 'challenges' ? (
          <ChallengeEditor
            draft={draft}
            placed={placed}
            pointer={jptr(policy, 'challenges')}
            onChange={(challenges) =>
              setDraft({ ...draft, policy: { ...draft.policy, challenges } })
            }
          />
        ) : null}

        {current.key === 'dry-run' ? (
          <DryRunPanel
            api={api}
            draft={draft}
            input={sample}
            onInputChange={setSample}
            onDiagnostics={receiveDiagnostics}
          />
        ) : null}

        {current.key === 'submit' ? (
          <SubmitPanel api={api} draft={draft} onPendingRevision={governance.reload} />
        ) : null}
      </section>

      <section aria-label="교환 포맷 미리보기">
        <h2>교환 포맷</h2>
        <p className="field__hint">
          폼이 만들어 내는 문서입니다. 파일 저작이 읽고 쓰는 것과 같은 포맷이며, 제출도 시험 평가도
          이 문서를 보냅니다.
        </p>
        <pre className="document" data-testid="document-preview">
          {serializeDraft(draft)}
        </pre>
      </section>
    </div>
  )
}

function bindRole(draft: Draft, role: Role, value: string): Draft {
  const policy = draft.policy
  switch (role) {
    case 'subject':
      return { ...draft, policy: { ...policy, subject: value } }
    case 'resource':
      return { ...draft, policy: { ...policy, resource: value } }
    case 'context':
      return { ...draft, policy: { ...policy, context: value } }
  }
}

function toggleAction(draft: Draft, name: string, checked: boolean): Draft {
  const actions = checked
    ? [...draft.policy.actions, name]
    : draft.policy.actions.filter((action) => action !== name)
  return { ...draft, policy: { ...draft.policy, actions } }
}
