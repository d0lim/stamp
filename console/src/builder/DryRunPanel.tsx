/**
 * The trial evaluation step.
 *
 * The dry-run endpoint takes an unsaved document plus a sample request, evaluates
 * it against the live fact plane, and stores nothing — its Go type holds no
 * writer of any kind, and its response carries `stored: false` so that the
 * guarantee is something this screen can show rather than something it has to
 * assert. It is displayed, because "did this write anything" is the first
 * question an author has about a button that runs their draft against
 * production facts.
 *
 * The sample input is itself a rendered form. R44 draws the line the dry-run
 * handler enforces: an attribute the schema does not declare is an authoring
 * mistake here, not a PEP extension to tolerate. So the console offers exactly
 * the declared attributes of the bound entity types and converts each one to the
 * JSON shape its declared type calls for — a bool as a bool, a timestamp as an
 * RFC 3339 string — rather than posting whatever the box holds.
 *
 * Per-condition results come back keyed by JSON Pointer, in the same scheme the
 * diagnostics use, so each node's outcome is shown on the row that node
 * occupies. The pointers arrive rooted at the policy rather than at the
 * document; pointer.ts is where the two roots meet.
 */
import { useState } from 'react'
import { ApiError, type ApiClient } from '../api/client'
import type { DryRunResponse, NodeTrace } from './api-types'
import { diagnosticsOf, type Diagnostic } from './diagnostics'
import {
  attributesFor,
  boundEntity,
  elemType,
  isListType,
  ROLES,
  type AttributeDraft,
  type Draft,
  type PolicyType,
  type Role,
} from './model'
import { serializeDraft } from './serialize'
import { fromTracePointer } from './pointer'

export interface SampleEntity {
  readonly id: string
  readonly attributes: Readonly<Record<string, string>>
}

export interface SampleInput {
  readonly action: string
  readonly subject: SampleEntity
  readonly resource: SampleEntity
  readonly context: SampleEntity
}

export function emptySample(): SampleInput {
  const entity: SampleEntity = { id: '', attributes: {} }
  return { action: '', subject: entity, resource: entity, context: entity }
}

/** Converts one typed box into the JSON value the declared type calls for. */
function typedValue(type: PolicyType, text: string): unknown {
  if (isListType(type)) {
    const element = elemType(type)
    const items = text.split(',').map((part) => part.trim()).filter((part) => part !== '')
    return element === null ? items : items.map((item) => typedValue(element, item))
  }
  switch (type) {
    case 'bool':
      return text.trim() === 'true'
    case 'int':
    case 'double': {
      const value = Number(text)
      return Number.isFinite(value) ? value : text
    }
    default:
      // string, timestamp and duration all travel as text; the server parses
      // the last two and reports its own error when they do not parse.
      return text
  }
}

function entityPayload(draft: Draft, role: Role, sample: SampleEntity) {
  const type = boundEntity(draft.policy, role)
  if (type === '') return undefined
  const declared = attributesFor(draft, role)
  const attributes: Record<string, unknown> = {}
  for (const attribute of declared) {
    const text = sample.attributes[attribute.name]
    if (text === undefined || text === '') continue
    attributes[attribute.name] = typedValue(attribute.type, text)
  }
  return { type, id: sample.id, attributes }
}

function sampleOf(input: SampleInput, role: Role): SampleEntity {
  switch (role) {
    case 'subject':
      return input.subject
    case 'resource':
      return input.resource
    case 'context':
      return input.context
  }
}

function withRole(input: SampleInput, role: Role, entity: SampleEntity): SampleInput {
  switch (role) {
    case 'subject':
      return { ...input, subject: entity }
    case 'resource':
      return { ...input, resource: entity }
    case 'context':
      return { ...input, context: entity }
  }
}

function resultLabel(trace: NodeTrace): string {
  if (trace.result === null) return '평가 불가'
  return trace.result ? '참' : '거짓'
}

function EntitySample({
  role,
  type,
  attributes,
  sample,
  onChange,
}: {
  readonly role: Role
  readonly type: string
  readonly attributes: readonly AttributeDraft[]
  readonly sample: SampleEntity
  readonly onChange: (next: SampleEntity) => void
}) {
  return (
    <fieldset className="group group--nested">
      <legend className="group__legend">
        {role} ({type})
      </legend>
      <div className="field">
        <label className="field__label" htmlFor={`sample-${role}-id`}>
          {role} 식별자
        </label>
        <input
          id={`sample-${role}-id`}
          className="control"
          type="text"
          value={sample.id}
          onChange={(event) => onChange({ ...sample, id: event.target.value })}
        />
      </div>
      {attributes.map((attribute) => (
        <div className="field" key={attribute.name}>
          <label className="field__label" htmlFor={`sample-${role}-${attribute.name}`}>
            {attribute.name} ({attribute.type})
          </label>
          <input
            id={`sample-${role}-${attribute.name}`}
            className="control"
            type="text"
            value={sample.attributes[attribute.name] ?? ''}
            onChange={(event) =>
              onChange({
                ...sample,
                attributes: { ...sample.attributes, [attribute.name]: event.target.value },
              })
            }
          />
        </div>
      ))}
    </fieldset>
  )
}

export function DryRunPanel({
  api,
  draft,
  input,
  onInputChange,
  onDiagnostics,
}: {
  readonly api: ApiClient
  readonly draft: Draft
  readonly input: SampleInput
  readonly onInputChange: (next: SampleInput) => void
  /** Validation failures the dry run reported, for placement on the form. */
  readonly onDiagnostics: (diagnostics: readonly Diagnostic[]) => void
}) {
  const [result, setResult] = useState<DryRunResponse | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [running, setRunning] = useState(false)

  async function run() {
    setRunning(true)
    setFailure(null)
    setResult(null)
    onDiagnostics([])
    try {
      const response = await api.request<DryRunResponse>('policy-dry-run', {
        body: {
          document: serializeDraft(draft),
          policy_id: draft.policy.id,
          input: {
            action: input.action,
            subject: entityPayload(draft, 'subject', input.subject),
            resource: entityPayload(draft, 'resource', input.resource),
            context: entityPayload(draft, 'context', input.context),
          },
        },
      })
      setResult(response)
    } catch (error) {
      if (error instanceof ApiError) {
        const diagnostics = diagnosticsOf(error.body)
        if (diagnostics.length > 0) {
          // The policy did not survive validation. Those failures belong on the
          // fields that caused them, not in a banner here.
          onDiagnostics(diagnostics)
          setFailure('정책이 정적 검증을 통과하지 못했습니다. 위 오류 요약을 확인하십시오.')
        } else {
          setFailure(messageOf(error))
        }
      } else {
        setFailure(error instanceof Error ? error.message : String(error))
      }
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="dry-run">
      <p>
        저장하지 않고 지금 상태 그대로 평가합니다. 샘플 입력은 선언된 속성에서 렌더링되며, 선언에
        없는 속성은 보내지 않습니다.
      </p>

      <div className="field">
        <label className="field__label" htmlFor="sample-action">
          action
        </label>
        <select
          id="sample-action"
          className="control"
          value={input.action}
          onChange={(event) => onInputChange({ ...input, action: event.target.value })}
        >
          <option value="">선택하십시오</option>
          {draft.policy.actions.map((action) => (
            <option key={action} value={action}>
              {action}
            </option>
          ))}
        </select>
      </div>

      {ROLES.filter((role) => boundEntity(draft.policy, role) !== '').map((role) => (
        <EntitySample
          key={role}
          role={role}
          type={boundEntity(draft.policy, role)}
          attributes={attributesFor(draft, role)}
          sample={sampleOf(input, role)}
          onChange={(entity) => onInputChange(withRole(input, role, entity))}
        />
      ))}

      <button type="button" className="button button--primary" onClick={run} disabled={running}>
        {running ? '평가 중…' : '시험 평가 실행'}
      </button>

      {failure === null ? null : (
        <p className="notice notice--warning" role="alert">
          {failure}
        </p>
      )}

      {result === null ? null : (
        <div className="dry-run__result" data-testid="dry-run-result">
          <h3>시험 평가 결과</h3>
          <dl className="summary-list">
            <dt>정책</dt>
            <dd>{result.policy_id}</dd>
            <dt>매칭</dt>
            <dd>{result.matched ? '이 요청에 적용됨' : '이 요청에 적용되지 않음'}</dd>
            <dt>조건</dt>
            <dd>{result.holds ? '성립' : '불성립'}</dd>
            <dt>판정</dt>
            <dd>
              {result.decision}
              {result.reason === '' ? '' : ` (${result.reason})`}
            </dd>
            <dt>저장 여부</dt>
            <dd data-testid="dry-run-stored">
              {result.stored ? '저장됨' : '저장되지 않음 — 시험 평가는 아무것도 남기지 않습니다'}
            </dd>
          </dl>

          <h4>조건별 결과</h4>
          <ul className="trace">
            {result.conditions.map((trace) => (
              <li key={trace.pointer} data-pointer={fromTracePointer(trace.pointer)}>
                <code>{fromTracePointer(trace.pointer)}</code> · {trace.kind} · {resultLabel(trace)}
                {trace.error === undefined || trace.error === '' ? '' : ` — ${trace.error}`}
              </li>
            ))}
          </ul>

          <h4>발동될 challenge</h4>
          {result.challenges.length === 0 ? (
            <p>없습니다 — 이 정책은 check 경로에서 즉시 판정됩니다.</p>
          ) : (
            <ul className="trace">
              {result.challenges.map((challenge, index) => (
                <li key={`${challenge.type}-${index}`}>
                  {challenge.type}
                  {challenge.detail === undefined
                    ? ''
                    : ` · ${Object.entries(challenge.detail)
                        .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
                        .join(', ')}`}
                </li>
              ))}
            </ul>
          )}

          {result.sources === undefined || result.sources.length === 0 ? null : (
            <>
              <h4>호출된 fact source</h4>
              <ul className="trace">
                {result.sources.map((call) => (
                  <li key={call}>
                    <code>{call}</code>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  )
}

function messageOf(error: ApiError): string {
  const body = error.body
  if (typeof body === 'object' && body !== null) {
    const message = (body as { message?: unknown }).message
    if (typeof message === 'string' && message !== '') return message
  }
  return error.message
}
