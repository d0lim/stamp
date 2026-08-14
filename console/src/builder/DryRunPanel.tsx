/**
 * The dry run step.
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
import { errorMessageOf } from '../api/error-codes'
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
  if (trace.result === null) return 'not evaluated'
  return trace.result ? 'true' : 'false'
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
          {role} identifier
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
          setFailure('The policy did not pass static validation. See the error summary above.')
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
        Evaluates the draft exactly as it stands, and stores nothing. The sample input is rendered
        from the declared attributes, and an attribute the declarations do not have is not sent.
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
          <option value="">Select one</option>
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
        {running ? 'Evaluating…' : 'Run dry run'}
      </button>

      {failure === null ? null : (
        <p className="notice notice--warning" role="alert">
          {failure}
        </p>
      )}

      {result === null ? null : (
        <div className="dry-run__result" data-testid="dry-run-result">
          <h3>Dry run result</h3>
          <dl className="summary-list">
            <dt>Policy</dt>
            <dd>{result.policy_id}</dd>
            <dt>Match</dt>
            <dd>{result.matched ? 'applies to this request' : 'does not apply to this request'}</dd>
            <dt>Condition</dt>
            <dd>{result.holds ? 'holds' : 'does not hold'}</dd>
            <dt>Judgment</dt>
            <dd>
              {result.decision}
              {result.reason === '' ? '' : ` (${result.reason})`}
            </dd>
            <dt>Stored</dt>
            <dd data-testid="dry-run-stored">
              {result.stored ? 'stored' : 'not stored — a dry run leaves nothing behind'}
            </dd>
          </dl>

          <h4>Per-condition results</h4>
          <ul className="trace">
            {result.conditions.map((trace) => (
              <li key={trace.pointer} data-pointer={fromTracePointer(trace.pointer)}>
                <code>{fromTracePointer(trace.pointer)}</code> · {trace.kind} · {resultLabel(trace)}
                {trace.error === undefined || trace.error === '' ? '' : ` — ${trace.error}`}
              </li>
            ))}
          </ul>

          <h4>Challenges that would fire</h4>
          {result.challenges.length === 0 ? (
            <p>None — this policy is judged immediately on the check path.</p>
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
              <h4>Fact sources called</h4>
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
  return errorMessageOf(error) ?? error.message
}
