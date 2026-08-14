/**
 * The declarations, authored in the builder.
 *
 * R19 puts entity, action and source declarations inside the same builder as
 * the policy, and asks for a path from a genuinely empty state — no
 * declarations at all — to a first declaration. That is not a convenience: a
 * form rendered from a schema has nothing to render before a schema exists, so
 * without this step the empty install has a builder that can only show an error.
 *
 * The pointers here are `/schema/...`, which is where the validator reports
 * declaration failures, so a bad source signature lands on the source rather
 * than on the rule that called it.
 *
 * What a declaration does *not* carry is transport: a source's endpoint, its
 * cache TTL, the stream it reads. policy.SourceDecl holds a name, a kind, a
 * signature and a failure behaviour, and the note on SourceKind says the rest
 * belongs to the deployment's fact plane. So this editor states which half is
 * being authored, rather than offering fields the format has nowhere to put.
 */
import {
  ON_ERRORS,
  SOURCE_KINDS,
  allTypes,
  hasNoDeclarations,
  type ActionDraft,
  type EntityDraft,
  type OnError,
  type PolicyType,
  type SchemaDraft,
  type SourceDraft,
  type SourceKind,
} from './model'
import { Field, FieldGroup } from './Field'
import type { PlacedDiagnostics } from './diagnostics'
import { fieldId, jptr } from './pointer'

const KIND_NOTES: Readonly<Record<SourceKind, string>> = {
  static: 'Returns a value fixed in the deployment configuration. There is no call.',
  http: "A synchronous HTTP call. The call target and the cache TTL are the operator's fact plane configuration and are not carried in the declaration.",
  event: 'Reads an asynchronous event aggregate. The stream and window definitions are operator configuration.',
  idp_group: 'An IdP group lookup. The same declaration is what resolves an approver set.',
}

function EntityEditor({
  placed,
  index,
  entity,
  onChange,
  onRemove,
}: {
  readonly placed: PlacedDiagnostics
  readonly index: number
  readonly entity: EntityDraft
  readonly onChange: (next: EntityDraft) => void
  readonly onRemove: () => void
}) {
  const pointer = jptr('schema', 'entities', index)
  return (
    <FieldGroup
      pointer={pointer}
      legend={`entity ${entity.name === '' ? index + 1 : entity.name}`}
      placed={placed}
      className="node"
    >
      <Field
        pointer={jptr(pointer, 'name')}
        label="Name"
        hint="Starts with a lowercase letter and uses only lowercase letters, digits and underscores — it becomes a CEL identifier."
        placed={placed}
      >
        {(props) => (
          <input
            {...props}
            className="control"
            type="text"
            value={entity.name}
            onChange={(event) => onChange({ ...entity, name: event.target.value })}
          />
        )}
      </Field>
      {entity.attributes.map((attribute, i) => (
        <div className="field field--inline" key={i}>
          <label className="field__label" htmlFor={`${fieldId(pointer)}--attr-${i}`}>
            Attribute {i + 1} name
          </label>
          <input
            id={`${fieldId(pointer)}--attr-${i}`}
            className="control"
            type="text"
            value={attribute.name}
            onChange={(event) =>
              onChange({
                ...entity,
                attributes: entity.attributes.map((a, j) =>
                  j === i ? { ...a, name: event.target.value } : a,
                ),
              })
            }
          />
          <label
            className="field__label"
            htmlFor={fieldId(jptr(pointer, 'attributes', attribute.name))}
          >
            Attribute {i + 1} type
          </label>
          <select
            id={fieldId(jptr(pointer, 'attributes', attribute.name))}
            className="control"
            value={attribute.type}
            onChange={(event) =>
              onChange({
                ...entity,
                attributes: entity.attributes.map((a, j) =>
                  j === i ? { ...a, type: event.target.value as PolicyType } : a,
                ),
              })
            }
          >
            {allTypes().map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="button button--quiet"
            onClick={() =>
              onChange({ ...entity, attributes: entity.attributes.filter((_, j) => j !== i) })
            }
          >
            Delete attribute {i + 1}
          </button>
        </div>
      ))}
      <button
        type="button"
        className="button"
        onClick={() =>
          onChange({ ...entity, attributes: [...entity.attributes, { name: '', type: 'string' }] })
        }
      >
        Add attribute
      </button>
      <button type="button" className="button button--quiet" onClick={onRemove}>
        Delete entity {index + 1}
      </button>
    </FieldGroup>
  )
}

function ActionEditor({
  placed,
  index,
  action,
  onChange,
  onRemove,
}: {
  readonly placed: PlacedDiagnostics
  readonly index: number
  readonly action: ActionDraft
  readonly onChange: (next: ActionDraft) => void
  readonly onRemove: () => void
}) {
  const pointer = jptr('schema', 'actions', index)
  return (
    <FieldGroup
      pointer={pointer}
      legend={`action ${action.name === '' ? index + 1 : action.name}`}
      placed={placed}
      className="node"
    >
      <Field pointer={jptr(pointer, 'name')} label="Name" placed={placed}>
        {(props) => (
          <input
            {...props}
            className="control"
            type="text"
            value={action.name}
            onChange={(event) => onChange({ ...action, name: event.target.value })}
          />
        )}
      </Field>
      <div className="field">
        <label className="field__label" htmlFor={`${fieldId(pointer)}--description`}>
          Description
        </label>
        <input
          id={`${fieldId(pointer)}--description`}
          className="control"
          type="text"
          value={action.description}
          onChange={(event) => onChange({ ...action, description: event.target.value })}
        />
      </div>
      <button type="button" className="button button--quiet" onClick={onRemove}>
        Delete action {index + 1}
      </button>
    </FieldGroup>
  )
}

function SourceEditor({
  placed,
  index,
  source,
  onChange,
  onRemove,
}: {
  readonly placed: PlacedDiagnostics
  readonly index: number
  readonly source: SourceDraft
  readonly onChange: (next: SourceDraft) => void
  readonly onRemove: () => void
}) {
  const pointer = jptr('schema', 'sources', index)
  return (
    <FieldGroup
      pointer={pointer}
      legend={`source ${source.name === '' ? index + 1 : source.name}`}
      placed={placed}
      className="node"
    >
      <Field pointer={jptr(pointer, 'name')} label="Name" placed={placed}>
        {(props) => (
          <input
            {...props}
            className="control"
            type="text"
            value={source.name}
            onChange={(event) => onChange({ ...source, name: event.target.value })}
          />
        )}
      </Field>
      <Field
        pointer={jptr(pointer, 'kind')}
        label="Kind"
        hint={KIND_NOTES[source.kind]}
        placed={placed}
      >
        {(props) => (
          <select
            {...props}
            className="control"
            value={source.kind}
            onChange={(event) => onChange({ ...source, kind: event.target.value as SourceKind })}
          >
            {SOURCE_KINDS.map((kind) => (
              <option key={kind} value={kind}>
                {kind}
              </option>
            ))}
          </select>
        )}
      </Field>
      {source.params.map((param, i) => (
        <div className="field field--inline" key={i}>
          <label className="field__label" htmlFor={`${fieldId(pointer)}--param-name-${i}`}>
            Parameter {i + 1} name
          </label>
          <input
            id={`${fieldId(pointer)}--param-name-${i}`}
            className="control"
            type="text"
            value={param.name}
            onChange={(event) =>
              onChange({
                ...source,
                params: source.params.map((p, j) =>
                  j === i ? { ...p, name: event.target.value } : p,
                ),
              })
            }
          />
          <label className="field__label" htmlFor={fieldId(jptr(pointer, 'params', i))}>
            Parameter {i + 1} type
          </label>
          <select
            id={fieldId(jptr(pointer, 'params', i))}
            className="control"
            value={param.type}
            onChange={(event) =>
              onChange({
                ...source,
                params: source.params.map((p, j) =>
                  j === i ? { ...p, type: event.target.value as PolicyType } : p,
                ),
              })
            }
          >
            {allTypes().map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </div>
      ))}
      <button
        type="button"
        className="button"
        onClick={() =>
          onChange({ ...source, params: [...source.params, { name: '', type: 'string' }] })
        }
      >
        Add parameter
      </button>
      <Field pointer={jptr(pointer, 'returns')} label="Return type" placed={placed}>
        {(props) => (
          <select
            {...props}
            className="control"
            value={source.returns}
            onChange={(event) => onChange({ ...source, returns: event.target.value as PolicyType })}
          >
            {allTypes().map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        )}
      </Field>
      <Field
        pointer={jptr(pointer, 'on_error')}
        label="Failure behaviour"
        hint="allow only permits anything if the deployment enables it as well. The declaration alone does not open it."
        placed={placed}
      >
        {(props) => (
          <select
            {...props}
            className="control"
            value={source.onError}
            onChange={(event) => onChange({ ...source, onError: event.target.value as OnError })}
          >
            {ON_ERRORS.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        )}
      </Field>
      <button type="button" className="button button--quiet" onClick={onRemove}>
        Delete source {index + 1}
      </button>
    </FieldGroup>
  )
}

export function DeclarationsEditor({
  schema,
  placed,
  onChange,
}: {
  readonly schema: SchemaDraft
  readonly placed: PlacedDiagnostics
  readonly onChange: (next: SchemaDraft) => void
}) {
  return (
    <div className="declarations">
      {hasNoDeclarations(schema) ? (
        <p data-testid="declarations-empty">
          This authoring session has no declarations at all. The policy form is rendered from the
          declarations, so an entity has to be declared before a condition can be written.
        </p>
      ) : null}

      <h3>entity</h3>
      {schema.entities.map((entity, index) => (
        <EntityEditor
          key={index}
          placed={placed}
          index={index}
          entity={entity}
          onChange={(next) =>
            onChange({
              ...schema,
              entities: schema.entities.map((e, i) => (i === index ? next : e)),
            })
          }
          onRemove={() =>
            onChange({ ...schema, entities: schema.entities.filter((_, i) => i !== index) })
          }
        />
      ))}
      <button
        type="button"
        className="button button--primary"
        onClick={() => onChange({ ...schema, entities: [...schema.entities, { name: '', attributes: [] }] })}
      >
        Add entity declaration
      </button>

      <h3>action</h3>
      {schema.actions.map((action, index) => (
        <ActionEditor
          key={index}
          placed={placed}
          index={index}
          action={action}
          onChange={(next) =>
            onChange({ ...schema, actions: schema.actions.map((a, i) => (i === index ? next : a)) })
          }
          onRemove={() =>
            onChange({ ...schema, actions: schema.actions.filter((_, i) => i !== index) })
          }
        />
      ))}
      <button
        type="button"
        className="button"
        onClick={() => onChange({ ...schema, actions: [...schema.actions, { name: '', description: '' }] })}
      >
        Add action declaration
      </button>

      <h3>fact source</h3>
      {schema.sources.map((source, index) => (
        <SourceEditor
          key={index}
          placed={placed}
          index={index}
          source={source}
          onChange={(next) =>
            onChange({ ...schema, sources: schema.sources.map((s, i) => (i === index ? next : s)) })
          }
          onRemove={() =>
            onChange({ ...schema, sources: schema.sources.filter((_, i) => i !== index) })
          }
        />
      ))}
      <button
        type="button"
        className="button"
        onClick={() =>
          onChange({
            ...schema,
            sources: [
              ...schema.sources,
              { name: '', kind: 'http', params: [], returns: 'string', onError: 'deny' },
            ],
          })
        }
      >
        Add source declaration
      </button>
    </div>
  )
}

export { KIND_NOTES }
