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
  static: '배포 설정에 고정된 값을 돌려줍니다. 호출이 없습니다.',
  http: '동기 HTTP 호출입니다. 호출 대상과 캐시 TTL은 운영자의 fact plane 설정이며 선언에 담기지 않습니다.',
  event: '비동기 이벤트 집계를 읽습니다. 스트림과 윈도 정의는 운영자 설정입니다.',
  idp_group: 'IdP 그룹 조회입니다. 승인자 집합 해석에도 같은 선언을 씁니다.',
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
        label="이름"
        hint="소문자로 시작하고 소문자·숫자·밑줄만 씁니다 — CEL 식별자가 됩니다."
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
            속성 {i + 1} 이름
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
            속성 {i + 1} 타입
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
            속성 {i + 1} 삭제
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
        속성 추가
      </button>
      <button type="button" className="button button--quiet" onClick={onRemove}>
        entity {index + 1} 삭제
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
      <Field pointer={jptr(pointer, 'name')} label="이름" placed={placed}>
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
          설명
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
        action {index + 1} 삭제
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
      <Field pointer={jptr(pointer, 'name')} label="이름" placed={placed}>
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
        label="종류"
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
            인자 {i + 1} 이름
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
            인자 {i + 1} 타입
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
        인자 추가
      </button>
      <Field pointer={jptr(pointer, 'returns')} label="반환 타입" placed={placed}>
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
        label="실패 동작"
        hint="allow는 배포 단위로도 켜져 있어야 실제로 허용됩니다. 선언만으로는 열리지 않습니다."
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
        source {index + 1} 삭제
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
          이 저작 세션에는 선언이 하나도 없습니다. 정책 폼은 선언에서 렌더링되므로, 먼저 entity를
          하나 선언해야 조건을 쓸 수 있습니다.
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
        entity 선언 추가
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
        action 선언 추가
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
        source 선언 추가
      </button>
    </div>
  )
}

export { KIND_NOTES }
