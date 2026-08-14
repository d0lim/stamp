/**
 * The rule editor: the AST, drawn.
 *
 * Every control here corresponds to a field of a node in internal/policy/ast.go,
 * and the palette an author picks from is NODE_KINDS and OPERAND_KINDS — the
 * same lists the serializer switches over. There is no "advanced" tab, no
 * expression box, and no place to add one; that absence is D8's price paid in
 * full and D12's guarantee collected.
 *
 * Two narrowings are the AST's, not this editor's taste:
 *
 *   The left side of a rule offers only a field or a fact source. Compare.Left
 *   is a Reference, so a constant on the left is not a shape the AST has.
 *
 *   A fact source's arguments offer a field or a constant, never another source
 *   call. SourceRef documents that its arguments may not themselves be source
 *   calls, and the validator refuses one — so the form does not draw it.
 *
 * The operator list narrows to equality when the left side's declared type is
 * unordered, and only when that type is known. That is the form declining to
 * offer a shape the AST rejects, which is different from validating: when the
 * type is not yet known the form offers everything and the server decides.
 */
import {
  COMPARE_OPS,
  LOGIC_OPS,
  NODE_KINDS,
  OPERAND_KINDS,
  ORDERING_OPS,
  ROLES,
  allTypes,
  attributesFor,
  elemType,
  fieldType,
  isListType,
  newNode,
  newOperand,
  sourceDecl,
  type CompareOp,
  type ConditionNode,
  type Draft,
  type LogicOp,
  type NodeKind,
  type Operand,
  type OperandKind,
  type PolicyType,
  type ReferenceOperand,
  type Role,
} from './model'
import { Field, FieldGroup } from './Field'
import type { PlacedDiagnostics } from './diagnostics'
import { fieldId, jptr } from './pointer'

// The node and operand labels are lowercase noun phrases because they are read
// inside a sentence as often as they are read alone — "Add comparison rule" and
// "Delete comparison rule" are the same words the group's legend carries.
const NODE_LABELS: Readonly<Record<NodeKind, string>> = {
  logic: 'logic group',
  compare: 'comparison rule',
  member: 'membership rule',
}

const LOGIC_LABELS: Readonly<Record<LogicOp, string>> = {
  all: 'all must hold (all)',
  any: 'at least one must hold (any)',
  not: 'negation (not)',
}

const COMPARE_LABELS: Readonly<Record<CompareOp, string>> = {
  eq: 'equals (eq)',
  ne: 'does not equal (ne)',
  lt: 'less than (lt)',
  le: 'less than or equal to (le)',
  gt: 'greater than (gt)',
  ge: 'greater than or equal to (ge)',
}

const OPERAND_LABELS: Readonly<Record<OperandKind, string>> = {
  field: 'entity attribute',
  source: 'fact source call',
  literal: 'constant',
}

/** Types that lt/le/gt/ge accept, from policy.Type.IsOrdered. */
const UNORDERED: readonly PolicyType[] = ['bool']

function operandType(draft: Draft, operand: Operand): PolicyType | null {
  switch (operand.kind) {
    case 'field':
      return fieldType(draft, operand)
    case 'source':
      return sourceDecl(draft, operand.name)?.returns ?? null
    case 'literal':
      return operand.type
  }
}

function orderedType(type: PolicyType | null): boolean {
  if (type === null) return true
  return !isListType(type) && !UNORDERED.includes(type)
}

export interface EditorContext {
  readonly draft: Draft
  readonly placed: PlacedDiagnostics
}

// ---------------------------------------------------------------------------
// operands
// ---------------------------------------------------------------------------

function OperandEditor({
  context,
  pointer,
  label,
  operand,
  allowed,
  onChange,
}: {
  readonly context: EditorContext
  readonly pointer: string
  readonly label: string
  readonly operand: Operand
  readonly allowed: readonly OperandKind[]
  readonly onChange: (next: Operand) => void
}) {
  const { draft, placed } = context
  const kindId = `${fieldId(pointer)}--kind`

  return (
    <div className="operand">
      <div className="field">
        <label className="field__label" htmlFor={kindId}>
          {label} kind
        </label>
        <select
          id={kindId}
          className="control"
          value={operand.kind}
          onChange={(event) => onChange(newOperand(event.target.value as OperandKind))}
        >
          {allowed.map((kind) => (
            <option key={kind} value={kind}>
              {OPERAND_LABELS[kind]}
            </option>
          ))}
        </select>
      </div>

      {operand.kind === 'field' ? (
        <>
          <Field pointer={pointer} label={`${label} — role`} placed={placed}>
            {(props) => (
              <select
                {...props}
                className="control"
                value={operand.role}
                onChange={(event) =>
                  onChange({ ...operand, role: event.target.value as Role, attribute: '' })
                }
              >
                {ROLES.map((role) => (
                  <option key={role} value={role}>
                    {role}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <div className="field">
            <label className="field__label" htmlFor={`${fieldId(pointer)}--attribute`}>
              {label} — attribute
            </label>
            <select
              id={`${fieldId(pointer)}--attribute`}
              className="control"
              value={operand.attribute}
              onChange={(event) => onChange({ ...operand, attribute: event.target.value })}
            >
              <option value="">Select one</option>
              {attributesFor(draft, operand.role).map((attribute) => (
                <option key={attribute.name} value={attribute.name}>
                  {attribute.name} ({attribute.type})
                </option>
              ))}
            </select>
          </div>
        </>
      ) : null}

      {operand.kind === 'source' ? (
        <SourceOperandEditor
          context={context}
          pointer={pointer}
          label={label}
          operand={operand}
          onChange={onChange}
        />
      ) : null}

      {operand.kind === 'literal' ? (
        <>
          <Field pointer={pointer} label={`${label} — type`} placed={placed}>
            {(props) => (
              <select
                {...props}
                className="control"
                value={operand.type}
                onChange={(event) =>
                  onChange({ ...operand, type: event.target.value as PolicyType, values: [''] })
                }
              >
                {allTypes().map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <LiteralValues label={label} pointer={pointer} operand={operand} onChange={onChange} />
        </>
      ) : null}
    </div>
  )
}

function SourceOperandEditor({
  context,
  pointer,
  label,
  operand,
  onChange,
}: {
  readonly context: EditorContext
  readonly pointer: string
  readonly label: string
  readonly operand: Extract<Operand, { kind: 'source' }>
  readonly onChange: (next: Operand) => void
}) {
  const { draft, placed } = context
  const declaration = sourceDecl(draft, operand.name)

  return (
    <>
      <Field
        pointer={pointer}
        label={`${label} — fact source`}
        hint="Only a declared source can be chosen. A name that is not in the declarations does not appear here."
        placed={placed}
      >
        {(props) => (
          <select
            {...props}
            className="control"
            value={operand.name}
            onChange={(event) => {
              const next = sourceDecl(draft, event.target.value)
              onChange({
                kind: 'source',
                name: event.target.value,
                // The argument list is the declared signature's shape, so it is
                // rebuilt from the declaration rather than carried over from
                // whichever source was selected before.
                args: (next?.params ?? []).map(() => newOperand('literal')),
              })
            }}
          >
            <option value="">Select one</option>
            {draft.schema.sources.map((source) => (
              <option key={source.name} value={source.name}>
                {source.name} → {source.returns}
              </option>
            ))}
          </select>
        )}
      </Field>
      {declaration?.params.map((param, index) => (
        <OperandEditor
          key={param.name}
          context={context}
          pointer={jptr(pointer, 'args', index)}
          label={`Argument ${param.name} (${param.type})`}
          operand={operand.args[index] ?? newOperand('literal')}
          // SourceRef arguments may not be source calls; the AST says so and the
          // validator refuses one, so the palette does not offer it.
          allowed={['field', 'literal']}
          onChange={(next) =>
            onChange({
              ...operand,
              args: operand.args.map((arg, i) => (i === index ? next : arg)),
            })
          }
        />
      ))}
    </>
  )
}

function LiteralValues({
  label,
  pointer,
  operand,
  onChange,
}: {
  readonly label: string
  readonly pointer: string
  readonly operand: Extract<Operand, { kind: 'literal' }>
  readonly onChange: (next: Operand) => void
}) {
  const element = elemType(operand.type)
  if (element === null) {
    return (
      <div className="field">
        <label className="field__label" htmlFor={`${fieldId(pointer)}--value`}>
          {label} — value
        </label>
        <input
          id={`${fieldId(pointer)}--value`}
          className="control"
          type="text"
          value={operand.values[0] ?? ''}
          onChange={(event) => onChange({ ...operand, values: [event.target.value] })}
        />
      </div>
    )
  }
  return (
    <div className="literal-list">
      <p className="field__label">
        {label} — list items ({element})
      </p>
      {operand.values.map((value, index) => (
        <div className="field field--inline" key={index}>
          <label className="field__label" htmlFor={`${fieldId(pointer)}--value-${index}`}>
            Item {index + 1}
          </label>
          <input
            id={`${fieldId(pointer)}--value-${index}`}
            className="control"
            type="text"
            value={value}
            onChange={(event) =>
              onChange({
                ...operand,
                values: operand.values.map((v, i) => (i === index ? event.target.value : v)),
              })
            }
          />
          <button
            type="button"
            className="button button--quiet"
            onClick={() =>
              onChange({ ...operand, values: operand.values.filter((_, i) => i !== index) })
            }
          >
            Delete item {index + 1}
          </button>
        </div>
      ))}
      <button
        type="button"
        className="button"
        onClick={() => onChange({ ...operand, values: [...operand.values, ''] })}
      >
        Add list item
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// nodes
// ---------------------------------------------------------------------------

function AddNodeButtons({ onAdd }: { readonly onAdd: (kind: NodeKind) => void }) {
  return (
    <div className="palette" data-testid="condition-palette">
      {NODE_KINDS.map((kind) => (
        <button
          key={kind}
          type="button"
          className="button"
          data-node-kind={kind}
          onClick={() => onAdd(kind)}
        >
          Add {NODE_LABELS[kind]}
        </button>
      ))}
    </div>
  )
}

function NodeEditor({
  context,
  pointer,
  node,
  onChange,
  onRemove,
}: {
  readonly context: EditorContext
  readonly pointer: string
  readonly node: ConditionNode
  readonly onChange: (next: ConditionNode) => void
  readonly onRemove: () => void
}) {
  const { placed } = context

  if (node.kind === 'logic') {
    const canAdd = node.op !== 'not' || node.operands.length === 0
    return (
      <FieldGroup pointer={pointer} legend={NODE_LABELS.logic} placed={placed} className="node">
        <div className="field">
          <label className="field__label" htmlFor={`${fieldId(pointer)}--op`}>
            Combination
          </label>
          <select
            id={`${fieldId(pointer)}--op`}
            className="control"
            value={node.op}
            onChange={(event) => {
              const op = event.target.value as LogicOp
              onChange({
                ...node,
                op,
                // `not` takes exactly one operand. Trimming here is what keeps
                // the form from holding a shape the AST would reject.
                operands: op === 'not' ? node.operands.slice(0, 1) : node.operands,
              })
            }}
          >
            {LOGIC_OPS.map((op) => (
              <option key={op} value={op}>
                {LOGIC_LABELS[op]}
              </option>
            ))}
          </select>
        </div>
        <ol className="node__children">
          {node.operands.map((child, index) => (
            <li key={index}>
              <NodeEditor
                context={context}
                pointer={node.op === 'not' ? jptr(pointer, 'not') : jptr(pointer, node.op, index)}
                node={child}
                onChange={(next) =>
                  onChange({
                    ...node,
                    operands: node.operands.map((c, i) => (i === index ? next : c)),
                  })
                }
                onRemove={() =>
                  onChange({ ...node, operands: node.operands.filter((_, i) => i !== index) })
                }
              />
            </li>
          ))}
        </ol>
        {canAdd ? (
          <AddNodeButtons
            onAdd={(kind) => onChange({ ...node, operands: [...node.operands, newNode(kind)] })}
          />
        ) : null}
        <button type="button" className="button button--quiet" onClick={onRemove}>
          Delete {NODE_LABELS.logic}
        </button>
      </FieldGroup>
    )
  }

  if (node.kind === 'compare') {
    const leftType = operandType(context.draft, node.left)
    const operators = orderedType(leftType)
      ? COMPARE_OPS
      : COMPARE_OPS.filter((op) => !ORDERING_OPS.includes(op))
    const opPointer = jptr(pointer, 'op')
    return (
      <FieldGroup pointer={pointer} legend={NODE_LABELS.compare} placed={placed} className="node">
        <OperandEditor
          context={context}
          pointer={jptr(pointer, 'left')}
          label="Left operand"
          operand={node.left}
          allowed={['field', 'source']}
          onChange={(next) => onChange({ ...node, left: next as ReferenceOperand })}
        />
        <Field pointer={opPointer} label="Operator" placed={placed}>
          {(props) => (
            <select
              {...props}
              className="control"
              value={node.op}
              onChange={(event) => onChange({ ...node, op: event.target.value as CompareOp })}
            >
              {operators.map((op) => (
                <option key={op} value={op}>
                  {COMPARE_LABELS[op]}
                </option>
              ))}
            </select>
          )}
        </Field>
        <OperandEditor
          context={context}
          pointer={jptr(pointer, 'right')}
          label="Right operand"
          operand={node.right}
          allowed={OPERAND_KINDS}
          onChange={(next) => onChange({ ...node, right: next })}
        />
        <button type="button" className="button button--quiet" onClick={onRemove}>
          Delete {NODE_LABELS.compare}
        </button>
      </FieldGroup>
    )
  }

  const collectionPointer = jptr(pointer, node.negate ? 'not_in' : 'in')
  return (
    <FieldGroup pointer={pointer} legend={NODE_LABELS.member} placed={placed} className="node">
      <OperandEditor
        context={context}
        pointer={jptr(pointer, 'left')}
        label="Left operand"
        operand={node.left}
        allowed={['field', 'source']}
        onChange={(next) => onChange({ ...node, left: next as ReferenceOperand })}
      />
      <div className="field">
        <label className="field__label" htmlFor={`${fieldId(pointer)}--negate`}>
          Membership direction
        </label>
        <select
          id={`${fieldId(pointer)}--negate`}
          className="control"
          value={node.negate ? 'not_in' : 'in'}
          onChange={(event) => onChange({ ...node, negate: event.target.value === 'not_in' })}
        >
          <option value="in">is in (in)</option>
          <option value="not_in">is not in (not_in)</option>
        </select>
      </div>
      <OperandEditor
        context={context}
        pointer={collectionPointer}
        label="Collection"
        operand={node.collection}
        allowed={OPERAND_KINDS}
        onChange={(next) => onChange({ ...node, collection: next })}
      />
      <button type="button" className="button button--quiet" onClick={onRemove}>
        Delete {NODE_LABELS.member}
      </button>
    </FieldGroup>
  )
}

export function ConditionEditor({
  draft,
  placed,
  pointer,
  onChange,
}: {
  readonly draft: Draft
  readonly placed: PlacedDiagnostics
  readonly pointer: string
  readonly onChange: (next: ConditionNode | null) => void
}) {
  const context: EditorContext = { draft, placed }
  const condition = draft.policy.condition

  if (condition === null) {
    return (
      <div className="node node--empty" id={fieldId(pointer)} tabIndex={-1}>
        <p>
          There is no condition. A policy without a condition always applies to the entities and
          actions it is bound to.
        </p>
        <AddNodeButtons onAdd={(kind) => onChange(newNode(kind))} />
      </div>
    )
  }

  return (
    <NodeEditor
      context={context}
      pointer={pointer}
      node={condition}
      onChange={onChange}
      onRemove={() => onChange(null)}
    />
  )
}
