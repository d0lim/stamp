/**
 * The form's output: the exchange format, and nothing else.
 *
 * R10 makes the file the exchange format and requires form authoring and file
 * authoring to round-trip through the same one, so the builder does not have a
 * wire shape of its own. Every call it makes carries an exchange-format
 * document: the dry run takes one, and a revision delta carries one per side of
 * each change. The console therefore writes YAML and never a struct dump, which
 * is also what keeps a form-authored policy readable in the diff an approver
 * sees.
 *
 * Two rules govern how a value is written, and both exist to make the D8 trade
 * hold at the serialization boundary rather than only in the editor.
 *
 * Every literal is written in the explicit `{value, type}` form. The decoder has
 * a second path — a bare scalar whose type YAML resolves from its tag — and this
 * never uses it. Under tag inference the text `2026-01-01` is a timestamp, `010`
 * is an int, `yes` is a bool in some readers, and an author who typed a string
 * would get whatever YAML thought. The explicit form hands the declared type to
 * the decoder's `scalarData`, which parses the raw text under exactly that type.
 *
 * Every author-supplied scalar is double-quoted and escaped. That is what makes
 * "the form cannot express what the AST cannot hold" survive contact with a
 * text box: `{field: subject.id}` typed into a value box serializes as a quoted
 * string containing braces, which the decoder reads as a string constant. There
 * is no text an author can type that becomes a node.
 */
import {
  type ApproverSetDraft,
  type ChallengeDraft,
  type ConditionNode,
  type Draft,
  type Operand,
  type PolicyDraft,
  type SchemaDraft,
  hasNoDeclarations,
} from './model'

/** The version tag every document carries, from policy.APIVersion. */
export const API_VERSION = 'stamp/v1'

// ---------------------------------------------------------------------------
// a YAML writer, small enough to read
// ---------------------------------------------------------------------------

type YNode = YScalar | YMap | YSeq

interface YScalar {
  readonly t: 'scalar'
  readonly text: string
}
interface YMap {
  readonly t: 'map'
  readonly entries: readonly (readonly [string, YNode])[]
  readonly flow: boolean
}
interface YSeq {
  readonly t: 'seq'
  readonly items: readonly YNode[]
  readonly flow: boolean
}

function raw(text: string): YScalar {
  return { t: 'scalar', text }
}

/**
 * A double-quoted YAML scalar.
 *
 * Quoting is unconditional. A plain scalar's meaning depends on its content —
 * `no`, `1.0`, `2026-01-01`, a leading `*` or `&` — and the one thing this
 * console must never do is let the shape of an author's text decide how the
 * document parses.
 */
function q(value: string): YScalar {
  let out = '"'
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0
    if (ch === '\\') out += '\\\\'
    else if (ch === '"') out += '\\"'
    else if (ch === '\n') out += '\\n'
    else if (ch === '\r') out += '\\r'
    else if (ch === '\t') out += '\\t'
    else if (code < 0x20 || code === 0x7f) out += '\\x' + code.toString(16).padStart(2, '0')
    else out += ch
  }
  return raw(out + '"')
}

function map(entries: readonly (readonly [string, YNode])[], flow = false): YMap {
  return { t: 'map', entries, flow: flow || entries.length === 0 }
}

function seq(items: readonly YNode[], flow = false): YSeq {
  return { t: 'seq', items, flow: flow || items.length === 0 }
}

function inline(node: YNode): string {
  switch (node.t) {
    case 'scalar':
      return node.text
    case 'map':
      return `{${node.entries.map(([k, v]) => `${k}: ${inline(v)}`).join(', ')}}`
    case 'seq':
      return `[${node.items.map(inline).join(', ')}]`
  }
}

function emit(node: YNode, indent: number): string[] {
  const pad = ' '.repeat(indent)
  if (node.t === 'scalar' || node.flow) return [pad + inline(node)]
  if (node.t === 'map') {
    const lines: string[] = []
    for (const [key, value] of node.entries) {
      if (value.t === 'scalar' || value.flow) {
        lines.push(`${pad}${key}: ${inline(value)}`)
        continue
      }
      lines.push(`${pad}${key}:`)
      lines.push(...emit(value, indent + 2))
    }
    return lines
  }
  const lines: string[] = []
  for (const item of node.items) {
    if (item.t === 'scalar' || item.flow) {
      lines.push(`${pad}- ${inline(item)}`)
      continue
    }
    const sub = emit(item, indent + 2)
    const head = sub[0] ?? ''
    sub[0] = `${pad}- ${head.slice(indent + 2)}`
    lines.push(...sub)
  }
  return lines
}

function document(node: YMap): string {
  return emit(node, 0).join('\n') + '\n'
}

// ---------------------------------------------------------------------------
// operands and conditions
// ---------------------------------------------------------------------------

function operandNode(operand: Operand): YNode {
  switch (operand.kind) {
    case 'field':
      return map([['field', q(`${operand.role}.${operand.attribute}`)]], true)
    case 'source': {
      const entries: (readonly [string, YNode])[] = [['source', q(operand.name)]]
      if (operand.args.length > 0) {
        entries.push(['args', seq(operand.args.map(operandNode), true)])
      }
      return map(entries, true)
    }
    case 'literal': {
      const values = operand.type.startsWith('list<')
        ? seq(operand.values.map(q), true)
        : q(operand.values[0] ?? '')
      return map(
        [
          ['value', values],
          ['type', q(operand.type)],
        ],
        true,
      )
    }
  }
}

function conditionNode(node: ConditionNode): YNode {
  switch (node.kind) {
    case 'logic':
      if (node.op === 'not') {
        const inner = node.operands[0]
        return map([['not', inner ? conditionNode(inner) : map([])]])
      }
      return map([[node.op, seq(node.operands.map(conditionNode))]])
    case 'compare':
      return map([
        ['left', operandNode(node.left)],
        ['op', q(node.op)],
        ['right', operandNode(node.right)],
      ])
    case 'member':
      return map([
        ['left', operandNode(node.left)],
        [node.negate ? 'not_in' : 'in', operandNode(node.collection)],
      ])
  }
}

function approverNode(set: ApproverSetDraft): YNode {
  switch (set.mode) {
    case 'claim':
      return map([['claim', q(set.claim)]], true)
    case 'source': {
      const entries: (readonly [string, YNode])[] = [['source', q(set.source.name)]]
      if (set.source.args.length > 0) {
        entries.push(['args', seq(set.source.args.map(operandNode), true)])
      }
      return map(entries, true)
    }
    case 'members':
      return map([['members', seq(set.members.map(q), true)]], true)
  }
}

function challengeNode(challenge: ChallengeDraft): YNode {
  switch (challenge.type) {
    case 'quorum':
      return map([
        ['type', q('quorum')],
        ['threshold', raw(String(Math.trunc(challenge.threshold)))],
        ['approvers', approverNode(challenge.approvers)],
      ])
    case 'mfa': {
      const entries: (readonly [string, YNode])[] = [
        ['type', q('mfa')],
        ['mode', q(challenge.mode)],
      ]
      if (challenge.acrValues.length > 0) {
        entries.push(['acr_values', seq(challenge.acrValues.map(q), true)])
      }
      return map(entries)
    }
    case 'delay': {
      const entries: (readonly [string, YNode])[] = [
        ['type', q('delay')],
        ['duration', q(challenge.duration)],
      ]
      if (challenge.cancellable) {
        entries.push(['cancellable_by', approverNode(challenge.cancellableBy)])
      }
      return map(entries)
    }
    case 'external':
      return map([
        ['type', q('external')],
        ['target', q(challenge.target)],
      ])
  }
}

// ---------------------------------------------------------------------------
// documents
// ---------------------------------------------------------------------------

/** Renders the declarations as a Schema document. */
export function serializeSchema(schema: SchemaDraft): string {
  const entries: (readonly [string, YNode])[] = [
    ['apiVersion', q(API_VERSION)],
    ['kind', q('Schema')],
  ]
  if (schema.entities.length > 0) {
    entries.push([
      'entities',
      seq(
        schema.entities.map((entity) =>
          map([
            ['name', q(entity.name)],
            ['attributes', map(entity.attributes.map((a) => [q(a.name).text, q(a.type)] as const))],
          ]),
        ),
      ),
    ])
  }
  if (schema.actions.length > 0) {
    entries.push([
      'actions',
      seq(
        schema.actions.map((action) => {
          const fields: (readonly [string, YNode])[] = [['name', q(action.name)]]
          if (action.description !== '') fields.push(['description', q(action.description)])
          return map(fields)
        }),
      ),
    ])
  }
  if (schema.sources.length > 0) {
    entries.push([
      'sources',
      seq(
        schema.sources.map((source) => {
          const fields: (readonly [string, YNode])[] = [
            ['name', q(source.name)],
            ['kind', q(source.kind)],
          ]
          if (source.params.length > 0) {
            fields.push([
              'params',
              seq(
                source.params.map((p) => map([[q(p.name).text, q(p.type)]], true)),
                false,
              ),
            ])
          }
          fields.push(['returns', q(source.returns)])
          fields.push(['on_error', q(source.onError)])
          return map(fields)
        }),
      ),
    ])
  }
  return document(map(entries))
}

/** Renders the policy under authoring as a Policy document. */
export function serializePolicy(policy: PolicyDraft): string {
  const entries: (readonly [string, YNode])[] = [
    ['apiVersion', q(API_VERSION)],
    ['kind', q('Policy')],
    ['id', q(policy.id)],
  ]
  if (policy.description !== '') entries.push(['description', q(policy.description)])
  entries.push(['subject', q(policy.subject)])
  entries.push(['resource', q(policy.resource)])
  if (policy.context !== '') entries.push(['context', q(policy.context)])
  entries.push(['actions', seq(policy.actions.map(q), true)])
  if (policy.condition !== null) entries.push(['condition', conditionNode(policy.condition)])
  if (policy.challenges.length > 0) {
    entries.push(['challenges', seq(policy.challenges.map(challengeNode))])
  }
  return document(map(entries))
}

/**
 * Renders the whole draft as the document stream a dry run evaluates.
 *
 * The schema document is omitted when the author has declared nothing, because
 * the dry-run endpoint fills an absent schema in from the deployment's effective
 * one — which is how a draft gets tried against what is actually in force
 * rather than against an empty vocabulary.
 */
export function serializeDraft(draft: Draft): string {
  const policy = serializePolicy(draft.policy)
  if (hasNoDeclarations(draft.schema)) return policy
  return `${serializeSchema(draft.schema)}---\n${policy}`
}
