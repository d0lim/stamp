/**
 * The form's state, which is the condition AST and nothing else.
 *
 * D8 chose the form builder over a rule canvas and over code-with-preview, and
 * it chose it knowing the price: v1's policy expressiveness is bounded by what a
 * form can render. D12 is how that price is *collected* — the AST is closed, and
 * this module is its mirror. Every type here corresponds one-to-one with a type
 * in internal/policy/ast.go:
 *
 *   Logic / Compare / Member          → ConditionNode
 *   FieldRef / SourceRef / Literal    → Operand
 *
 * There is no node for an arbitrary expression, and — this is the part that
 * matters — there is no *place to put one*. A form row is chosen from
 * NODE_KINDS, an operand from OPERAND_KINDS, and both lists are `as const`
 * unions that the serializer switches over exhaustively. Adding a variant to
 * either one without also giving it a row and a serialization is a type error,
 * not a runtime surprise. That is what makes "the form cannot express a
 * condition the AST cannot hold" a structural property rather than a discipline.
 *
 * Free text never becomes structure. A value typed into a box is a
 * LiteralOperand — a declared type plus its raw text — and serialize.ts writes
 * every literal in the explicit `{value, type}` form with the text quoted. Text
 * that looks like `{field: subject.id}` therefore serializes as a string
 * constant that happens to contain braces, which is the only reading of it the
 * AST has.
 */

/** The logical combinators, from policy.LogicOp. */
export const LOGIC_OPS = ['all', 'any', 'not'] as const
export type LogicOp = (typeof LOGIC_OPS)[number]

/** The comparison operators, from policy.CompareOp. */
export const COMPARE_OPS = ['eq', 'ne', 'lt', 'le', 'gt', 'ge'] as const
export type CompareOp = (typeof COMPARE_OPS)[number]

/** The operators that need an ordered operand type, from CompareOp.Ordering. */
export const ORDERING_OPS: readonly CompareOp[] = ['lt', 'le', 'gt', 'ge']

/** The scalar types, from policy.ScalarTypes. */
export const SCALAR_TYPES = ['bool', 'int', 'double', 'string', 'timestamp', 'duration'] as const
export type ScalarType = (typeof SCALAR_TYPES)[number]

/** A declared type: a scalar or a homogeneous list of scalars. */
export type PolicyType = ScalarType | `list<${ScalarType}>`

/** The entity roles a policy may bind, from policy.Roles. */
export const ROLES = ['subject', 'resource', 'context'] as const
export type Role = (typeof ROLES)[number]

/** The fact source kinds, from policy.SourceKinds. */
export const SOURCE_KINDS = ['static', 'http', 'event', 'idp_group'] as const
export type SourceKind = (typeof SOURCE_KINDS)[number]

/** The fact source failure behaviours, from policy.OnError. */
export const ON_ERRORS = ['deny', 'allow'] as const
export type OnError = (typeof ON_ERRORS)[number]

/** The challenge kinds, from policy.ChallengeTypes. The set is closed for v1. */
export const CHALLENGE_TYPES = ['quorum', 'mfa', 'delay', 'external'] as const
export type ChallengeType = (typeof CHALLENGE_TYPES)[number]

/** The MFA modes. v1 implements `delegated`; `direct` is refused at load. */
export const MFA_MODES = ['delegated', 'direct'] as const
export type MFAMode = (typeof MFA_MODES)[number]

/**
 * The condition node kinds a form row can be.
 *
 * This list is the palette the rule editor offers and the set the serializer
 * handles. They are the same list on purpose: a kind the editor could produce
 * and the serializer could not is exactly the failure D12 forecloses.
 */
export const NODE_KINDS = ['logic', 'compare', 'member'] as const
export type NodeKind = (typeof NODE_KINDS)[number]

/** The operand kinds, mirroring FieldRef, SourceRef and Literal. */
export const OPERAND_KINDS = ['field', 'source', 'literal'] as const
export type OperandKind = (typeof OPERAND_KINDS)[number]

/** Reads one declared attribute of one bound entity role. */
export interface FieldOperand {
  readonly kind: 'field'
  readonly role: Role
  readonly attribute: string
}

/** Calls a declared fact source with positional arguments. */
export interface SourceOperand {
  readonly kind: 'source'
  readonly name: string
  readonly args: readonly Operand[]
}

/**
 * A constant of a declared type.
 *
 * The value is kept as the text the input holds, with the type declared beside
 * it, rather than as a parsed value. Two reasons: an author mid-keystroke has
 * text that is not yet a number, and the server is the one authority on whether
 * `2026-13-01` is a timestamp — reimplementing that check here would give the
 * console a second opinion about validity.
 */
export interface LiteralOperand {
  readonly kind: 'literal'
  readonly type: PolicyType
  /** One entry for a scalar; one per element for a list. */
  readonly values: readonly string[]
}

/** An operand that reads something the schema declares. */
export type ReferenceOperand = FieldOperand | SourceOperand
export type Operand = ReferenceOperand | LiteralOperand

/** Combines child conditions. `not` carries exactly one operand. */
export interface LogicNode {
  readonly kind: 'logic'
  readonly op: LogicOp
  readonly operands: readonly ConditionNode[]
}

/**
 * Relates a reference to another operand.
 *
 * The left side is a Reference and never a constant, which is the AST's own
 * asymmetry and also how a form row reads: attribute picker on the left, value
 * box on the right.
 */
export interface CompareNode {
  readonly kind: 'compare'
  readonly left: ReferenceOperand
  readonly op: CompareOp
  readonly right: Operand
}

/** Tests whether a reference's value appears in a collection. */
export interface MemberNode {
  readonly kind: 'member'
  readonly left: ReferenceOperand
  readonly collection: Operand
  readonly negate: boolean
}

export type ConditionNode = LogicNode | CompareNode | MemberNode

// ---------------------------------------------------------------------------
// declarations
// ---------------------------------------------------------------------------

export interface AttributeDraft {
  readonly name: string
  readonly type: PolicyType
}

export interface EntityDraft {
  readonly name: string
  readonly attributes: readonly AttributeDraft[]
}

export interface ActionDraft {
  readonly name: string
  readonly description: string
}

export interface ParamDraft {
  readonly name: string
  readonly type: PolicyType
}

export interface SourceDraft {
  readonly name: string
  readonly kind: SourceKind
  readonly params: readonly ParamDraft[]
  readonly returns: PolicyType
  readonly onError: OnError
}

export interface SchemaDraft {
  readonly entities: readonly EntityDraft[]
  readonly actions: readonly ActionDraft[]
  readonly sources: readonly SourceDraft[]
}

// ---------------------------------------------------------------------------
// challenges
// ---------------------------------------------------------------------------

/** How an approver set resolves. Exactly one resolution is in force. */
export const APPROVER_MODES = ['members', 'claim', 'source'] as const
export type ApproverMode = (typeof APPROVER_MODES)[number]

export interface ApproverSetDraft {
  readonly mode: ApproverMode
  readonly members: readonly string[]
  readonly claim: string
  readonly source: SourceOperand
}

export interface QuorumChallengeDraft {
  readonly type: 'quorum'
  readonly threshold: number
  readonly approvers: ApproverSetDraft
}

export interface MFAChallengeDraft {
  readonly type: 'mfa'
  readonly mode: MFAMode
  readonly acrValues: readonly string[]
}

export interface DelayChallengeDraft {
  readonly type: 'delay'
  readonly duration: string
  readonly cancellable: boolean
  readonly cancellableBy: ApproverSetDraft
}

export interface ExternalChallengeDraft {
  readonly type: 'external'
  readonly target: string
}

export type ChallengeDraft =
  | QuorumChallengeDraft
  | MFAChallengeDraft
  | DelayChallengeDraft
  | ExternalChallengeDraft

// ---------------------------------------------------------------------------
// the policy under authoring
// ---------------------------------------------------------------------------

export interface PolicyDraft {
  readonly id: string
  readonly description: string
  readonly subject: string
  readonly resource: string
  readonly context: string
  readonly actions: readonly string[]
  readonly condition: ConditionNode | null
  readonly challenges: readonly ChallengeDraft[]
}

/** The whole authoring session: the declarations, and the policy written against them. */
export interface Draft {
  readonly schema: SchemaDraft
  readonly policy: PolicyDraft
}

// ---------------------------------------------------------------------------
// constructors
//
// Every new node arrives through one of these, so a node with no shape — an
// empty row waiting for free text — never exists.
// ---------------------------------------------------------------------------

export function emptySchema(): SchemaDraft {
  return { entities: [], actions: [], sources: [] }
}

export function emptyPolicy(): PolicyDraft {
  return {
    id: '',
    description: '',
    subject: '',
    resource: '',
    context: '',
    actions: [],
    condition: null,
    challenges: [],
  }
}

export function emptyDraft(): Draft {
  return { schema: emptySchema(), policy: emptyPolicy() }
}

export function literal(type: PolicyType = 'string', values: readonly string[] = ['']): LiteralOperand {
  return { kind: 'literal', type, values }
}

export function fieldRef(role: Role = 'subject', attribute = ''): FieldOperand {
  return { kind: 'field', role, attribute }
}

export function sourceRef(name = '', args: readonly Operand[] = []): SourceOperand {
  return { kind: 'source', name, args }
}

export function newOperand(kind: OperandKind): Operand {
  switch (kind) {
    case 'field':
      return fieldRef()
    case 'source':
      return sourceRef()
    case 'literal':
      return literal()
  }
}

export function newNode(kind: NodeKind): ConditionNode {
  switch (kind) {
    case 'logic':
      return { kind: 'logic', op: 'all', operands: [] }
    case 'compare':
      return { kind: 'compare', left: fieldRef(), op: 'eq', right: literal() }
    case 'member':
      return { kind: 'member', left: fieldRef(), collection: literal('list<string>', ['']), negate: false }
  }
}

export function emptyApproverSet(): ApproverSetDraft {
  return { mode: 'members', members: [''], claim: '', source: sourceRef() }
}

export function newChallenge(type: ChallengeType): ChallengeDraft {
  switch (type) {
    case 'quorum':
      return { type: 'quorum', threshold: 2, approvers: emptyApproverSet() }
    case 'mfa':
      return { type: 'mfa', mode: 'delegated', acrValues: [] }
    case 'delay':
      return { type: 'delay', duration: '1h', cancellable: false, cancellableBy: emptyApproverSet() }
    case 'external':
      return { type: 'external', target: '' }
  }
}

// ---------------------------------------------------------------------------
// derived reads
// ---------------------------------------------------------------------------

/** The list type whose elements have the given scalar type. */
export function listOf(elem: ScalarType): PolicyType {
  return `list<${elem}>`
}

export function isListType(t: PolicyType): boolean {
  return t.startsWith('list<')
}

export function elemType(t: PolicyType): ScalarType | null {
  if (!isListType(t)) return null
  const inner = t.slice('list<'.length, -1)
  return (SCALAR_TYPES as readonly string[]).includes(inner) ? (inner as ScalarType) : null
}

/** Every declared type an author may choose, scalars first. */
export function allTypes(): readonly PolicyType[] {
  return [...SCALAR_TYPES, ...SCALAR_TYPES.map((t) => listOf(t))]
}

/** The entity type a policy binds to a role, or '' when it binds none. */
export function boundEntity(policy: PolicyDraft, role: Role): string {
  switch (role) {
    case 'subject':
      return policy.subject
    case 'resource':
      return policy.resource
    case 'context':
      return policy.context
  }
}

/** The attributes readable through a role, given what the policy binds. */
export function attributesFor(draft: Draft, role: Role): readonly AttributeDraft[] {
  const name = boundEntity(draft.policy, role)
  if (name === '') return []
  return draft.schema.entities.find((e) => e.name === name)?.attributes ?? []
}

/** The declared type of a field reference, when both the binding and the attribute exist. */
export function fieldType(draft: Draft, ref: FieldOperand): PolicyType | null {
  return attributesFor(draft, ref.role).find((a) => a.name === ref.attribute)?.type ?? null
}

export function sourceDecl(draft: Draft, name: string): SourceDraft | null {
  return draft.schema.sources.find((s) => s.name === name) ?? null
}

/** True when the draft has no declaration at all — R19's empty state. */
export function hasNoDeclarations(schema: SchemaDraft): boolean {
  return schema.entities.length === 0 && schema.actions.length === 0 && schema.sources.length === 0
}
