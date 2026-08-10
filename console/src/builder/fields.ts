/**
 * Which pointers the form actually renders a control for.
 *
 * A diagnostic names a pointer into the document; a form can only put a message
 * where it has a control. Those two sets are close but not equal — the
 * validator reports `/policies/0/condition/all/1/right` at an input the form
 * has, and `/policies/0/condition/all/1` at a row that has no input of its own —
 * so a diagnostic is placed at the nearest ancestor the form does render, and
 * only a pointer with no rendered ancestor at all is shown unattached.
 *
 * This enumeration walks the same draft the serializer walks, in the same
 * order. It is not a registry the components populate at render time: a
 * registry can disagree with what was rendered, and the disagreement would show
 * up as an error that silently lands nowhere.
 */
import {
  type ApproverSetDraft,
  type ChallengeDraft,
  type ConditionNode,
  type Draft,
  type Operand,
  type SchemaDraft,
} from './model'
import { ancestors, jptr, policyPointer } from './pointer'

function operandPointers(operand: Operand, pointer: string, out: string[]): void {
  out.push(pointer)
  if (operand.kind === 'source') {
    operand.args.forEach((arg, i) => operandPointers(arg, jptr(pointer, 'args', i), out))
  }
}

function conditionPointers(node: ConditionNode, pointer: string, out: string[]): void {
  out.push(pointer)
  switch (node.kind) {
    case 'logic':
      if (node.op === 'not') {
        const inner = node.operands[0]
        if (inner) conditionPointers(inner, jptr(pointer, 'not'), out)
        return
      }
      node.operands.forEach((child, i) =>
        conditionPointers(child, jptr(pointer, node.op, i), out),
      )
      return
    case 'compare':
      operandPointers(node.left, jptr(pointer, 'left'), out)
      out.push(jptr(pointer, 'op'))
      operandPointers(node.right, jptr(pointer, 'right'), out)
      return
    case 'member':
      operandPointers(node.left, jptr(pointer, 'left'), out)
      operandPointers(node.collection, jptr(pointer, node.negate ? 'not_in' : 'in'), out)
  }
}

function approverPointers(set: ApproverSetDraft, pointer: string, out: string[]): void {
  out.push(pointer)
  switch (set.mode) {
    case 'members':
      set.members.forEach((_, i) => out.push(jptr(pointer, 'members', i)))
      return
    case 'claim':
      out.push(jptr(pointer, 'claim'))
      return
    case 'source':
      out.push(jptr(pointer, 'source'))
      set.source.args.forEach((arg, i) => operandPointers(arg, jptr(pointer, 'args', i), out))
  }
}

function challengePointers(challenge: ChallengeDraft, pointer: string, out: string[]): void {
  out.push(pointer)
  switch (challenge.type) {
    case 'quorum':
      out.push(jptr(pointer, 'threshold'))
      approverPointers(challenge.approvers, jptr(pointer, 'approvers'), out)
      return
    case 'mfa':
      out.push(jptr(pointer, 'mode'))
      challenge.acrValues.forEach((_, i) => out.push(jptr(pointer, 'acr_values', i)))
      return
    case 'delay':
      out.push(jptr(pointer, 'duration'))
      if (challenge.cancellable) {
        approverPointers(challenge.cancellableBy, jptr(pointer, 'cancellable_by'), out)
      }
      return
    case 'external':
      out.push(jptr(pointer, 'target'))
  }
}

function schemaPointers(schema: SchemaDraft, out: string[]): void {
  schema.entities.forEach((entity, i) => {
    const pointer = jptr('schema', 'entities', i)
    out.push(pointer, jptr(pointer, 'name'))
    entity.attributes.forEach((attribute) =>
      out.push(jptr(pointer, 'attributes', attribute.name)),
    )
  })
  schema.actions.forEach((_, i) => {
    const pointer = jptr('schema', 'actions', i)
    out.push(pointer, jptr(pointer, 'name'))
  })
  schema.sources.forEach((source, i) => {
    const pointer = jptr('schema', 'sources', i)
    out.push(
      pointer,
      jptr(pointer, 'name'),
      jptr(pointer, 'kind'),
      jptr(pointer, 'returns'),
      jptr(pointer, 'on_error'),
    )
    source.params.forEach((_, j) => out.push(jptr(pointer, 'params', j)))
  })
}

/** Every pointer the form renders a control for, in document order. */
export function renderedPointers(draft: Draft): readonly string[] {
  const out: string[] = []
  schemaPointers(draft.schema, out)
  const policy = policyPointer()
  out.push(
    jptr(policy, 'id'),
    jptr(policy, 'description'),
    jptr(policy, 'subject'),
    jptr(policy, 'resource'),
    jptr(policy, 'context'),
    jptr(policy, 'actions'),
  )
  if (draft.policy.condition !== null) {
    conditionPointers(draft.policy.condition, jptr(policy, 'condition'), out)
  }
  draft.policy.challenges.forEach((challenge, i) =>
    challengePointers(challenge, jptr(policy, 'challenges', i), out),
  )
  return out
}

/**
 * The pointer a message about `pointer` should be shown at: the pointer itself
 * when the form renders it, otherwise its nearest rendered ancestor.
 */
export function placementFor(pointer: string, rendered: ReadonlySet<string>): string | null {
  if (rendered.has(pointer)) return pointer
  for (const ancestor of ancestors(pointer)) {
    if (rendered.has(ancestor)) return ancestor
  }
  return null
}
