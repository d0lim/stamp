/**
 * One labelled control, with the server's diagnostics attached to it.
 *
 * R19 asks for two things that have to agree: a summary at the top of the form,
 * and each error connected to its field with `aria-describedby`. The shell owns
 * the summary (a11y/ErrorSummary.tsx) and this owns the other half. They agree
 * because both are keyed by the same thing — the pointer the diagnostic named —
 * so the link in the summary and the id of the input are the same string by
 * construction rather than by two components remembering the same convention.
 *
 * `aria-describedby` is set only when there is a message. Pointing it at an
 * element that does not exist is worse than not setting it: a screen reader
 * announces nothing and an audit reports a broken reference.
 */
import type { ReactNode } from 'react'
import { fieldErrorId } from '../a11y/ErrorSummary'
import { at, describe, type PlacedDiagnostics } from './diagnostics'
import { fieldId } from './pointer'

export interface FieldProps {
  /** The JSON Pointer this control occupies in the document. */
  readonly pointer: string
  readonly label: ReactNode
  readonly hint?: ReactNode
  readonly placed: PlacedDiagnostics
  /** Rendered with the id and the aria wiring this component computed. */
  readonly children: (props: ControlProps) => ReactNode
}

export interface ControlProps {
  readonly id: string
  readonly 'aria-describedby'?: string
  readonly 'aria-invalid'?: true
}

/** The aria wiring for a control at a pointer. */
export function controlProps(pointer: string, placed: PlacedDiagnostics): ControlProps {
  const id = fieldId(pointer)
  const messages = at(placed, pointer)
  if (messages.length === 0) return { id }
  return { id, 'aria-describedby': fieldErrorId(id), 'aria-invalid': true }
}

/** The messages for a pointer, rendered where `aria-describedby` points. */
export function FieldMessages({
  pointer,
  placed,
}: {
  readonly pointer: string
  readonly placed: PlacedDiagnostics
}) {
  const messages = at(placed, pointer)
  if (messages.length === 0) return null
  return (
    <p className="field__error" id={fieldErrorId(fieldId(pointer))}>
      {messages.map((message) => describe(message)).join(' · ')}
    </p>
  )
}

export function Field({ pointer, label, hint, placed, children }: FieldProps) {
  const props = controlProps(pointer, placed)
  return (
    <div className="field">
      <label className="field__label" htmlFor={props.id}>
        {label}
      </label>
      {hint ? <p className="field__hint">{hint}</p> : null}
      {children(props)}
      <FieldMessages pointer={pointer} placed={placed} />
    </div>
  )
}

/**
 * A group of controls that stands where a diagnostic might land.
 *
 * A compare row has an input for its left side, its operator and its right
 * side, but the validator also reports failures at the row itself — "a rule
 * needs either op and right, or in, or not_in". The row is therefore addressable
 * too: it carries the id and takes focus when the summary links to it.
 */
export function FieldGroup({
  pointer,
  legend,
  placed,
  children,
  className = 'group',
}: {
  readonly pointer: string
  readonly legend: ReactNode
  readonly placed: PlacedDiagnostics
  readonly children: ReactNode
  readonly className?: string
}) {
  return (
    <fieldset className={className} id={fieldId(pointer)} tabIndex={-1}>
      <legend className="group__legend">{legend}</legend>
      <FieldMessages pointer={pointer} placed={placed} />
      {children}
    </fieldset>
  )
}
