/**
 * The error summary R19 asks for, and the `aria-describedby` wiring that goes
 * with it.
 *
 * It lives in the shell rather than in the form builder because U15 and U16
 * both need it and because "the errors are listed at the top and each one
 * focuses its field" is a property of the console, not of one screen. The
 * summary takes focus when it appears: an error that is announced but leaves
 * focus at the bottom of a long form is an error a keyboard user has to hunt
 * for.
 */
import { useEffect, useRef } from 'react'

export interface FieldError {
  /** The id of the field this error belongs to. */
  readonly fieldId: string
  readonly message: string
}

/** The id an input should name in aria-describedby. */
export function fieldErrorId(fieldId: string): string {
  return `${fieldId}-error`
}

export interface ErrorSummaryProps {
  readonly errors: readonly FieldError[]
  readonly title?: string
}

export function ErrorSummary({ errors, title = '입력을 확인해 주십시오' }: ErrorSummaryProps) {
  const ref = useRef<HTMLDivElement>(null)
  const count = errors.length

  useEffect(() => {
    if (count > 0) ref.current?.focus()
  }, [count])

  if (count === 0) return null

  return (
    <div
      ref={ref}
      className="error-summary"
      role="alert"
      tabIndex={-1}
      aria-labelledby="error-summary-title"
      data-testid="error-summary"
    >
      <h2 id="error-summary-title" className="error-summary__title">
        {title}
      </h2>
      <ul className="error-summary__list">
        {errors.map((error) => (
          <li key={`${error.fieldId}:${error.message}`}>
            <a href={`#${error.fieldId}`}>{error.message}</a>
          </li>
        ))}
      </ul>
    </div>
  )
}
