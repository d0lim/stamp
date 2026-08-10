/**
 * Collapse as visual compression, not as suppression.
 *
 * R55 is explicit about this and it is the reason this primitive is in the
 * shell: a collapsed item stays in the DOM so a screen reader and the browser's
 * own find-in-page still reach it. `hidden`, `display:none` and unmounting all
 * fail that. What this does instead is clip the region visually while leaving
 * it in the accessibility tree, and expose `aria-expanded` on a real button.
 *
 * The second half of R55 — the approval button that stays disabled until every
 * item has been expanded once — is U16's, and `onFirstExpand` is the hook it
 * needs. Keeping the "has been seen" signal here is what makes that rule
 * enforceable without every screen reimplementing the disclosure.
 */
import { useId, useRef, useState, type ReactNode } from 'react'

export interface DisclosureProps {
  readonly summary: ReactNode
  readonly children: ReactNode
  readonly defaultExpanded?: boolean
  /** Fired the first time this disclosure is expanded, ever. */
  readonly onFirstExpand?: () => void
  /**
   * Drives the open state from outside. Passing it makes this a controlled
   * disclosure and `onToggle` becomes the only way it changes.
   *
   * U16 needs it for "expand everything", which R55 accepts as satisfying the
   * approve gate in one action. The alternative — remounting every disclosure
   * with a new default — would reset `aria-expanded` by destroying the element
   * that carried it, which is a worse answer to an accessibility requirement
   * than a controlled prop.
   */
  readonly expanded?: boolean
  readonly onToggle?: (next: boolean) => void
}

export function Disclosure({
  summary,
  children,
  defaultExpanded = false,
  onFirstExpand,
  expanded: controlled,
  onToggle,
}: DisclosureProps) {
  const id = useId()
  const [uncontrolled, setUncontrolled] = useState(defaultExpanded)
  const everExpanded = useRef(defaultExpanded)
  const expanded = controlled ?? uncontrolled

  function toggle() {
    const next = !expanded
    if (controlled === undefined) setUncontrolled(next)
    onToggle?.(next)
    if (next && !everExpanded.current) {
      everExpanded.current = true
      onFirstExpand?.()
    }
  }

  return (
    <div className="disclosure">
      <button
        type="button"
        className="disclosure__trigger"
        aria-expanded={expanded}
        aria-controls={`${id}-region`}
        id={`${id}-trigger`}
        onClick={toggle}
      >
        {/* The state is carried by text as well as by the marker, because a
            triangle alone is a colour-and-shape-only signal. */}
        <span aria-hidden="true" className="disclosure__marker">
          {expanded ? '▾' : '▸'}
        </span>
        {summary}
      </button>
      <div
        id={`${id}-region`}
        role="region"
        aria-labelledby={`${id}-trigger`}
        className={expanded ? 'disclosure__region' : 'disclosure__region disclosure__region--collapsed'}
        data-expanded={expanded}
      >
        {children}
      </div>
    </div>
  )
}
