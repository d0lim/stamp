/**
 * The first focusable element on the page, and the only one that is invisible
 * until it has focus.
 *
 * Without it, reaching the content of a screen with the keyboard means tabbing
 * through the whole navigation on every route change.
 */
export function SkipLink() {
  return (
    <a className="skip-link" href="#main">
      Skip to main content
    </a>
  )
}
