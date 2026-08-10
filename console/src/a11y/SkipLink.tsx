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
      본문으로 건너뛰기
    </a>
  )
}
