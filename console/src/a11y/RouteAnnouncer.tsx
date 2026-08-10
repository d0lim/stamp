/**
 * What happens to focus and to a screen reader when a client-side route
 * changes.
 *
 * A server-rendered navigation resets focus to the document and the assistive
 * technology reads the new title. A client-side route change does neither by
 * default: focus stays on the link that was activated, which is now gone, and
 * nothing is announced. The result is a console that is usable with a mouse and
 * silently broken with a screen reader.
 *
 * So the shell does both explicitly, once, here — R55's parity requirement is
 * only reachable if the screens U15 and U16 build inherit this rather than each
 * remembering it.
 */
import { useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'

export interface RouteAnnouncerProps {
  /** The page title, announced and set as document.title. */
  readonly title: string
  /** Where focus goes. Defaults to the main landmark. */
  readonly focusTargetId?: string
}

export function RouteAnnouncer({ title, focusTargetId = 'main' }: RouteAnnouncerProps) {
  const location = useLocation()
  const liveRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    document.title = `${title} · STAMP 콘솔`
    // A page load is already announced by the browser, and moving focus on one
    // would fight the fragment a deep link may carry. React Router gives the
    // location a fresh key on every navigation and the literal key "default"
    // on the entry location — which is exactly the distinction needed, and is
    // why this is not tracked per component: each screen mounts its own
    // announcer, so a per-instance "first render" flag would be true on every
    // navigation and this would never fire.
    if (location.key === 'default') return

    document.getElementById(focusTargetId)?.focus()
    // The live region is written after focus moves, so the announcement is not
    // interrupted by the focus change.
    if (liveRef.current) liveRef.current.textContent = `${title} 화면으로 이동했습니다.`
  }, [location.key, title, focusTargetId])

  return (
    <div
      ref={liveRef}
      className="visually-hidden"
      role="status"
      aria-live="polite"
      aria-atomic="true"
      data-testid="route-announcer"
    />
  )
}
