/**
 * The single-policy field diff, and the one renderer that draws it.
 *
 * There is exactly one of these on purpose. The approval screen shows an
 * approver what a revision would change and binds their approval to a hash over
 * that material; the builder shows an author the same change before they spend
 * a quorum's attention on it. If those were two components, the sentence "the
 * hash covers what you were shown" would quietly mean two different things.
 *
 * R55 rules the presentation. The change kind is carried by a text label as
 * well as by a mark and a colour, because "green means added" is a rule a
 * colour-blind approver cannot read and a screen reader never hears. The mark
 * is `aria-hidden`; the label is not.
 */
import { diffDocuments, countChanged, type ChangeKind, type FieldChange } from './document'

/** The three words the console uses for a change, everywhere. */
export const CHANGE_LABELS: Readonly<Record<ChangeKind, string>> = {
  added: '추가',
  removed: '삭제',
  changed: '수정',
  unchanged: '동일',
}

/** A shape as well as a colour, so the distinction survives greyscale. */
const CHANGE_MARKS: Readonly<Record<ChangeKind, string>> = {
  added: '+',
  removed: '−',
  changed: '~',
  unchanged: '=',
}

export interface FieldDiffProps {
  readonly changes: readonly FieldChange[]
  /** Shows fields that did not change. Off by default: a diff is the changes. */
  readonly showUnchanged?: boolean
  /** Distinguishes this list's element ids from another on the same screen. */
  readonly idPrefix: string
}

export function FieldDiff({ changes, showUnchanged = false, idPrefix }: FieldDiffProps) {
  const rows = showUnchanged ? changes : changes.filter((change) => change.kind !== 'unchanged')
  if (rows.length === 0) {
    return (
      <p className="field__hint" data-testid={`${idPrefix}-empty`}>
        이 정책의 필드 중 달라진 것이 없습니다.
      </p>
    )
  }
  return (
    <ul className="fielddiff" data-testid={`${idPrefix}-fields`}>
      {rows.map((change) => (
        <li key={change.pointer} className={`fielddiff__row fielddiff__row--${change.kind}`}>
          <p className="fielddiff__head">
            <span aria-hidden="true" className="fielddiff__mark">
              {CHANGE_MARKS[change.kind]}
            </span>
            {/* The label is the accessible carrier of the change kind. It is
                text, not a colour and not a shape. */}
            <span className="fielddiff__kind">{CHANGE_LABELS[change.kind]}</span>
            <code className="fielddiff__label">{change.label}</code>
          </p>
          {change.before === undefined ? null : (
            <p className="fielddiff__value">
              <span className="fielddiff__side">이전</span>
              {/* Rendered as text. A policy document is authored content and
                  there is no HTML interpretation path on this screen (R22). */}
              <code>{change.before}</code>
            </p>
          )}
          {change.after === undefined ? null : (
            <p className="fielddiff__value">
              <span className="fielddiff__side">이후</span>
              <code>{change.after}</code>
            </p>
          )}
        </li>
      ))}
    </ul>
  )
}

/**
 * A whole document pair, diffed and rendered.
 *
 * This is the entry point both screens use, so that "compute the diff" and
 * "draw the diff" cannot drift apart between them.
 */
export function DocumentDiff({
  before,
  after,
  idPrefix,
  showUnchanged,
}: {
  readonly before?: string
  readonly after?: string
  readonly idPrefix: string
  readonly showUnchanged?: boolean
}) {
  const changes = diffDocuments(before, after)
  return <FieldDiff changes={changes} idPrefix={idPrefix} {...(showUnchanged === undefined ? {} : { showUnchanged })} />
}

/** How many fields a document pair changes, for a collapsed summary. */
export function changedFieldCount(before: string | undefined, after: string | undefined): number {
  return countChanged(diffDocuments(before, after))
}
