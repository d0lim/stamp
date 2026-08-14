/**
 * The challenge declarations.
 *
 * A challenge is what turns a policy from something the stateless check path can
 * answer into something that needs a decision, so this step is where an author
 * decides whether a rule is a gate or a wait. The four kinds are closed for v1
 * (policy.ChallengeTypes) and each one's parameters are the fields of its Go
 * struct — threshold and approvers, mode and acr_values, duration and who may
 * cancel, target.
 *
 * The external target is a select over the operator's egress allowlist and never
 * a text box. R20 is explicit that a call target is chosen from the allowlist
 * and that a target not on it is not offered; policy.External says the same
 * thing from the other side — Target names an allowlist entry rather than a URL.
 * A free-text box here would let an author name a destination the operator never
 * permitted and find out at runtime.
 *
 * The console has no way to *read* that allowlist yet: no endpoint in the public
 * contract exposes it. So the select renders empty with the operator-request
 * path spelled out, which is what R20 asks for when a target is not on the list —
 * and the moment the endpoint exists the options appear with no other change.
 */
import {
  APPROVER_MODES,
  CHALLENGE_TYPES,
  MFA_MODES,
  newChallenge,
  newOperand,
  sourceDecl,
  type ApproverMode,
  type ApproverSetDraft,
  type ChallengeDraft,
  type ChallengeType,
  type Draft,
  type MFAMode,
} from './model'
import { Field, FieldGroup } from './Field'
import type { PlacedDiagnostics } from './diagnostics'
import { fieldId, jptr } from './pointer'

// Each label names the challenge and then, in parentheses, the `type` value the
// document will carry — so an author reading the form and an approver reading
// the diff are looking at the same four things under the same four names.
const CHALLENGE_LABELS: Readonly<Record<ChallengeType, string>> = {
  quorum: 'quorum approval (quorum)',
  mfa: 're-authentication (mfa)',
  delay: 'wait (delay)',
  external: 'external approval (external)',
}

const APPROVER_LABELS: Readonly<Record<ApproverMode, string>> = {
  members: 'explicit list',
  claim: 'token claim',
  source: 'IdP group source',
}

const MFA_LABELS: Readonly<Record<MFAMode, string>> = {
  delegated: 'delegated — the IdP performs the step-up',
  direct: 'direct — not implemented in v1',
}

function ApproverSetEditor({
  draft,
  placed,
  pointer,
  legend,
  set,
  onChange,
}: {
  readonly draft: Draft
  readonly placed: PlacedDiagnostics
  readonly pointer: string
  readonly legend: string
  readonly set: ApproverSetDraft
  readonly onChange: (next: ApproverSetDraft) => void
}) {
  const declaration = sourceDecl(draft, set.source.name)
  return (
    <FieldGroup pointer={pointer} legend={legend} placed={placed} className="group group--nested">
      <div className="field">
        <label className="field__label" htmlFor={`${fieldId(pointer)}--mode`}>
          Resolution
        </label>
        <select
          id={`${fieldId(pointer)}--mode`}
          className="control"
          value={set.mode}
          onChange={(event) => onChange({ ...set, mode: event.target.value as ApproverMode })}
        >
          {APPROVER_MODES.map((mode) => (
            <option key={mode} value={mode}>
              {APPROVER_LABELS[mode]}
            </option>
          ))}
        </select>
      </div>

      {set.mode === 'members'
        ? set.members.map((member, index) => (
            <Field
              key={index}
              pointer={jptr(pointer, 'members', index)}
              label={`Approver ${index + 1}`}
              placed={placed}
            >
              {(props) => (
                <input
                  {...props}
                  className="control"
                  type="text"
                  value={member}
                  onChange={(event) =>
                    onChange({
                      ...set,
                      members: set.members.map((m, i) => (i === index ? event.target.value : m)),
                    })
                  }
                />
              )}
            </Field>
          ))
        : null}
      {set.mode === 'members' ? (
        <button
          type="button"
          className="button"
          onClick={() => onChange({ ...set, members: [...set.members, ''] })}
        >
          Add approver
        </button>
      ) : null}

      {set.mode === 'claim' ? (
        <Field pointer={jptr(pointer, 'claim')} label="claim name" placed={placed}>
          {(props) => (
            <input
              {...props}
              className="control"
              type="text"
              value={set.claim}
              onChange={(event) => onChange({ ...set, claim: event.target.value })}
            />
          )}
        </Field>
      ) : null}

      {set.mode === 'source' ? (
        <>
          <Field
            pointer={jptr(pointer, 'source')}
            label="IdP group source"
            hint="Only an idp_group source that returns list<string> is resolved as an approver set."
            placed={placed}
          >
            {(props) => (
              <select
                {...props}
                className="control"
                value={set.source.name}
                onChange={(event) => {
                  const next = sourceDecl(draft, event.target.value)
                  onChange({
                    ...set,
                    source: {
                      kind: 'source',
                      name: event.target.value,
                      args: (next?.params ?? []).map(() => newOperand('literal')),
                    },
                  })
                }}
              >
                <option value="">Select one</option>
                {draft.schema.sources.map((source) => (
                  <option key={source.name} value={source.name}>
                    {source.name} → {source.returns}
                  </option>
                ))}
              </select>
            )}
          </Field>
          {declaration?.params.map((param, index) => {
            const argument = set.source.args[index]
            const value = argument?.kind === 'literal' ? (argument.values[0] ?? '') : ''
            return (
              <Field
                key={param.name}
                pointer={jptr(pointer, 'args', index)}
                label={`Argument ${param.name} (${param.type})`}
                placed={placed}
              >
                {(props) => (
                  <input
                    {...props}
                    className="control"
                    type="text"
                    value={value}
                    onChange={(event) =>
                      onChange({
                        ...set,
                        source: {
                          ...set.source,
                          args: set.source.args.map((arg, i) =>
                            i === index
                              ? { kind: 'literal', type: param.type, values: [event.target.value] }
                              : arg,
                          ),
                        },
                      })
                    }
                  />
                )}
              </Field>
            )
          })}
        </>
      ) : null}
    </FieldGroup>
  )
}

function ChallengeFields({
  draft,
  placed,
  pointer,
  challenge,
  egressTargets,
  onChange,
}: {
  readonly draft: Draft
  readonly placed: PlacedDiagnostics
  readonly pointer: string
  readonly challenge: ChallengeDraft
  readonly egressTargets: readonly string[]
  readonly onChange: (next: ChallengeDraft) => void
}) {
  switch (challenge.type) {
    case 'quorum':
      return (
        <>
          <Field
            pointer={jptr(pointer, 'threshold')}
            label="Quorum"
            hint="The number of distinct approvals a decision this policy gates needs before it passes."
            placed={placed}
          >
            {(props) => (
              <input
                {...props}
                className="control"
                type="number"
                min={1}
                value={challenge.threshold}
                onChange={(event) =>
                  onChange({ ...challenge, threshold: Number(event.target.value) })
                }
              />
            )}
          </Field>
          <ApproverSetEditor
            draft={draft}
            placed={placed}
            pointer={jptr(pointer, 'approvers')}
            legend="Approver set"
            set={challenge.approvers}
            onChange={(approvers) => onChange({ ...challenge, approvers })}
          />
        </>
      )
    case 'mfa':
      return (
        <>
          <Field pointer={jptr(pointer, 'mode')} label="Mode" placed={placed}>
            {(props) => (
              <select
                {...props}
                className="control"
                value={challenge.mode}
                onChange={(event) =>
                  onChange({ ...challenge, mode: event.target.value as MFAMode })
                }
              >
                {MFA_MODES.map((mode) => (
                  <option key={mode} value={mode}>
                    {MFA_LABELS[mode]}
                  </option>
                ))}
              </select>
            )}
          </Field>
          {challenge.acrValues.map((value, index) => (
            <Field
              key={index}
              pointer={jptr(pointer, 'acr_values', index)}
              label={`Allowed acr ${index + 1}`}
              placed={placed}
            >
              {(props) => (
                <input
                  {...props}
                  className="control"
                  type="text"
                  value={value}
                  onChange={(event) =>
                    onChange({
                      ...challenge,
                      acrValues: challenge.acrValues.map((v, i) =>
                        i === index ? event.target.value : v,
                      ),
                    })
                  }
                />
              )}
            </Field>
          ))}
          <button
            type="button"
            className="button"
            onClick={() => onChange({ ...challenge, acrValues: [...challenge.acrValues, ''] })}
          >
            Add acr value
          </button>
        </>
      )
    case 'delay':
      return (
        <>
          <Field
            pointer={jptr(pointer, 'duration')}
            label="Wait duration"
            hint="Written like 1h30m."
            placed={placed}
          >
            {(props) => (
              <input
                {...props}
                className="control"
                type="text"
                value={challenge.duration}
                onChange={(event) => onChange({ ...challenge, duration: event.target.value })}
              />
            )}
          </Field>
          <div className="field field--inline">
            <input
              id={`${fieldId(pointer)}--cancellable`}
              className="control"
              type="checkbox"
              checked={challenge.cancellable}
              onChange={(event) => onChange({ ...challenge, cancellable: event.target.checked })}
            />
            <label className="field__label" htmlFor={`${fieldId(pointer)}--cancellable`}>
              Allow cancellation while waiting
            </label>
          </div>
          {challenge.cancellable ? (
            <ApproverSetEditor
              draft={draft}
              placed={placed}
              pointer={jptr(pointer, 'cancellable_by')}
              legend="Who may cancel"
              set={challenge.cancellableBy}
              onChange={(cancellableBy) => onChange({ ...challenge, cancellableBy })}
            />
          ) : null}
        </>
      )
    case 'external':
      return (
        <Field
          pointer={jptr(pointer, 'target')}
          label="External target"
          hint="Only a target on the operator's egress allowlist can be chosen. This is not a free-text field."
          placed={placed}
        >
          {(props) =>
            egressTargets.length === 0 ? (
              <>
                <select {...props} className="control" value="" disabled>
                  <option value="">No target is available</option>
                </select>
                <p className="field__hint" data-testid="egress-empty">
                  This deployment exposes no egress allowlist the console can read. Ask the operator
                  to add the target you need to the allowlist, then select it here.
                </p>
              </>
            ) : (
              <select
                {...props}
                className="control"
                value={challenge.target}
                onChange={(event) => onChange({ ...challenge, target: event.target.value })}
              >
                <option value="">Select one</option>
                {egressTargets.map((target) => (
                  <option key={target} value={target}>
                    {target}
                  </option>
                ))}
              </select>
            )
          }
        </Field>
      )
  }
}

export function ChallengeEditor({
  draft,
  placed,
  pointer,
  egressTargets = [],
  onChange,
}: {
  readonly draft: Draft
  readonly placed: PlacedDiagnostics
  readonly pointer: string
  readonly egressTargets?: readonly string[]
  readonly onChange: (next: readonly ChallengeDraft[]) => void
}) {
  const challenges = draft.policy.challenges
  return (
    <div className="challenges">
      {challenges.length === 0 ? (
        <p>
          A policy with no challenge is judged immediately on the check path. If it needs a human
          approval or a wait, add one below.
        </p>
      ) : null}
      {challenges.map((challenge, index) => (
        <FieldGroup
          key={index}
          pointer={jptr(pointer, index)}
          legend={CHALLENGE_LABELS[challenge.type]}
          placed={placed}
          className="node"
        >
          <ChallengeFields
            draft={draft}
            placed={placed}
            pointer={jptr(pointer, index)}
            challenge={challenge}
            egressTargets={egressTargets}
            onChange={(next) => onChange(challenges.map((c, i) => (i === index ? next : c)))}
          />
          <button
            type="button"
            className="button button--quiet"
            onClick={() => onChange(challenges.filter((_, i) => i !== index))}
          >
            Delete {CHALLENGE_LABELS[challenge.type]}
          </button>
        </FieldGroup>
      ))}
      <div className="palette" data-testid="challenge-palette">
        {CHALLENGE_TYPES.map((type) => (
          <button
            key={type}
            type="button"
            className="button"
            data-challenge-type={type}
            onClick={() => onChange([...challenges, newChallenge(type)])}
          >
            Add {CHALLENGE_LABELS[type]}
          </button>
        ))}
      </div>
    </div>
  )
}
