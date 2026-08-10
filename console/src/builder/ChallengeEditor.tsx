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

const CHALLENGE_LABELS: Readonly<Record<ChallengeType, string>> = {
  quorum: '정족수 승인 (quorum)',
  mfa: '재인증 (mfa)',
  delay: '대기 (delay)',
  external: '외부 승인 (external)',
}

const APPROVER_LABELS: Readonly<Record<ApproverMode, string>> = {
  members: '명시적 목록',
  claim: '토큰 claim',
  source: 'IdP 그룹 source',
}

const MFA_LABELS: Readonly<Record<MFAMode, string>> = {
  delegated: '위임 (delegated) — IdP가 step-up을 수행',
  direct: '직접 (direct) — v1 미구현',
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
          해석 방식
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
              label={`승인자 ${index + 1}`}
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
          승인자 추가
        </button>
      ) : null}

      {set.mode === 'claim' ? (
        <Field pointer={jptr(pointer, 'claim')} label="claim 이름" placed={placed}>
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
            label="IdP 그룹 source"
            hint="list<string>을 반환하는 idp_group source만 승인자 집합으로 해석됩니다."
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
                <option value="">선택하십시오</option>
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
                label={`인자 ${param.name} (${param.type})`}
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
            label="정족수"
            hint="이 정책이 걸린 결정을 통과시키는 데 필요한 서로 다른 승인 수입니다."
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
            legend="승인자 집합"
            set={challenge.approvers}
            onChange={(approvers) => onChange({ ...challenge, approvers })}
          />
        </>
      )
    case 'mfa':
      return (
        <>
          <Field pointer={jptr(pointer, 'mode')} label="방식" placed={placed}>
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
              label={`허용 acr ${index + 1}`}
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
            acr 값 추가
          </button>
        </>
      )
    case 'delay':
      return (
        <>
          <Field
            pointer={jptr(pointer, 'duration')}
            label="대기 시간"
            hint="1h30m 처럼 씁니다."
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
              대기 중 취소를 허용한다
            </label>
          </div>
          {challenge.cancellable ? (
            <ApproverSetEditor
              draft={draft}
              placed={placed}
              pointer={jptr(pointer, 'cancellable_by')}
              legend="취소 권한"
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
          label="외부 대상"
          hint="운영자 egress 허용목록에 있는 대상만 고를 수 있습니다. 자유 입력이 아닙니다."
          placed={placed}
        >
          {(props) =>
            egressTargets.length === 0 ? (
              <>
                <select {...props} className="control" value="" disabled>
                  <option value="">선택할 수 있는 대상이 없습니다</option>
                </select>
                <p className="field__hint" data-testid="egress-empty">
                  이 배포에는 콘솔이 읽을 수 있는 egress 허용목록이 없습니다. 필요한 대상을 운영자에게
                  요청해 허용목록에 등록한 뒤 다시 선택하십시오.
                </p>
              </>
            ) : (
              <select
                {...props}
                className="control"
                value={challenge.target}
                onChange={(event) => onChange({ ...challenge, target: event.target.value })}
              >
                <option value="">선택하십시오</option>
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
          challenge가 없는 정책은 check 경로에서 즉시 판정됩니다. 사람의 승인이나 대기가 필요하면
          아래에서 추가하십시오.
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
            {CHALLENGE_LABELS[challenge.type]} 삭제
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
            {CHALLENGE_LABELS[type]} 추가
          </button>
        ))}
      </div>
    </div>
  )
}
