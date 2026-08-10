/**
 * What the console shows when it could not load its own configuration.
 *
 * It renders the whole document rather than a banner inside the shell, because
 * the shell needs the configuration it did not get. There is no retry that
 * would help without an operator changing something, so the screen names the
 * document that failed instead of spinning.
 */
export interface ConfigErrorScreenProps {
  readonly message: string
  readonly detail?: string
}

export function ConfigErrorScreen({ message, detail }: ConfigErrorScreenProps) {
  return (
    <main id="main" className="shell__main" tabIndex={-1}>
      <div className="panel panel--refusal" role="alert">
        <h1>콘솔을 시작하지 못했습니다</h1>
        <p>{message}</p>
        {detail ? <p className="panel__meta">{detail}</p> : null}
        <p>
          콘솔 설정 문서는 콘솔을 서빙하는 프로세스가 내려줍니다. <code>--roles</code>에{' '}
          <code>console</code>이 포함되어 있는지 확인하십시오.
        </p>
      </div>
    </main>
  )
}
