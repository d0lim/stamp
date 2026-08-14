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
        <h1>The console did not start</h1>
        <p>{message}</p>
        {detail ? <p className="panel__meta">{detail}</p> : null}
        <p>
          The console configuration document is served by the process that serves the console.
          Check that <code>--roles</code> includes <code>console</code>.
        </p>
      </div>
    </main>
  )
}
