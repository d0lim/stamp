/**
 * The console's operator configuration, and the one rule that governs it.
 *
 * R50: the API base address comes from the server that served the bundle, and
 * from nowhere else. Not the query string, not the fragment, not localStorage,
 * not sessionStorage, not a `window.__CONFIG__` an injected script could set
 * first. Every one of those is writable by whoever can hand an approver a link,
 * and the console holds that approver's access token — a console that took its
 * base address from a link would post the token wherever the link said.
 *
 * The one URL this module hardcodes is the configuration document itself, and
 * it is same-origin with the bundle by construction: `import.meta.env.BASE_URL`
 * is a build-time constant that matches the subtree the Go server mounts the
 * bundle on. That is not a browser-supplied value.
 *
 * scripts/check-contract.mjs enforces the ban statically, so this comment is
 * not the only thing keeping it true.
 */

export interface ConsoleOIDCConfig {
  readonly issuer: string
  readonly authorizationEndpoint: string
  readonly tokenEndpoint: string
  readonly endSessionEndpoint?: string
  readonly clientId: string
  readonly scopes: readonly string[]
  readonly roleClaim: string
}

export interface ConsoleRuntimeConfig {
  readonly version: number
  /** Empty means same-origin with the bundle, which is the single-container install. */
  readonly apiBaseUrl: string
  readonly basePath: string
  readonly oidc: ConsoleOIDCConfig
}

/** The document shape this build understands. */
export const SUPPORTED_CONFIG_VERSION = 1

/** Same-origin by construction: a build-time constant, not a runtime input. */
export const CONFIG_URL = `${import.meta.env.BASE_URL}config.json`

export class ConfigError extends Error {
  constructor(
    message: string,
    readonly detail?: string,
  ) {
    super(message)
    this.name = 'ConfigError'
  }
}

/**
 * Fetches and validates the operator configuration.
 *
 * `credentials: 'omit'` is deliberate: the document is public and carrying a
 * cookie to it would be the beginning of a session the console does not have.
 */
export async function loadRuntimeConfig(
  fetchImpl: typeof fetch = fetch,
): Promise<ConsoleRuntimeConfig> {
  let response: Response
  try {
    response = await fetchImpl(CONFIG_URL, { credentials: 'omit', cache: 'no-store' })
  } catch (cause) {
    throw new ConfigError(
      'Could not load the console configuration.',
      `The request for ${CONFIG_URL} failed: ${String(cause)}`,
    )
  }
  if (!response.ok) {
    throw new ConfigError(
      'Could not load the console configuration.',
      `${CONFIG_URL} returned ${response.status}.`,
    )
  }
  let raw: unknown
  try {
    raw = await response.json()
  } catch (cause) {
    throw new ConfigError('Could not parse the console configuration.', String(cause))
  }
  return parseRuntimeConfig(raw)
}

export function parseRuntimeConfig(raw: unknown): ConsoleRuntimeConfig {
  if (typeof raw !== 'object' || raw === null) {
    throw new ConfigError('The console configuration document is not an object.')
  }
  const doc = raw as Record<string, unknown>
  const version = doc.version
  if (version !== SUPPORTED_CONFIG_VERSION) {
    throw new ConfigError(
      'This build does not understand the version of the console configuration document.',
      `Document version ${String(version)}; this build knows version ${SUPPORTED_CONFIG_VERSION}.`,
    )
  }

  const apiBaseUrl = requireString(doc, 'apiBaseUrl')
  assertSafeApiBase(apiBaseUrl)

  const basePath = requireString(doc, 'basePath') || import.meta.env.BASE_URL
  const oidcRaw = doc.oidc
  if (typeof oidcRaw !== 'object' || oidcRaw === null) {
    throw new ConfigError('The console configuration document has no oidc entry.')
  }
  const oidc = oidcRaw as Record<string, unknown>

  const config: ConsoleRuntimeConfig = {
    version,
    apiBaseUrl,
    basePath,
    oidc: {
      issuer: requireString(oidc, 'issuer'),
      authorizationEndpoint: requireString(oidc, 'authorizationEndpoint'),
      tokenEndpoint: requireString(oidc, 'tokenEndpoint'),
      endSessionEndpoint: requireString(oidc, 'endSessionEndpoint'),
      clientId: requireString(oidc, 'clientId'),
      scopes: Array.isArray(oidc.scopes) ? oidc.scopes.map(String) : [],
      roleClaim: requireString(oidc, 'roleClaim') || 'roles',
    },
  }
  return deepFreeze(config)
}

/**
 * A second line of defence on the value the server sent.
 *
 * The server validates this too. Checking again here costs nothing and closes
 * the case where a console bundle is served by something other than the Go
 * server — which is precisely the separation D19 is keeping open.
 */
function assertSafeApiBase(value: string): void {
  if (value === '') return
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new ConfigError(
      'The API base address is not an absolute address.',
      `Configured value: ${value}. Leave it empty to use the same origin.`,
    )
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new ConfigError('The API base address scheme is neither http nor https.', value)
  }
  if (parsed.search !== '' || parsed.hash !== '') {
    throw new ConfigError('The API base address carries a query string or a fragment.', value)
  }
}

function requireString(source: Record<string, unknown>, key: string): string {
  const value = source[key]
  if (value === undefined || value === null) return ''
  if (typeof value !== 'string') {
    throw new ConfigError(`The ${key} entry in the console configuration document is not a string.`)
  }
  return value
}

function deepFreeze<T>(value: T): T {
  Object.freeze(value)
  for (const key of Object.getOwnPropertyNames(value)) {
    const child = (value as Record<string, unknown>)[key]
    if (child !== null && typeof child === 'object' && !Object.isFrozen(child)) {
      deepFreeze(child)
    }
  }
  return value
}

/** True when the deployment has configured a relying party at all. */
export function isLoginConfigured(config: ConsoleRuntimeConfig): boolean {
  return (
    config.oidc.clientId !== '' &&
    config.oidc.authorizationEndpoint !== '' &&
    config.oidc.tokenEndpoint !== ''
  )
}
