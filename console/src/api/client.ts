/**
 * The console's one network seam.
 *
 * Every request the console makes goes through here. That is not a style
 * preference: D19's promise is that the console consumes the public API and has
 * no private surface of its own, and a promise like that survives exactly as
 * long as there is one place to look. scripts/check-contract.mjs enforces it —
 * `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource` and `sendBeacon` are
 * refused anywhere in src/ except this file.
 *
 * Calls name a contract endpoint rather than a path. The path template comes
 * from the generated contract, so an endpoint that is not in the public
 * contract is not addressable, and adding one means adding it to the Go
 * declaration first.
 */
import type { ConsoleRuntimeConfig } from '../config/runtime-config'
import { endpoint, fillPath } from './contract'

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body?: unknown,
    /**
     * The `Retry-After` the response carried, in seconds, when it carried one
     * this client could read.
     *
     * Undefined is not "retry now": it means the header was absent, unparseable,
     * or withheld by the browser. A cross-origin API response only exposes
     * `Retry-After` to script when the server lists it in
     * `Access-Control-Expose-Headers`, which the split topology's proxy may not
     * do — so a screen that words a wait must word one that works without a
     * number as well as one that has it.
     */
    readonly retryAfterSeconds?: number,
  ) {
    super(message)
    this.name = 'ApiError'
  }

  /**
   * The request was refused by a budget rather than by a rule (R43).
   *
   * It is a wait and not an escalation: whatever was refused can be sent again
   * shortly, and copy that sends the reader to an operator is worse than no copy
   * at all — the operator has nothing to do, and the reader stops trying the one
   * thing that works.
   */
  get isRateLimited(): boolean {
    return this.status === 429
  }

  /** The session is gone or was never good enough. */
  get isUnauthenticated(): boolean {
    return this.status === 401
  }

  get isForbidden(): boolean {
    return this.status === 403
  }

  /**
   * The server has nothing to give under this identifier.
   *
   * On the surfaces that act on one named decision — the approval submission and
   * its review, the delegated cancellation, the audit detail — this is also the
   * answer to "you may not have it". The server collapsed the two deliberately
   * (#38): telling them apart would make the status code an oracle for whether
   * an identifier names anything, which is what R40 exists to prevent. So a
   * screen that reads this cannot tell which one happened, and must not write
   * copy that claims to know.
   */
  get isNotFound(): boolean {
    return this.status === 404
  }
}

export class NetworkError extends Error {
  constructor(cause: unknown) {
    super(`요청이 네트워크 단계에서 실패했습니다: ${String(cause)}`)
    this.name = 'NetworkError'
  }
}

export interface ApiRequestOptions {
  /** Values for the endpoint template's {param} segments. */
  readonly params?: Readonly<Record<string, string>>
  /** Query parameters, encoded by URLSearchParams. */
  readonly query?: Readonly<Record<string, string | undefined>>
  /** JSON request body. */
  readonly body?: unknown
  readonly signal?: AbortSignal
}

export interface ApiClient {
  request<T>(name: string, options?: ApiRequestOptions): Promise<T>
  /** The absolute origin requests go to, for the "where am I pointed" display. */
  readonly baseUrl: string
}

export interface ApiClientDeps {
  readonly config: ConsoleRuntimeConfig
  /** Returns the current access token, or null when there is no session. */
  readonly getAccessToken: () => string | null
  /** Called once per 401, so the shell can offer a re-login. */
  readonly onUnauthenticated?: () => void
  readonly fetchImpl?: typeof fetch
}

export function createApiClient(deps: ApiClientDeps): ApiClient {
  const { config, getAccessToken, onUnauthenticated } = deps
  const doFetch = deps.fetchImpl ?? fetch
  // Empty base means same-origin, which is the single-container install. The
  // value is the server's; see config/runtime-config.ts for why it can only be
  // the server's.
  const base = config.apiBaseUrl.replace(/\/+$/, '')

  async function request<T>(name: string, options: ApiRequestOptions = {}): Promise<T> {
    const target = endpoint(name)
    const path = fillPath(target.path, options.params)
    const query = buildQuery(options.query)
    const url = `${base}${path}${query}`

    const headers: Record<string, string> = { Accept: 'application/json' }
    const token = getAccessToken()
    if (token) headers.Authorization = `Bearer ${token}`
    let payload: string | undefined
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json'
      payload = JSON.stringify(options.body)
    }

    let response: Response
    try {
      response = await doFetch(url, {
        method: target.method,
        headers,
        // The console authenticates with a bearer token in memory. Sending
        // ambient credentials would give the API a second, weaker way in.
        credentials: 'omit',
        mode: 'cors',
        cache: 'no-store',
        redirect: 'error',
        ...(payload === undefined ? {} : { body: payload }),
        ...(options.signal ? { signal: options.signal } : {}),
      })
    } catch (cause) {
      throw new NetworkError(cause)
    }

    if (response.status === 401) {
      onUnauthenticated?.()
    }
    if (!response.ok) {
      throw new ApiError(
        response.status,
        await describeFailure(response),
        await safeBody(response),
        retryAfterOf(response),
      )
    }
    if (response.status === 204) return undefined as T
    return (await response.json()) as T
  }

  return { request, baseUrl: base || window.location.origin }
}

function buildQuery(query: ApiRequestOptions['query']): string {
  if (!query) return ''
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined) params.set(key, value)
  }
  const rendered = params.toString()
  return rendered === '' ? '' : `?${rendered}`
}

async function describeFailure(response: Response): Promise<string> {
  switch (response.status) {
    case 401:
      return '로그인이 만료되었습니다. 다시 로그인하십시오.'
    case 403:
      return '이 작업을 수행할 권한이 없습니다.'
    case 404:
      return '대상을 찾을 수 없습니다.'
    case 409:
      return '대상의 상태가 바뀌어 요청을 적용할 수 없습니다.'
    default:
      return `요청이 ${response.status}로 실패했습니다.`
  }
}

/**
 * The response's `Retry-After` as a number of seconds, when it has one.
 *
 * Only the delta-seconds form is read. RFC 9110 also allows an HTTP-date, and
 * this API never sends one — the value is a refill interval computed from the
 * budget, which is a duration and not an instant — so parsing a date here would
 * be code for a case that cannot arrive, resolved against a client clock that
 * may be wrong. Anything else, including an absent or non-numeric header, is
 * undefined: the caller words the wait without a number rather than inventing
 * one.
 */
function retryAfterOf(response: Response): number | undefined {
  const raw = response.headers.get('Retry-After')
  if (raw === null) return undefined
  const seconds = Number(raw.trim())
  if (!Number.isFinite(seconds) || seconds < 0) return undefined
  return Math.ceil(seconds)
}

async function safeBody(response: Response): Promise<unknown> {
  try {
    return await response.clone().json()
  } catch {
    return undefined
  }
}
