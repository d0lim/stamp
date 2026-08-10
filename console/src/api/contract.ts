/**
 * The public contract, as the console sees it.
 *
 * The JSON is generated from internal/api/contract.go and verified against the
 * routes the composition root actually mounts, so it is not a copy that can
 * drift — it is the same declaration, exported. The console addresses endpoints
 * by *name*, and the path template comes from here, which means the console
 * cannot express a call to something outside the contract even before
 * scripts/check-contract.mjs looks at it.
 */
import document from '../../contract/public-endpoints.json'

export interface ContractEndpoint {
  readonly name: string
  readonly method: string
  readonly path: string
  readonly auth: string
  readonly group: string
}

export const CONTRACT_VERSION: number = document.version
export const ENDPOINTS: readonly ContractEndpoint[] = Object.freeze(
  document.endpoints.map((e) => Object.freeze({ ...e })),
)

const BY_NAME = new Map(ENDPOINTS.map((e) => [e.name, e]))

export class UnknownEndpointError extends Error {
  constructor(name: string) {
    super(
      `"${name}"은(는) 공개 계약에 없는 엔드포인트입니다. ` +
        `internal/api/contract.go에 선언한 뒤 contract/public-endpoints.json을 다시 생성하십시오.`,
    )
    this.name = 'UnknownEndpointError'
  }
}

export function endpoint(name: string): ContractEndpoint {
  const found = BY_NAME.get(name)
  if (!found) throw new UnknownEndpointError(name)
  return found
}

/**
 * Fills a path template's {param} segments.
 *
 * Every value is percent-encoded. A decision identifier that arrived from an
 * API response is not a trusted path segment, and the endpoint's shape is fixed
 * by the template rather than by string concatenation at the call site — which
 * is what keeps the set of reachable paths equal to the set of declared ones.
 */
export function fillPath(template: string, params: Readonly<Record<string, string>> = {}): string {
  const missing: string[] = []
  const filled = template.replace(/\{([^}]+)\}/g, (_match, key: string) => {
    const value = params[key]
    if (value === undefined) {
      missing.push(key)
      return ''
    }
    return encodeURIComponent(value)
  })
  if (missing.length > 0) {
    throw new Error(`경로 ${template}에 필요한 인자가 없습니다: ${missing.join(', ')}`)
  }
  return filled
}
