// A call target computed at runtime is a call target no static check can read.
import type { ApiClient } from '../../../src/api/client'

export async function call(api: ApiClient, name: string) {
  return api.request<unknown>(name)
}
