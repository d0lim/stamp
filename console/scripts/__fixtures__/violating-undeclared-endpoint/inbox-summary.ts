// The BFF, arriving the way a BFF actually arrives: one endpoint that would be
// so much more convenient than composing the public ones.
import type { ApiClient } from '../../../src/api/client'

export async function inboxSummary(api: ApiClient) {
  return api.request<unknown>('console-inbox-summary')
}
