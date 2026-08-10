// The shape a real screen has: a call named by a contract endpoint, made
// through the client the shell provides.
import type { ApiClient } from '../../../src/api/client'

export async function listPolicies(api: ApiClient) {
  return api.request<unknown[]>('policy-list')
}

export async function readRevision(api: ApiClient, id: string) {
  return api.request<unknown>('revision-read', { params: { id } })
}
