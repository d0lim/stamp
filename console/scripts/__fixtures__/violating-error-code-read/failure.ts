// A screen that reads the refusal code for itself.
//
// This is how the vocabulary escapes the one module that declares it: the
// branch below is invisible to the set comparison, so a code the server stopped
// emitting would go on being branched on here and nothing would say so. It is
// the #51 incident with a fresh coat of paint.
import type { ApiError } from '../../../src/api/client'
import type { ErrorResponse } from '../../../src/builder/api-types'

export function wordIt(cause: ApiError): string {
  const body = cause.body as { error?: string; message?: string } | undefined
  if (body?.error === 'not_an_approver') return '당신은 승인자가 아닙니다.'
  return body?.message ?? cause.message
}

export function wordItAgain(cause: ApiError): string {
  const declared = cause.body as ErrorResponse
  return declared.error
}

export function wordItLoosely(cause: ApiError): string {
  return String((cause.body as any).error)
}
