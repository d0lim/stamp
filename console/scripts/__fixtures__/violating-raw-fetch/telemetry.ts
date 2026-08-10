// The escape hatch around the client seam. Every static guarantee about call
// targets ends here.
export async function ping() {
  const response = await fetch('/console/internal/ping', { method: 'POST' })
  return response.ok
}
