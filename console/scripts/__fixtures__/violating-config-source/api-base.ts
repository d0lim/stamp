// R50's exact failure: the API base address taken from somewhere the person
// holding the link controls.
export function apiBase(): string {
  const override = window.localStorage.getItem('stamp.apiBaseUrl')
  if (override) return override
  const params = new URLSearchParams(window.location.search)
  return params.get('apiBaseUrl') ?? ''
}
