/**
 * Which console a person sees, derived from a token claim.
 *
 * The claim that carries this is operator configuration (`roleClaim`), because
 * the plan leaves the source open — an IdP group claim in some deployments, a
 * governance-derived set in others. What is *not* open is the failure
 * direction: a token with no recognisable role gets no navigation and lands on
 * a screen that says so, rather than getting everything. The engine authorises
 * every call independently, so this is about what is offered, never about what
 * is permitted.
 */

export const CONSOLE_ROLES = ['author', 'approver', 'auditor'] as const
export type ConsoleRole = (typeof CONSOLE_ROLES)[number]

/**
 * Accepted spellings. A deployment's IdP is unlikely to emit exactly our three
 * words, and the alternative to a small alias table is asking every operator to
 * rename their groups.
 */
const ALIASES: Readonly<Record<string, ConsoleRole>> = {
  author: 'author',
  'policy-author': 'author',
  'policy_author': 'author',
  approver: 'approver',
  reviewer: 'approver',
  auditor: 'auditor',
  audit: 'auditor',
  viewer: 'auditor',
}

export function rolesFromClaims(
  claims: Readonly<Record<string, unknown>> | null,
  roleClaim: string,
): ReadonlySet<ConsoleRole> {
  const roles = new Set<ConsoleRole>()
  if (!claims) return roles
  for (const raw of collectValues(claims[roleClaim])) {
    // `stamp:approver` and `approver` are the same role. The prefix is how a
    // shared IdP keeps our groups apart from someone else's.
    const normalized = raw.trim().toLowerCase().replace(/^stamp[:/]/, '')
    const role = ALIASES[normalized]
    if (role) roles.add(role)
  }
  return roles
}

function collectValues(value: unknown): string[] {
  if (typeof value === 'string') {
    // Both a space separated scope-like string and a single value.
    return value.split(/[\s,]+/).filter(Boolean)
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => collectValues(item))
  }
  return []
}

/**
 * R-landing: policies when the person can author, the inbox when they can
 * approve, audit otherwise. Someone with no role at all is sent to the screen
 * that explains the gap rather than bounced between guards.
 */
export function defaultLanding(roles: ReadonlySet<ConsoleRole>): string {
  if (roles.has('author')) return '/policies'
  if (roles.has('approver')) return '/inbox'
  if (roles.has('auditor')) return '/audit'
  return '/no-access'
}

export const ROLE_LABELS: Readonly<Record<ConsoleRole, string>> = {
  // Person nouns, not activities. The strip these render in reads "No roles"
  // when empty, so the filled state has to name roles too — and the navigation
  // already has an item labelled "Audit" for the screen, so the role wants a
  // word that cannot be mistaken for it.
  author: 'Policy author',
  approver: 'Approver',
  auditor: 'Auditor',
}
