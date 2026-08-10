/**
 * The environment variables the console's own configuration comes from, named
 * so an operator reading a refusal screen knows what to set.
 *
 * They are stated here rather than sent in the configuration document because a
 * document that could not be generated cannot carry the names of the variables
 * that would have let it be generated.
 */
export const EnvConsoleVariables = [
  'STAMP_CONSOLE_OIDC_CLIENT_ID',
  'STAMP_CONSOLE_OIDC_AUTHORIZATION_ENDPOINT',
  'STAMP_CONSOLE_OIDC_TOKEN_ENDPOINT',
  'STAMP_CONSOLE_OIDC_ISSUER',
] as const
