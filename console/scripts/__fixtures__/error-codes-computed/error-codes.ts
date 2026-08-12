// A declared vocabulary that cannot be read statically.
//
// The comparison needs the console's half enumerable without running anything.
// A list built at run time is a list the checker would have to guess at, and a
// checker that guesses is one that passes when it should not — so this shape is
// refused outright rather than approximated.
const BASE = ['expired', 'not_found']

export const CONSUMED_ERROR_CODES = BASE.concat(['material_changed']) as const
