# Violating fixtures

Nothing here is compiled and nothing here is run. These files are input, and
their only job is to confirm that `scripts/check-contract.mjs` **still fails**.

A check that has only ever passed is a check with no evidence it is alive. Each
directory reproduces one way D19's promise breaks, and `check-contract.test.mjs`
feeds that directory to the checker and watches for the rule that is supposed to
catch it.

`tsconfig.json`'s `include` holds `src` alone, so none of these files reaches the
type check.
