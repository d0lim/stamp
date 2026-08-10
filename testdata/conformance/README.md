# AuthZEN interop conformance

This directory holds everything the AuthZEN Access Evaluation conformance gate
needs: the upstream fixtures, the interop scenario ported to STAMP's own schema
and policy format, and the PDP the official harness talks to.

## Provenance

`decisions-authorization-api-1_0-01.json` is vendored verbatim from
[`openid/authzen`](https://github.com/openid/authzen) at commit
`6fb7fa85c86acda14710f9f0f161da9aaa801a45`, path
`interop/authzen-todo-backend/test/decisions-authorization-api-1_0-01.json`.

The commit is pinned in `.github/workflows/conformance.yml` as well, and both
must move together. Upstream edits its fixtures on `main`, so an unpinned
harness would make our gate fail for reasons that have nothing to do with a
change of ours.

The conformance target is the **Access Evaluation profile only** — 40 cases.
The `-02` spec variant adds three batch-evaluation cases against
`/access/v1/evaluations`, which is deferred, so targeting it would fix this gate
at permanently red.

## What is ported, and where it lives

| Upstream concept | Here |
|---|---|
| todo application's entity and action model | `policies/schema.yaml` |
| todo application's authorization rules | `policies/todo.yaml` |
| the reference PDP's loaded user directory | `directory.json`, served behind the declared fact sources |

The directory is deployment data rather than policy data. The schema declares
`role_members(role)` and `user_email(user_id)`; the PDP serves both from
`directory.json` over loopback HTTP, through the fact plane's own egress gate,
timeout and TTL cache. That is what a real deployment fronting this application
would do, and it keeps the identity-to-role join out of the policy documents.

Two mappings are deployment configuration rather than derivable:

- The harness sends the property `ownerID`; a STAMP attribute name becomes a CEL
  identifier and is `owner_id`. The check surface's `PropertyAliases` table maps
  the two.
- The AuthZEN envelope's `id` is bound to the declared `id` attribute so a
  condition can read it.

## Running it

The 40 cases also run offline as an ordinary Go test — see
`internal/api/conformance_test.go`, which replays the same vendored fixtures
against the same handler. The workflow additionally runs the **official** Node
harness against a real listener:

```sh
go build -o conformance-pdp ./testdata/conformance/pdp
./conformance-pdp -addr 127.0.0.1:9090 -dir testdata/conformance -token-file pdp-token.txt &

cd /path/to/authzen/interop/authzen-todo-backend
yarn install --frozen-lockfile && yarn build
AUTHZEN_PDP_API_KEY="Bearer $(cat /path/to/pdp-token.txt)" \
  node build/test/runner.js http://127.0.0.1:9090 authorization-api-1_0-01 console \
  | tee results.txt

bash testdata/conformance/assert-results.sh results.txt 40
```

`assert-results.sh` is not optional decoration. The harness's runner exits 0
regardless of what it found — a run in which all 40 cases ERROR because the PDP
was unreachable exits 0 as well — so the wrapper parses the output and fails
unless it sees exactly the expected number of cases and every one of them
passed.
