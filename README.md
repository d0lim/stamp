# STAMP

**ST**ateful **A**uthorization for **M**ulti-**P**arty approvals — a self-hosted policy engine for decisions that need more than allow/deny.

> Status: pre-v1, under active construction. The engine core is being built unit by unit; see the plan linked below.

## What it is

Existing policy engines (OPA, Cedar, Cerbos) productize stateless judgment. For high-risk authorization — a transfer above a threshold, a destructive admin action — the parts that actually cost you are gathering the facts the decision needs and coordinating the approvals it requires. Those land outside the engine, so every team ends up building an orchestrator on top of one.

STAMP makes a decision an object with a lifecycle instead of a boolean, and pulls quorum, MFA, time delay, and external challenges inside the engine.

Two evaluation paths share one policy model:

- **`check()`** — stateless, high-QPS, immediate. AuthZEN-compatible.
- **`decide()`** — creates a decision that stays `pending` while challenges are collected, then resolves to allow, deny, or expired.

## Running it

One image serves every topology. `--roles` is the only difference between an all-in-one install and a scaled-out one.

```sh
# everything in one process (the default)
stamp --roles=all

# scaled out: many stateless check replicas, one decide, split API and console
stamp --roles=check
stamp --roles=decide
stamp --roles=api
stamp --roles=console
```

An unknown role name fails startup rather than quietly running a subset — a typo in a deployment manifest should not silently disable the decide subsystem. A role that is not active has no routes at all: its endpoints answer 404 on this process rather than refusing.

The three surfaces are three listeners, not three path prefixes on one. A route mounted on the PEP listener is not reachable through the console listener, because the other listener's router has never heard of it.

| Surface | Default address | Callers |
|---|---|---|
| PEP | `:8080` | workloads holding client credentials |
| console | `:8081` | operators and approvers holding end-user tokens |
| callback | unbound | external systems completing a challenge |

Everything else comes from the environment, and nothing that would be a credential or a trust decision has a default — a missing DSN, issuer or audience fails startup with a message naming the variable.

```sh
STAMP_DSN='postgres://stamp:stamp@localhost:5432/stamp?sslmode=disable' \
STAMP_OIDC_ISSUER='https://idp.example' \
STAMP_OIDC_JWKS_URL='https://idp.example/.well-known/jwks.json' \
STAMP_OIDC_AUDIENCE='stamp' \
STAMP_OIDC_WORKLOAD_CLIENTS='pep-1' \
stamp --roles=all
```

| Variable | Meaning |
|---|---|
| `STAMP_DSN` | PostgreSQL connection string. Required. |
| `STAMP_OIDC_ISSUER`, `STAMP_OIDC_JWKS_URL`, `STAMP_OIDC_AUDIENCE` | The token verification trust boundary. Required. |
| `STAMP_OIDC_WORKLOAD_CLIENTS` | Client identifiers whose tokens are workload credentials rather than end-user ones. |
| `STAMP_PEP_ADDR`, `STAMP_CONSOLE_ADDR`, `STAMP_CALLBACK_ADDR` | Listen addresses. Set one to the empty string to leave that surface unbound. |
| `STAMP_AUDIT_WRITER_ID` | The audit chain segment this process owns. Exactly one live process may hold it; a collision fails the boot. Defaults to the hostname. |
| `STAMP_FACT_SOURCES` | Fact source transports, as a JSON document or a path to one. |
| `STAMP_EGRESS_ALLOW` | Origins a fact call may reach, comma-separated. Nothing else is dialled. |
| `STAMP_FACT_ALLOW_FAIL_OPEN` | Permit source declarations that fail open. Off by default. |
| `STAMP_AUDIT_FAIL_CLOSED` | Deny while the check-path audit buffer is saturated. On by default. |
| `STAMP_GOVERNANCE_MIN_APPROVERS` | The operator floor under any revision quorum. |
| `STAMP_EXTERNAL_TARGETS` | Webhook destinations an `external` challenge may reach, as a JSON document or a path to one: `name`, `url`, `secret`, and optionally `timeout` and `respond_within`. A policy names an entry; it cannot name a URL. |
| `STAMP_CALLBACK_BASE_URL` | This deployment's externally reachable callback base. Told to an external target and used to build the step-up redirect a completion returns to. |
| `STAMP_MFA_ACR_VALUES` | The operator allowlist of authentication context classes. Required to run delegated MFA at all: an IdP downgrades an `acr` request it cannot satisfy without saying so, so an unchecked response is an unchecked authentication. |
| `STAMP_MFA_AUTHORIZATION_ENDPOINT`, `STAMP_MFA_CLIENT_ID`, `STAMP_MFA_REDIRECT_URI` | The step-up redirect flow, which is the default delegation path (D26). |
| `STAMP_MFA_CIBA_*` | The optional CIBA backchannel client, tried ahead of the step-up and falling back to it when the IdP has no decoupled authentication server behind its CIBA grant. |

Configure no `STAMP_MFA_*` and the `mfa` challenge kind simply has no handler: a
policy declaring one cannot issue a decision, which is the fail-closed reading of
"this deployment has no step-up". If `STAMP_OIDC_ACR_VALUES` is set at all it
bounds *every* end-user token, so it has to be a superset of
`STAMP_MFA_ACR_VALUES` and of whatever class console login returns — otherwise a
completed step-up is rejected as a bad credential before the challenge sees it.
Startup checks the first half of that and says so.

A policy's `mfa` challenge is completed by the decision's subject, matched on the
token's `sub`. A decide request that puts anything else in `subject.id` — an
account number, a resource key — produces a challenge no person can complete.

On its first start with the `api` role the process installs the reserved governance policy and prints a one-time bootstrap token. It is shown once and stored only as a digest; lock governance with it as soon as the approver set is known.

### The console

The console is a React + TypeScript bundle built by Vite and embedded in the binary with `go:embed`. It consumes the engine's public API and has no backend of its own — no BFF — and it is served by the `console` role alone, which is separate from `api` so that a deployment can run one without the other.

Embedding is not a bet against ever separating them. The bundle's API base address is operator configuration served at `/console/config.json`, so the same bundle runs against another origin; and the console's calls are checked in CI against the public contract exported from `internal/api/contract.go`, so a private console endpoint cannot appear quietly. The base address comes from that document and nothing else — not a query string, not a fragment, not `localStorage` — because all three are writable by whoever can send an approver a link, and the console holds that approver's token. Every console response carries a CSP whose `connect-src` names only the configured API origin and the IdP.

| Variable | Meaning |
|---|---|
| `STAMP_CONSOLE_API_BASE_URL` | Where the console sends its API calls. Empty means the same origin the bundle came from, which is the single-container install. |
| `STAMP_CONSOLE_OIDC_CLIENT_ID`, `STAMP_CONSOLE_OIDC_AUTHORIZATION_ENDPOINT`, `STAMP_CONSOLE_OIDC_TOKEN_ENDPOINT` | The console's relying party: an authorization code flow with PKCE, public client, tokens held in memory only. Without them the console starts and says it cannot log anyone in. |
| `STAMP_CONSOLE_OIDC_ISSUER` | The issuer the console logs in through. Defaults to `STAMP_OIDC_ISSUER`. |
| `STAMP_CONSOLE_ROLE_CLAIM` | The token claim navigation and default landing are derived from. Defaults to `roles`. |

`go build` does not need Node: `console/dist` is tracked through a placeholder, and a binary built without running the console build starts, mounts the console role, and answers with the command that is missing. `make build-all` produces the shipped artifact, and the Docker build does it in its own stage.

```sh
make build          # build ./stamp (no Node required)
make console        # build the console bundle into console/dist
make build-all      # both, in order
make land           # every gate a PR must pass
make hooks          # run those gates from a pre-push hook
make help           # list targets
```

## Development

```sh
make test              # go test -race ./...
make lint              # golangci-lint
make vulncheck         # govulncheck
make console-test      # typecheck, contract boundary check, vitest
make console-contract  # the exported contract, and the console's calls against it
```

Dependencies for the whole engine-core milestone are declared once in `internal/deps` behind the `m1deps` build tag, so sibling branches in the landing stack don't each edit `go.sum`.

Contributions follow the landing strategy in the plan: one implementation unit per pull request, stacked on the unit it depends on, with the PR body carrying background, approach, rationale, and where review attention is best spent.

## Design documents

| Document | What it holds |
|---|---|
| [`STRATEGY.md`](STRATEGY.md) | Target problem, approach, who it's for, what we're not building |
| [`docs/plans/2026-08-07-001-feat-stamp-feature-map-plan.md`](docs/plans/2026-08-07-001-feat-stamp-feature-map-plan.md) | What v1 is and how it gets built — requirements, units, verification, landing strategy |
| [`docs/decisions/stamp-decision-log.md`](docs/decisions/stamp-decision-log.md) | Why it has this shape, and which alternatives were rejected |

## License

MIT — see [`LICENSE`](LICENSE).
