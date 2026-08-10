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

An unknown role name fails startup rather than quietly running a subset — a typo in a deployment manifest should not silently disable the decide subsystem.

```sh
make build          # build ./stamp
make land           # every gate a PR must pass
make hooks          # run those gates from a pre-push hook
make help           # list targets
```

## Development

```sh
make test           # go test -race ./...
make lint           # golangci-lint
make vulncheck      # govulncheck
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
