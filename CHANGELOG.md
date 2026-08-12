# Changelog

The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [semantic versioning](https://semver.org/spec/v2.0.0.html).

The release workflow reads this file: a tag whose version has no section here
does not release. The three public contracts carry their own versions, stated in
`docs/contracts/`, and they move independently of the product version —
`scripts/check-contract-versions.sh` is the gate that keeps each document in
step with the code it describes.

## [Unreleased]

STAMP is pre-v1 and has never been tagged. This section is the running record of
what a first release would contain.

### Added

- `check()` — a stateless AuthZEN Access Evaluation surface over the same policy
  model the decide path uses.
- `decide()` — decisions as lifecycle objects, with four challenge kinds behind
  one contract: quorum, delegated MFA, delay and external.
- The Fact Plane — static, HTTP, event and IdP group sources behind a TTL cache
  and an operator egress allowlist.
- Velocity aggregation over a broker-neutral ingestion port, with Kafka and HTTP
  ingest adapters.
- Self-referential governance: a policy change is itself a decision, with a
  weakening classifier, revision deltas and a bootstrap-then-lock path.
- Two authoring paths of equal standing — a schema-rendered form builder in the
  console, and declarative `apply`/`export` over files — sharing one revision
  pipeline, with an operator authoring mode that can close either one.
- The console: React and TypeScript, embedded in the binary, consuming the
  public API with no backend of its own.
- Postgres persistence with a hash-chained audit log and per-role database
  privileges.
- Signed audit checkpoints: the chain's heads published outside the database
  that stores them, under a rotatable Ed25519 key, verified offline by
  `stamp audit verify`.
- One image, five roles: `check`, `decide`, `consumer`, `api`, `console`,
  selected with `--roles`.
- Packaging: a Helm chart with two topologies, a release workflow that publishes
  the image and the chart with an SBOM and signatures, and specification
  documents for the three public contracts.

### Upgrade notes

- **A serving pod must not run ahead of the schema, and now it will not.** Only
  the tier holding the `api` role migrates, while `helm upgrade` rolls every
  Deployment at once. Every listener therefore answers `GET /readyz`, and the
  chart's readinessProbe asks it instead of `/healthz`: a pod whose binary needs
  a schema the database has not reached stays out of its Service until the
  migration lands, rather than joining it and answering `42703 column ... does
  not exist`. `/healthz` is unchanged and remains the liveness signal. Two
  consequences for an operator: an upgrade can now pause with pods Running and
  not Ready — that is the migration not having landed, and `kubectl describe`
  prints the version being waited for — and a chart upgraded ahead of the image
  will stall, because an older image has no `/readyz` to answer. Upgrade the
  chart and the image together.

- **An `Idempotency-Key` now names one request, and a PEP that reused keys across
  different requests will start seeing `409 idempotency_key_reused`.** The
  decision API is at 1.7.0 and states the rule. What it replaces is worse than a
  breaking change: reusing a key for a different subject, resource or action
  returned the *first* decision — `201`, `state: allowed` — for an authorization
  this engine had never evaluated, and the response body carries no subject,
  resource or action, so a PEP had no field in which to notice. A client that
  mints a key per attempt sees nothing change. A client that derives keys from an
  order or job number should check that two different requests can never share
  one; where they can, that was already a substitution waiting to happen.

- **Challenge issue budgets split in two, and one existing variable changed
  meaning.** `STAMP_CHALLENGE_ISSUE_RATE_*` is now charged per (caller, subject)
  rather than per subject, and the new
  `STAMP_CHALLENGE_ISSUE_SUBJECT_CEILING_*` bounds the total one person can be
  prompted for across every caller (default 20 an hour, bursting to 10). A
  deployment that set neither gets both defaults and needs no action. A
  deployment that lowered the existing pair should read it as a per-caller number
  now, and set the ceiling if the old value was chosen as a per-person bound. The
  process refuses to start if the ceiling's burst is not larger than the
  per-caller burst — a ceiling one caller can empty in an instant is the shared
  bucket the split exists to remove. The webhook dispatch budget is unchanged and
  still per subject; what a refusal there protects is somebody else's system,
  whose defence is that the total is bounded rather than each caller's share.

- **A shed challenge issuance no longer creates a decision.** On the decide path
  it is now `200` with no `id`, `reason: challenge_rate_limited` and
  `Retry-After`, where it used to be `201` with a decision that immediately
  resolved to denied. That decision was a terminal deny written onto the record
  of a person nobody had asked anything — and because the old budget was keyed on
  the subject alone, anyone who could name a person could keep it there. Clients
  that already follow the documented rule (read `state` and `id`, never infer
  `id` from the status code) see no difference. Alerting that counted denied
  decision rows to find shed traffic should count `decision.refused` audit
  entries instead.

- **Rolling migrations 000009 and 000008 back discards the in-flight idempotency
  keys, and a PEP mid-retry pays for it.** 000009 drops the unique index and
  000008 drops `decisions.idempotency_key` and `decisions.idempotency_fingerprint`
  with it; the decision rows survive, but
  the names their callers gave them do not. A PEP that retries a `POST /decisions`
  across that rollback is a caller whose key now matches nothing, so it gets a
  *second* decision: a second slot against the subject's outstanding cap, a
  second set of challenges, and a second push at whichever person was already
  asked to authorise the first one. Rolling forward again does not reunite them —
  the first decision keeps running under a name nobody holds. Treat the rollback
  as an operation with a human cost and drain the decide path first if the
  deployment can.

- 000009 builds its index with `CREATE INDEX CONCURRENTLY`, which is not atomic.
  An interrupted build leaves an INVALID index behind and marks the schema dirty,
  which the readiness gate above reports as unready on every tier. Recovery is to
  roll 000009 back — its down is a single `DROP INDEX CONCURRENTLY IF EXISTS`,
  which clears the corpse — and migrate up again.

[Unreleased]: https://github.com/d0lim/stamp/compare/main...HEAD
