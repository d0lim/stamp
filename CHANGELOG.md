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
- One image, five roles: `check`, `decide`, `consumer`, `api`, `console`,
  selected with `--roles`.
- Packaging: a Helm chart with two topologies, a release workflow that publishes
  the image and the chart with an SBOM and signatures, and specification
  documents for the three public contracts.

[Unreleased]: https://github.com/d0lim/stamp/compare/main...HEAD
