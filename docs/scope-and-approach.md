# Scope and approach

What STAMP is trying to do, how the work is divided, and — the part most worth
reading before you open a pull request — what it deliberately will not become.

## Target problem

Fintech teams that want to treat high-risk authorization — transaction approvals, admin actions — as policy pay most of their cost not in judgment logic, but in gathering the facts a judgment needs (PIP) and coordinating the approval process (an orchestrator). Existing policy engines (OPA, Cedar, Cerbos) productize stateless judgment alone and leave this part to the team, so teams end up building another engine on top of the engine.

## Our approach

Make a decision an object with a lifecycle, not a boolean — bring challenge collection like quorum, MFA, and time delay inside the engine, eliminating the pattern where every team builds another orchestrator on top of the policy engine. The engine takes responsibility for fact procurement (PIP) through declarative source bindings, and scales high-QPS lookups by splitting them into the stateless check() path.

## Who it is for

**Primary:** Fintech platform engineers — payment, transfer, and asset service teams hire STAMP as shared infrastructure to stop each hardcoding their own approval and authorization logic.


## Tracks

### Decision Kernel

The decision state machine — decision-object lifecycle (pending → allow/deny/expired), pluggable challenge types (quorum / mfa / delay / external), re-evaluation rules on policy change, obligation execution.

_Why it serves the approach:_ It is the approach itself — the core of bringing the approval process inside the engine.

### Fact Plane (PIP)

Declarative source bindings — synchronous (API/gRPC) and asynchronous (event stream) source definitions, TTL/batching/partial-failure semantics, fail-closed defaults.

_Why it serves the approach:_ Building a decision object requires fact procurement to be the engine's responsibility.

### Policy Language & Builder

A typed policy representation and entity/action schema, plus a UI policy builder rendered from that schema (including source-binding UX).

_Why it serves the approach:_ It's the direct answer to the "fixed kernel + JSON interpreter" trap, and the shared foundation for static validation and the UI builder.

### Scale & Self-hosted Ops

Splitting the check()/decide() paths, horizontal scaling, install packaging (container/Helm), audit-log export. Postgres (with SQL/PGQ under experimentation) is this track's storage-layer choice.

_Why it serves the approach:_ The track that carries the high-QPS requirement and the self-hosting entry conditions of a regulated industry.

## Not working on

- SaaS hosting — self-hosted first; reconsider a control-plane SaaS form later
- A general-purpose workflow engine — only as much state as authorization needs; not expanding into Temporal's territory
- Implementing authentication (authn) itself — WebAuthn/TOTP get verification integration only; STAMP does not become an IdP

