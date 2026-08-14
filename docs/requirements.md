# Requirements

The requirement canon for STAMP v1: what the system must do, stated once, so
that everything else can cite it instead of restating it.

Every requirement carries a stable identifier, `R1` through `R55`, and comments
throughout `internal/`, `cmd/` and `console/src` cite those identifiers to say
which requirement a piece of code exists to satisfy — "R43's enforcement point",
"R32 deliberately chose an async buffer". That is what makes this document
load-bearing rather than descriptive. Change what a requirement means here and
every comment citing it starts lying about the code beneath it.

So the numbering is fixed. Identifiers were assigned in the order the design
worked through them, not in the order the requirements group, which is why the
groups below run R1–R8 and then jump to R30. Those gaps are left alone. A
requirement that is ever withdrawn leaves its number behind rather than freeing
it for something else: a citation that silently starts pointing at a different
requirement is worse than one that points at nothing.

These state obligations, not progress. Nothing here is a claim that something is
built; the plan and the code say that.

---

## Decision kernel

- **R1.** `check()` provides stateless single request-response evaluation, and its request/response surface is compatible with the AuthZEN Access Evaluation single-request API. The verdict is returned as the AuthZEN canonical boolean, and STAMP-specific information rides only on namespaced keys in the response context (`stamp.reason`, `stamp.obligations`, `stamp.policy_version`) — a standard consumer that ignores the context must read the verdict identically.
- **R2.** `decide()` creates a decision object. The decision object exposes its state (pending / allow / deny / expired), the list of required challenges and their collection status, the expiry time, and the list of obligations.
- **R3.** Challenges are defined by a plugin contract. The contract covers quorum (m-of-n), mfa (delegated mode — delegate to an external IdP over RFC 9470 step-up and CIBA, then verify `acr` and `auth_time`, and check `amr` only when it is present / direct mode — WebAuthn with the decision context bound into it), delay (a waiting period, cancellable by a designated authority), and external (a webhook round trip to an external system). v1 implements quorum, mfa (delegated), delay and external; direct mode is defined as a contract only.
- **R4.** The decision lifecycle transitions from pending to allow / deny / expired, and includes an expiry timer and an approval collection API.
- **R5.** On a policy revision the author chooses between immediate re-evaluation and grandfathering, and the default is re-evaluation. Re-evaluation preserves those already-collected approvals that are valid against the new quorum set and collects only the shortfall. **Re-evaluation reuses the fact snapshot fixed at the moment the decision was created and does not query the sources again.** Only when the new policy newly references a source the snapshot does not have is that source queried and added to the snapshot, and in that case the approval binding hash differs, so every existing approval is invalidated and re-collected.
- **R6.** Policy creation, modification and deletion pass through STAMP's own `decide()` decision — the same door regardless of authoring path. The unit of revision is one policy or a set of policies, and a set revision is handled as a single decision so that partial approval cannot come about. A fresh install starts in solo administrator mode, and after an explicit lock action, policy revision requires a quorum.
- **R7.** Every decision fixes the policy version used in the evaluation, the fact snapshot, and the list of obligations returned, and records them in an append-only audit log.
- **R8.** The decision response returns a list of obligations. Enforcement is the calling service's responsibility, and v1 is responsible only as far as returning them.
- **R30.** A policy that has challenges can never be an allow on the check path — check returns a deny with reason `requires_decision`. This is an evaluator invariant, not a per-policy setting.
- **R31.** An approval is bound to a hash of the material the approver reviewed. The hash inputs are the decision context, the fact snapshot, the part of the challenge specification other than the quorum threshold (the target set, the challenge kind, the conditions), and the list of obligations. **The policy version identifier and the quorum number are excluded from the input** — so that a revision which only raises the threshold does not needlessly evaporate approvals already given. Re-evaluation preserves existing approvals only when this hash is identical, and invalidates and re-collects them when it differs.
- **R32.** The audit log must make tampering detectable. It provides a per-writer segment hash chain, periodic checkpoints binding together every writer's head hash as of each moment, and a verification procedure. Checkpoints are signed with an application-only key and published outside the database so they cannot be forged with database write access alone — **the default sink is an append-only local file, webhook dispatch is optionally supported, and the sink path and the signing key are exposed on the deployment configuration surface.** decide and governance audit records are written in the same transaction as the state transition. Audit loss on the check path is left in the chain as a loss-window marker (time range and count) so that verification reveals the gap, and the operator may choose a fail-closed mode that denies check when the buffer saturates.
- **R33.** Governance revisions classify their diff by whether it weakens. What counts as weakening is: reducing a quorum, widening the approver set, relaxing a source's on-error behaviour, removing a challenge, **deleting a policy**, and **narrowing a policy's trigger conditions**. Deleting a policy is the same as removing all of that policy's challenges, so it is always weakening; adding a policy is not weakening. A weakening revision must satisfy the requirements of whichever of the old and new policy is stricter, and may not violate the floors the operator configured (minimum number of approvers, proposer ≠ approver).
- **R34.** A revision that makes the approver set unsatisfiable is rejected. Governance actions before the lock require a bootstrap token printed once on first startup; the token is destroyed when the lock succeeds, and while it remains unused it periodically leaves a highest-severity audit warning. Recovery after the lock is provided only as an offline break-glass procedure that can be run only while the service listeners are not up, and it leaves a highest-severity audit event.
- **R53.** If no policy matches the request at all, the verdict is a deny with reason `no_matching_policy`. This is an evaluator invariant applying to both check and decide, and configuration cannot flip it. It fixes the failure direction to fail-closed for the states where the policy set is empty — right after a policy deletion, or right after a fresh install.

## Policy language and contracts

- **R9.** A policy is composed of a typed schema (entity, action and source declarations) and structured conditions (field, operator, value), and its expressiveness is bounded to what the form builder can render.
- **R10.** The exchange format for a policy is a file, and form authoring and file authoring must round-trip through the same format. The source of truth for storage is the engine, and the file is an exchange and authoring medium. **The format must be writable by a human directly and readable as a diff** — an AST serialization dump does not satisfy this requirement.
- **R11.** The three public contracts — the policy schema, the challenge interface, and the decision API — are versioned with semver from the first release, and each contract's specification document is kept in `docs/` with its version stated.
- **R12.** Policy load statically validates schema, types and source references, and a policy that fails is refused at load.
- **R44.** A dry run evaluates an unsaved policy against a sample input and returns whether it matches, the true/false result of each condition, and the challenges that would fire. It runs without saving and without revision approval. The sample input is taken through a form rendered from the entity and action declarations — it is not free-form JSON input.
- **R45.** The file authoring path is declarative. One directory is the desired state of a policy set, and apply turns that whole set into a single revision proposal. **The comparison against desired state is limited to policies whose authoring origin is file** — a form-origin policy does not become a deletion proposal by being absent from the directory. Only a policy that is file-origin and absent from the set is included as a deletion proposal. If even one policy fails static validation the whole proposal is rejected, and there is no partial application. Weakening classification is computed over the set, so if any one part weakens, the whole revision is treated as weakening. The apply payload has explicit bounds (document count, per-document byte size, condition AST node count and depth), and exceeding a bound is refused before parsing.
- **R46.** apply returns a revision proposal identifier by default and exits immediately. Given a wait option it blocks until resolution and reflects the outcome in its exit code — governance is asynchronous, so "applied" is not returned synchronously.
- **R47.** While an outstanding revision exists, a new revision proposal is rejected regardless of authoring path, and the rejection reports the in-flight proposal's identifier and its collection status — an approver always reviews exactly one diff against the currently effective state. The lock is released by four paths, and all four have to exist for each of the different deadlocks to come undone.
  - **Proposer withdrawal** — a proposer may withdraw their own outstanding proposal. It only reverts to the currently effective state, so it requires no quorum, and it leaves an audit event.
  - **Quorum withdrawal** — an approver set that meets the governance quorum may withdraw someone else's proposal. This closes the path of occupying governance with a proposal that could never be approved.
  - **Outstanding lifetime bound** — a revision proposal decision cannot outlive the operator-configured maximum outstanding lifetime (default 24 hours), and transitions to expired at that time.
  - **Same-origin supersession** — a new proposal from the same authoring origin supersedes the outstanding one. Already-collected approvals are invalidated, and the superseded proposal is recorded in the audit. A proposal from a different origin does not supersede and is rejected. This makes proposals converge rather than fail in the use where CI applies on every merge.

  All four paths are subject to rate limiting — it prevents holding the gate by re-occupying it immediately after a withdrawal, or by superseding repeatedly.
- **R48.** A path is provided for exporting the effective policy set in the file authoring format. It is the entry path for a deployment that started on the console and is switching to file authoring, and applying the exported result unchanged must be judged as no revision. Export can be called only by a principal holding policy authoring capability or audit capability, is subject to caller authentication, and leaves the caller identifier and the number of policies produced in the audit — because the output carries the approver identity list, the quorum thresholds and the internal call targets all at once, an unauthenticated read would be a reconnaissance path telling you which transactions can be split below which threshold to avoid approval.
- **R49.** The authoring mode is operator configuration — `both` (default), `file` (locks the console's policy authoring), `console` (locks file apply). `both` rests on R54's origin separation, so it means "the two paths each own their own policies" rather than "the two paths fight over the same policy", and the other two are stronger settings on top of that which close one window entirely. **In every mode the approval inbox, the audit views, the dry run and the lock action stay in the console** — if the lock screen went dark along with the authoring module, an operator who turned on `file` mode at install time would be trapped in solo administrator state.
- **R54.** Every policy is given an authoring origin (form or file) at creation, and that origin decides which path owns it. Moving origin is possible only through an explicit adoption declaration in a file document, and it is shown as an adoption item on the revision proposal — there is no implicit move. The console cannot edit a file-origin policy and can only view it, and an attempted edit tells the user which path owns it and what the adoption procedure is.

## Fact Plane

- **R13.** Two synchronous source kinds are provided (static list, HTTP call), and each declaration includes a TTL, a timeout, and an on-error behaviour (deny by default).
- **R14.** Source lookups on the check path are served from cache within the declared TTL, and the freshness limit of a verdict is what the source declaration states.
- **R15.** An asynchronous event source is provided. It subscribes to an event stream to maintain windowed aggregate state (for example, a 24-hour withdrawal total), and at evaluation time answers from a local state lookup. Ingestion sits behind a broker-neutral port, and v1 provides two adapters (Kafka, HTTP ingest) — with the ingest adapter present, this source works without a broker.
- **R16.** An IdP group lookup source is provided. It is usable both for resolving quorum targets and in ordinary conditions.
- **R35.** The call targets of remote sources are restricted to the egress allowlist in the operator's deployment configuration — policy content alone cannot name an arbitrary target. Link-local and private ranges blocked by default, redirects not followed, resolution pinned afterwards to prevent DNS rebinding, no ambient credentials.
- **R36.** allow on error (fail-open) is valid only where an explicit operator-level flag permits it. A TTL-expired entry is not served as a substitute response during an outage.
- **R37.** An asynchronous event source declares a freshness limit, and denies when ingestion lag exceeds it. Negative and deducting deltas are permitted only where the source has declared them.
- **R52.** The event ingestion port does not expose broker concepts — offsets, partitions and consumer groups stay inside the adapter, and the port defines only event receipt and the acknowledgement that processing is complete. On top of that, the following follow.
  - **Idempotency** — adapters guarantee at-least-once only, and deduplication is performed by the aggregator using the event identifier. Every event must carry a unique identifier assigned by the producer, and the port rejects an event that has none. The deduplication key is namespaced by caller identifier so that one caller cannot claim another caller's identifier. Deduplication state is retained for the maximum window declarable for that metric plus headroom, and a policy declaring a window beyond the retention period is refused at load.
  - **Lag reporting** — ingestion lag is defined as `current time − the producer timestamp of the most recently processed event`, and every event must carry a producer timestamp. If a producer clock runs ahead and the value comes out negative, it is clamped to 0. An adapter must report this value, and an adapter that cannot report it declares that fact; a policy that uses a freshness limit is refused at load against such a source.
  - **Ingest authorization** — the HTTP ingest adapter is a write surface, so it takes caller authentication and rate limiting exactly as any other does. Beyond that, each ingest credential is bound in operator configuration to the set of (source, metric) pairs it may write, and events for metrics outside that scope are rejected. Permission to send a deducting delta has to be granted again per credential, separately from the source declaration.

## Approver identity

- **R17.** STAMP acts as an OIDC relying party. It verifies the tokens of user actions such as approval submission against an external IdP's JWKS, and stores no credentials, roles or sessions. Verification enforces a fixed issuer set, a required audience, and an asymmetric algorithm allowlist, and JWKS refetches are protected by rate limiting and a negative cache.
- **R18.** The quorum target set is resolved from one of: an explicit list, a token claim, or an IdP group source.
- **R38.** A delegated MFA challenge stores a server-initiated correlator, and judging it satisfied requires an exact match on that correlator and a single consumption of it. `acr` values are restricted to an operator allowlist.
- **R40.** The PEP surface (check, decide, decision lookup) is reachable only by authenticated callers. It verifies workload credentials (an OIDC client_credentials token or mTLS), records the caller identifier on the audit row, and refuses unauthenticated requests before evaluation. Decision lookup is restricted to the caller that created that decision, or to a target approver.

## Authoring UI and console

- **R19.** The policy builder is form-based. Forms are rendered from the schema and source declarations, and it provides a guided authoring flow in the order trigger conditions → source bindings → rules → challenges. entity, action and source declarations are authored inside the same builder, and a path is provided leading from the empty state with no declarations at all through to creating one. The whole authoring flow can be completed with the keyboard alone, form errors are tied to their field with `aria-describedby` and accompanied by an error summary at the top, and contrast must be at least 4.5:1.
- **R20.** The source binding UX guides the settings by kind — for synchronous sources the call target, TTL and error behaviour; for asynchronous ones the event stream and window definition. The call target is a selection from the operator's egress allowlist rather than free input, and targets not on the list are not offered, with the user pointed at the path for requesting one from the operator.
- **R21.** In the approval inbox an approver views the pending decisions raised against them, approves or rejects them, and checks the collection status and the expiry time. The list is sorted by imminence of expiry and shows the remaining time, and the four submission failures (expired, already satisfied, not a target, invalidated by a revision) each have their own on-screen wording and follow-up action.
- **R22.** In the audit console an auditor views decision history, and for each decision reads the policy version applied and the fact snapshot. Auditor capability is determined by an operator-configured token claim or group and enforced server-side, and a user without the capability can view only the decisions they initiated or are a target of.
- **R23.** Policy revision submission shows, before submission, the change diff along with the weakening classification result, any violated operator floor, and the number of pending decisions that will be affected; it has the author choose the application method (re-evaluation by default) and then continues into the revision decision flow. A revision that violates an operator floor is blocked from being submitted at all. **The diff view must be able to display a multi-policy revision** — collapsed per policy, but with items classified as weakening left expanded and placed at the top, distinguishing additions, modifications and deletions visually, and keeping the total number of changed policies and the weakening count visible even while collapsed.
- **R41.** A fresh install instance displays its unlocked state as a standing warning, and the lock flow first shows the resolved approver set and quorum and then takes an explicit re-entry as confirmation.
- **R50.** The console's API base address is configurable and the engine supports a console origin allowlist — serving it embedded is the default, but the same bundle must work when served from another origin. **The base address comes only from operator configuration handed down by whatever serves the console** — it is not read from sources a browser user can write, such as the query string, the fragment, or `localStorage`. The CSP on console responses restricts `connect-src` to the configured API origin and the IdP, so that code which got into the bundle cannot exfiltrate an approver's token to an arbitrary target — an origin allowlist is a request-side control the browser enforces, and it does not stop that direction. The console calls no endpoint outside the public contract, and this is checked in CI.
- **R55.** Collapsing is visual compression, not display suppression. A collapsed item is still rendered into the DOM so it is caught by screen readers and by in-page search, and the approve button becomes enabled only after every item has been expanded at least once. Both rules are needed for R31's guarantee — "the hash is tied to what the approver saw" — to be compatible with a collapsing UI. The approval inbox and the audit console meet the same accessibility level as the policy builder: keyboard completion, `aria-describedby` error association, 4.5:1 contrast. Expand and collapse controls are keyboard operable and expose `aria-expanded` state, and the distinction between change types is conveyed by icon or text label as well as by colour.

## Scale and operations

- **R24.** The check path must scale horizontally with no state shared between instances. The decide path uses shared storage. Within at most `policy_refresh_interval` (default 5 seconds) of a policy taking effect, every check instance judges on the new version. If refresh keeps failing, an instance judges on the old version until a separate setting `policy_staleness_deadline` (default 60 seconds), exposing a staleness metric and a warning, and only an instance past that point switches to fail-closed — tying the freshness requirement and the availability grace period to one knob drops the whole check tier into deny at once during an ordinary DB failover.
- **R25.** Self-hosted installation must be possible with a single container and Postgres.
- **R26.** check p99 latency and maximum QPS are benchmarked continuously in CI. The warm-cache path and the end-to-end path that includes the miss rate are each tracked against a separate threshold.
- **R39.** DB privileges are separated by role — check gets reads and audit inserts, the consumer gets bucket upserts only. The surface that receives external callbacks is exposed on a listener separate from the PEP and console surfaces.
- **R42.** Every secret (the OIDC client secret, the per-role DB credentials, the webhook signing key, the audit checkpoint signing key) is injected only as a file or a Secret reference, and exists in plaintext in no chart values, image or log. Signing keys carry an identifier so they can be rotated without downtime. Starting with demo-only credentials is refused under a non-demo profile.
- **R43.** decide creation, challenge issuance (in particular the IdP request for delegated MFA), outbound external webhooks, approval submission, and the submission, withdrawal and supersession of revision proposals carry per-caller and per-subject rate limits and an outstanding-decision cap, and exceeding a limit is handled as a deny plus an audit event.
- **R51.** In the role flags, console serving and the API surface are selected independently. It must be possible to start the API without the console, and to start console static serving without the API.

## Release

- **R27.** Released under the MIT license.
- **R28.** A demo bundle ships with it. It is composed of docker-compose, Keycloak and example policies, and following the quickstart document alone gets you from install to first verdict, with F4, F5 and F6 demonstrable end to end. **The demo's default delegated MFA path is the RFC 9470 step-up redirect** — Keycloak's CIBA requires a separate decoupled authentication server, and that server is not shipped with the bundle, so putting CIBA in the demo would mean building the authentication approval UI ourselves. CIBA stays as a contract and a client implementation, verified against a mock OP. The default profile is composed without a broker by using the HTTP ingest adapter, and the Kafka path is provided as an optional overlay so that both adapters are demonstrated. The example policies are in the file authoring format exactly as it stands, and the quickstart loads them with apply.
- **R29.** Container images and a Helm chart are provided as release artifacts, releases follow semver and a changelog, and the artifacts are accompanied by an SBOM and signatures.

---

## Key flows

Six flows the requirements above have to compose into. They carry stable
`F`-IDs for the same reason the requirements do: integration tests in
`internal/runtime` cite them, so a flow is a thing that can be pointed at rather
than a story told once.

- **F1. Account whitelist check** (check path)
  - **Trigger:** a PEP calls `check()` with a transaction's source and destination accounts.
  - **Steps:** policy match → source lookup (the whitelist, served from cache while inside its TTL) → condition evaluation → allow/deny returned immediately, audited.
  - **Covers:** R1, R7, R13, R14.
- **F2. Quorum approval of a policy change** (decide path)
  - **Trigger:** an author submits a policy revision from the form builder.
  - **Steps:** the revision request goes through `decide()` → a quorum challenge is created and a pending decision returned → approvers approve from the inbox → on quorum, the decision transitions to allow and the revision takes effect → the application mode chosen by the author runs at that moment.
  - **Covers:** R2, R3, R4, R6, R7, R21, R23.
- **F3. Pending decisions when a revision takes effect**
  - **Trigger:** F2's revision takes effect while decisions raised against the old policy are still pending.
  - **Steps:** the author's chosen mode is applied — revalidation (the default) keeps the approvals that are still valid against the frozen fact snapshot and re-collects only the shortfall; grandfather continues on the old policy version. The mode applied to each pending decision is audited.
  - **Covers:** R5, R7, R31.
- **F4. Compound approval of a large withdrawal** (MFA + quorum)
  - **Trigger:** `decide()` is called for a withdrawal above the threshold.
  - **Steps:** an MFA challenge is issued (a short reference code derived from the correlator is carried in `binding_message`, over an IdP step-up or a CIBA request) → the requester authenticates at the IdP → STAMP verifies `acr`, `auth_time` and the correlator → a quorum challenge collects in parallel → allow once both are satisfied.
  - **Covers:** R2, R3, R4, R38.
- **F5. Velocity limit check** (asynchronous source)
  - **Trigger:** `check()` or `decide()` is called for a withdrawal request.
  - **Steps:** the 24-hour aggregate maintained from the event stream is read locally → compared against the limit → judged. The ingestion path is irrelevant to the read; either adapter serves it.
  - **Covers:** R15, R37, R52.
- **F6. File-authored set revision** (file path)
  - **Trigger:** the author's CI runs `apply` after changing the policy directory.
  - **Steps:** payload limits checked → **pending-revision check** → the directory is read as the desired state → compared against the file-origin policies in force to produce additions, modifications, deletions and adoptions → all of it must pass static validation → the whole set goes through `decide()` as a single revision proposal → `apply` returns the proposal identifier → approvers review the multi-policy diff in the inbox and approve → the application mode runs when it takes effect.
  - The pending-revision check comes before parsing and validation so that a request certain to be refused does not first pay for parsing the entire policy set and compiling its CEL.
  - **Covers:** R6, R10, R23, R45, R46, R47, R54.
