---
title: STAMP decision log
last_updated: 2026-08-10
---

# STAMP decision log

This document records **why STAMP v1 has the shape it has**. What gets built is owned by the feature plan, and how it gets built by the implementation units inside it. What stays here is the choices that are expensive to reverse, the reason each one was taken, and **the alternatives that were rejected**.

There is one reason to write the rejected alternatives down. Months from now, when the same option looks attractive again, you have to be able to tell whether it was already considered.

How each entry is marked:

- **Settled** — a decision the user directed outright, or approved after the alternatives were reviewed. It is not reopened as a matter of preference. It is revised when evidence arrives that its premise has broken.
- **Derived** — a choice that follows technically from a settled decision. It holds as long as the decision above it holds.

---

## Product decisions

### D1. A decision is a lifecycle object, not a boolean

**Settled** · rejected: a stateless PDP plus an external orchestrator

Every team rebuilding an approval orchestrator on top of an existing policy engine is not an implementation mistake but a **model mismatch**. In a model where judgment ends at a single value, quorum collection, MFA round trips and time delays have nowhere to live but outside the engine. So a decision becomes an object carrying state (pending → allow / deny / expired) and the collection status of its challenges, and that collection is pulled inside the engine.

This is why STAMP exists, and the root of most of the decisions below.

### D2. v1 is a complete open-source release

**Settled** · rejected: publishing a vertical slice early

The risk of running out of momentum was known, and a finished first impression was chosen anyway. The release gate is completeness across every area; the recommended build order is engine → authoring path → packaging.

This decision **raises the cost of every later decision that widens scope.** That is why the 2026-08-10 revision put the file authoring path in conditional scope (see D10), and why the decision point was written down so that the condition actually bites at the release gate.

### D3. check and decide are two execution paths over the same policy model

**Derived** (from D1)

Decisions that need state are low QPS, and high-QPS queries need no state. The two requirements looked like a conflict; their profiles are simply opposite. The same policy runs both as a stateless immediate judgment and as a stateful decision creation.

### D4. Standards alignment is AuthZEN; the XACML wire format is not adopted

**Settled** · rejected: XACML 3.0 conformance

Standardization is this product's largest external risk — if a mainstream provider ships the same capability as a standard, an interface of our own becomes debt. So the check surface is made compatible with AuthZEN Access Evaluation, and the decision lifecycle is positioned as a superset extension above it. XACML's wire format was judged not worth following.

### D5. On a policy revision the author chooses the application mode, and the default is revalidation

**Settled** · rejected: a blanket grandfathering default

In a compliance domain, tightening a policy is usually a response to risk. A silent default that lets the old rule keep passing empties the tightening of its meaning. So the default is revalidation, and an author who needs the existing rule kept chooses that explicitly.

**Revalidation does not re-fetch facts.** It reuses the fact snapshot taken when the decision was created. Re-fetching moves the snapshot, which moves the approval binding hash, and the "valid approvals are preserved" that D5 promises is then wiped out in practice. A source is fetched only when the new policy newly references one the snapshot does not hold, and in that case the hash does move, so every approval is collected again.

### D6. A policy change itself passes through a STAMP decision

**Settled** · rejected: leaving policy CRUD as an ordinary API

This is the scenario the user first put forward, and the product's dogfooding. A system that requires a quorum to change a policy gives no reason to be trusted if it does not work that way on itself.

A fresh install starts in single-administrator mode, and after the explicit lock action there is no way back.

### D7. Approver identity is delegated to an external IdP

**Settled** · rejected: a role store of our own

No authentication server is designed here; it closes as an OIDC relying party. No credentials, roles or sessions are stored. There is one side effect, and it is a good one — resolving an approver set from an IdP group turns out to have exactly the same shape as fact procurement (the Fact Plane).

### D8. The authoring UX is a form builder rendered from the schema

**Settled** · rejected: a rule canvas (node graph), code plus live preview

Three visual directions were mocked up and compared before choosing. The price was known when it was paid — **v1's policy expressiveness is bounded by what a form can render.** What that price buys is authoring by non-developers.

It is also why condition expressions are a structured AST of our own (D12).

### D9. MIT license

**Settled** · rejected: Apache-2.0 (recommended but not adopted), AGPL-3.0

### D10. File authoring is a first-class path equal to the form, and the engine is the source of truth

**Settled** (added 2026-08-10) · rejected: form-only authoring, git-as-store

Teams that GitOps suits and teams it does not both exist, so the authoring path has to be a choice. But **making git the source of truth is a separate question, and the answer to that one is no.**

With git as the source, four things break at once. Merge permission becomes permission to change policy, pushing the quorum out into branch protection rules; a revision taking effect cannot sit in the same transaction as the revalidation of pending decisions; the form builder ends up holding git write credentials; and two people editing policy in the form get a YAML merge conflict in a file neither has ever opened — that last one erases the entire reason D8 was chosen.

So the authoring path and the source of truth are separated. Git holds the *desired state* and CI pushes it in; the engine holds the *state in force* and governs the transitions.

**Unverified premise:** that teams requiring file authoring as first-class actually exist is the user's judgment and has not been confirmed against a concrete case. What justifies adopting D10 on top of that is a cost asymmetry, and the asymmetry genuinely holds only as far as **the revision delta's data type and the human-readability of the file format**. Changing either of those later means tearing up weakening classification, approval hashes and revalidation along with them. Apply, export, authoring mode and the CLI are additive and carry no such asymmetry, which is why the plan handles them conditionally at its decision point.

### D11. Abstraction goes at the IO boundary and nowhere else

**Settled** (added 2026-08-10) · rejected: implementing Kafka directly with no broker abstraction

The evaluation core and governance are implemented directly, but where an external system gets swapped there is a port.

This decision **reverses the previous edition.** The earlier ground was "an abstraction with only one implementation just doubles the test budget", which holds for a behavioural abstraction and works the other way round for an IO port. With a port the aggregation logic can be tested without a broker, so the cost falls rather than rises, and the broker can be lifted out of the demo bundle entirely.

---

## Technical decisions

### D12. A structured AST of our own is the canonical form of a condition expression, compiled by cel-go

**Derived** (from D8)

Only a 1:1 correspondence between form and AST makes "the form can render it" a structural guarantee. Assembling a string DSL has no such guarantee, and brings injection and escaping problems with it. Evaluation is left to the proven cel-go, and cel-go compilation is made the last stage of static validation so that **"validation passed" means "compilation succeeded"**. Otherwise a policy that passed the form's preflight fails at storage.

The AST type system is defined as a proper subset of CEL's types — no implicit numeric conversion, and timestamp and duration are the CEL types unchanged.

cel-go's `policy` package is pre-v1.0 and is not used. Only the core compile and evaluate APIs are used, with the compilation layer isolated behind a thin adapter, which absorbs the in-progress `cel-expr/cel-go` repository move and any API changes.

### D13. AuthZEN Final is implemented against directly, with no abstraction layer

**Derived** (from D4)

The spec went Final in 2026-01 and cannot be revised, so there is nothing for an abstraction to defend against.

**The conformance scope is pinned in the contract to the single Access Evaluation profile.** Batch evaluations and the Search API are deferred — the harness demands a whole profile, so leaving the scope open would fix the CI gate at permanently failing.

### D14. Deployment is a single image with role-selected startup

**Settled** · rejected: a single binary only

The requirement to support both single-binary and multi-binary deployment is satisfied by one artifact. One binary starts with all roles or with a subset of them. Loki and Temporal have proven the pattern.

Serving the console and the API surface are **separate roles**. Fusing them makes a console tier with no API exposure impossible, and the reverse too.

### D15. Expiry timers are a Postgres column plus a SKIP LOCKED sweeper

**Derived** (from D14's single-container promise)

It keeps the single-container promise without depending on an external job queue. The column value is the canonical form of expiry and the sweeper is only deferred cleanup — approval submission, state reads and the transition functions all check the deadline the moment they are entered. A path to promoting this to River is left open for larger scale.

### D16. MFA in v1 is delegated mode

**Settled** · rejected: direct WebAuthn first, implementing both

There are effectively only two live standards usable for transaction confirmation (dynamic linking) — RFC 9470 step-up and OIDC CIBA's `binding_message`. WebAuthn has no transaction confirmation extension, and Secure Payment Confirmation is a Chromium-only draft. So it is delegated to an external IdP, and STAMP verifies `acr`, `amr` and `auth_time` and nothing else.

`binding_message` is **for display only and is not a cryptographic binding.** The binding is carried by a server-initiated correlator.

Direct mode is defined in the challenge contract only; the implementation is deferred to v2.

### D17. Velocity aggregation is fixed-width Postgres buckets, and ingestion sits behind a broker-neutral port

**Derived** (from D11 and D14)

A stream processor (Flink, Kafka Streams) conflicts with the single-container promise and is not adopted.

**Drawing the port honestly brings three things with it.** Otherwise it is a Kafka interface that is neutral in name only.

1. Offsets, partitions and consumer groups do not appear on the port. The boundary is "an event arrived" and "processing is committed up to here", and no further.
2. Idempotency is the core's responsibility. The adapter guarantees at-least-once only, and deduplication is done by the aggregator on the event identifier. That is what lets a broker with different redelivery semantics implement the same port.
3. The adapter has to be able to report ingestion lag. The freshness limit is judged against that value.

v1 ships two adapters, Kafka and HTTP ingest. The second does two jobs — it is the device that proves the port is a real seam, and it is the actual feature that removes the broker from the demo bundle.

### D18. The performance targets are a design assumption, not a validated requirement

**Assumption** · adjusted against benchmark results

Check p99 ≤ 10ms on the cache-hit path, ≥ 5k QPS for a single check instance, on reference hardware of 4 vCPU / 8GB.

Alongside it sits **a separate threshold for end-to-end p99 including the miss rate.** Latency on the miss path is dominated by the source declaration's timeout, so measuring a warm cache alone produces a p99 that has nothing to do with operational latency.

### D19. The console ships embedded, with separability secured as a contract

**Derived** (from D14)

A React + TypeScript (Vite) static build is embedded in the binary. There is no console-only BFF; it consumes the engine's public API as it is — which keeps the principle that the API is the public contract.

Temporal split its UI into a separate image because that UI is Node SSR and cannot go inside a Go binary; the STAMP console is a pure static build and has no such constraint. Grafana embeds for the same reason.

**Two things are needed for embedding not to foreclose separation.** The API base address must be configurable and the engine must support an origin allowlist; and the console must hold no endpoint outside the public contract. The second leaks if it is left as a principle, so CI checks it.

v1 ships the embedded build alone; a separate image and CDN deployment are deferred.

### D20. There is one operational dependency: Postgres

**Derived** (from D14)

Policy, decisions, audit, timers, aggregation buckets and the deduplication index are all Postgres. A broker is an **optional dependency**, needed only by a deployment that uses the Kafka adapter.

There is one place this symmetry breaks, and it is intended — event ingestion went behind a port, but **policy storage cannot.** Policy storage has to be in the same transaction as the governance decision and the audit chain.

### D21. Security controls are enforced by code paths and operator configuration, not by policy data

**Derived** (from D6 and D10)

**A policy author is assumed to be outside the trust boundary, not inside it.** Permission to author policy must not become permission to reach infrastructure.

The enforcement points that follow from that principle:

| Threat | Where it is enforced |
|---|---|
| Bypassing a challenge through the check path | An evaluator invariant — not a policy setting |
| The verdict for a request no policy matches | An evaluator invariant — a deny no setting can reverse |
| SSRF to a URL a policy names | The operator egress allowlist |
| An author declaring fail-open | An operator-level flag is required |
| Binding of approvals and MFA | A server-issued hash and correlator |
| A quorum weakening itself | Weakening classification over the diff, plus the operator floor |

### D22. Two authoring paths, one revision pipeline

**Derived** (from D10; added 2026-08-10)

The form and apply are just two different input adapters, and both enter the same "revision proposal → validation → weakening classification → governance decision → effect hook" pipeline.

**A revision proposal is defined as a data structure holding a delta over the policy set, not a single policy.** Form authoring produces a delta with one element. Designed the other way round — the single policy as the base case and the set as the special case — weakening classification, approval hashes and revalidation all come in two copies.

This data type is fixed by M1's governance unit, not by the file authoring unit. That way there is nothing to go back over if file authoring is deferred.

### D23. The two authoring paths split ownership per policy

**Derived** (from D10 and D22; added 2026-08-10)

Every policy is given an authoring origin at creation, and apply's desired-state comparison is confined to policies whose origin is file.

Without this the product does not stand up in its default configuration — a policy made in the console is not in the file directory, so the next CI apply counts it as a deletion and **opens a proposal to delete the console's policies on every single run.**

Moving origin is possible only through an explicit adoption declaration in a file document. There is no implicit move.

### D24. One pending revision at a time, and the lock opens along four paths

**Settled** (2026-08-10) · rejected: invalidating the proposal when the baseline moves, allowing non-overlapping revisions in parallel

Serialization was chosen so that an approver always reviews exactly one diff against the state currently in force. The decision stands on the premise that policy revision is a low-frequency event.

**Serialization on its own, though, locks and never unlocks.** There are four failure paths and they demand different remedies.

| Situation | How it clears |
|---|---|
| CI applies from the wrong directory | Withdrawal by the proposer — no quorum needed, since it only returns to the current state |
| A hostile author occupies the slot with a proposal that cannot be approved | Withdrawal by quorum |
| The approvers do nothing at all | An operator-configured cap on pending lifetime (24h by default) |
| CI applies on every merge | A new proposal from the same origin supersedes the existing one |

All four are subject to rate limiting. Otherwise withdrawing and immediately re-occupying, over and over, holds the gate indefinitely.

**Where the premise is weak:** "low-frequency" holds for form authoring and may not hold for file authoring where CI applies on every merge. The supersede path is the device that covers that gap, and if friction is observed in real use, parallel pending revisions are reconsidered.

### D25. The landing unit is the implementation unit, and the stack is cut at the dependency graph

**Settled** (2026-08-10) · rejected: a linear stack flattening all 11 units into one line, a milestone integration branch, bundling units to cut the number of PRs

The PR unit is not designed anew; the implementation unit is used as it stands. Units were already cut on the criterion of "a meaningful unit that can land in one commit", so cutting them again at landing time produces two partitioning criteria, and the two will diverge.

**The linear stack was rejected because** M1's dependency graph is not a chain but a DAG with join points. U5 requires four units and U7 requires three, and a git PR has exactly one base. The second join point came out of file ownership — U5 builds the `internal/api` server and router while U20 and U9 add handlers to the same package, so a branch without U5 among its ancestors does not compile as a module. That dependency was not declared in the pre-revision unit table; it surfaced while drawing the landing order.

**The merge method is fixed to squash.** Matching unit boundaries to commit boundaries was chosen, and in exchange — since the parent commit does not survive in the child's history — the cost of moving each child with `rebase --onto` on every merge was accepted. GitHub's automatic base retargeting is conditional on deleting the head branch, and it moves only the base pointer without rewriting history, so under squash it does not keep the stack standing — hence an explicit rebase as the rule rather than relying on retargeting. Flattened into one line, false dependencies show up to the reviewer — U6 queued behind U4 — and when the bottom PR is blocked the ten above it stop with it. So the stack is cut at the join points: the lower tier merges to main, then the upper tier starts again from there — the tier boundary is not an invented procedure but a property the graph already has.

**The milestone integration branch was rejected because** main is empty right now, which makes main itself the milestone. An integration branch defers the discovery of real conflicts to one enormous merge at the end.

**Bundling units to cut the number of PRs was rejected because** M1's largest units (U4, the storage layer; U9, governance) are already heavy on their own, so bundling pushes them past a reviewable size. That the same reasoning points the other way was accepted along with it — if a unit grows past a reviewable size during implementation, the unit decomposition itself is revised rather than the PR split. That is what keeps units and PRs 1:1.

**The join gate is each unit's own set of prerequisites, not waiting for a whole tier.** Waiting for a whole tier revives at the tier boundary exactly the reason the linear stack was rejected — false dependencies and the chain-stopping of unrelated PRs. U7 waiting because U6's PR is blocked, when U7 does not require U6, is the example.

**Left unresolved:** this repository is private on a free plan, so the branch protection API is unavailable and the merge gate is not enforced. It runs as a convention until the repository goes public or moves to Pro, at which point it is locked down as a required check.

### D26. The demo's default delegated-MFA path is a step-up redirect, not CIBA

**Settled** (2026-08-10) · rejected: building a decoupled authentication server ourselves and shipping it with the demo, leaving delegated MFA out of the demo entirely

This is what U0 found by actually standing Keycloak up. The CIBA grant surface is real, but the only implementation of the `ciba-auth-channel` SPI is an adapter that hands authentication to an **external** HTTP endpoint, and Keycloak does not ship that authentication device server. A CIBA request that is valid in form still fails at that point.

Putting CIBA in the demo means building the authentication approval UI ourselves and standing it up as a third service in compose. That amounts to building a server outside the product's scope for the convenience of a demo, so it was rejected. Leaving delegated MFA out of the demo is wrong in the other direction — the decision lifecycle is this product's thesis, and a demo without it does not show the product.

So the RFC 9470 step-up redirect, which U10 had already written down as a fallback, was promoted to the demo's **default** path. CIBA stays as a contract and a client implementation, verified against a mock OP.

**Two constraints surfaced with it.** `binding_message` carries a 50-character cap and forbids whitespace, so a serialized decision context cannot be put in it — only a short reference code derived from the correlator goes there. That is consistent with the existing decision that the binding is the correlator's job and `binding_message` is for display. And `amr` comes back as an empty array in a default configuration, so it was demoted to optional in the satisfaction condition — required, it would make the challenge structurally impossible to satisfy.

**Where the plan was confirmed right.** An `acr` request that is not satisfied comes back as a silent downgrade rather than an error. Which means verifying the `acr` on the response is not a convenience but the only line of defence.

---

### D27. The before side of a revision delta is written by the server

**Settled** (2026-08-10) · rejected: comparing the submitted before against stored state and refusing on mismatch, pinning before with an optimistic concurrency token

The weakening classifier sets the approval requirement a revision has to meet (R33). That classifier compares two policy sets, one of which must be the state in force. But `assess()` classified the submitted delta as it arrived, and the classifier was the only reader of `Change.Before` — `Delta.Result` applies only `After`, and `Delta.Validate` looked only at shape. **A proposer who wrote a convenient past wrote their own classification.**

Compare-then-refuse was rejected because the console has no reason to send a before in the first place. Having the client send back what the server already knows and then checking that it agrees only adds a round trip and a new error path for the mismatch. An optimistic concurrency token is the answer to a different problem — the set in force moving while a proposal is open — and that problem is already held by `ErrBindingChanged` and the revalidation path.

**The reconstruction does not expand.** It fixes the `Before` of the changes the proposer declared and invents no change that was not there — taking the whole set in force as the before would count every console-authored policy as a deletion on each file apply, which overturns D23.

**The ordering is half the decision.** The reconstruction comes before `Validate`, `Classify` and `Digest`, all three. It has to come before `Digest` for R31 to hold — the hash an approval binds to and the delta the approver sees have to be the same thing, and that has to be true.

**It does not reach back over results already produced.** It is not retroactive to pending revisions issued before this commit. The effect path does not read `Before`, so behaviour is correct and the digest does not move either, which means no collected approval evaporates; but if a forged pending revision existed at the moment of the upgrade, it can take effect under the lenient classification. Retroactive reclassification would invalidate every approval already collected, which was the more expensive choice.

**Left unresolved:** `Change.FromOrigin` is still not compared against stored state. The console can move a policy's authoring origin with `take_ownership` and no `Adoption` document — a separate hole, from R54's point of view.

---


## Revision history

### 2026-08-07 — First edition

D1–D9 and D12–D21 settled. The plan reached implementation-ready.

### 2026-08-10 — Authoring paths and the IO boundary

It started from two questions. Is embedding the console right even in a role-split deployment, and what about letting the policy files' backend be configured in different ways.

The answer to the first was **keep embedding it** — the console consumes only the public API, so the seam for separating them is already open, and Temporal's split was forced by Node SSR, a constraint we do not have. The two things that could close that seam (a configurable API address, no calls outside the public contract) were pinned as contract.

The second question rested on a wrong premise — the plan had never made git the store. As the conversation went on the real requirement surfaced: **file authoring has to be a first-class path usable in place of the form.** D10, D22, D23 and D24 came out of that.

Third, the user raised abstraction at the IO boundary, which added D11 and reversed D17.

### 2026-08-10 — Multi-lens review incorporated

Independent review from seven lenses (coherence, feasibility, security, adversarial, scope, product, design) surfaced the following.

**Convergence across independent contexts** — four lenses each pointed at the missing way out of the pending-revision lock, and two pointed at policy deletion being absent from weakening classification. Both were taken up (D24, D21).

**Defects established from the document text alone** — CI apply proposing the deletion of console policies in the default configuration (resolved by D23); the broker-less default demo possibly being unable to load because of the freshness requirement (resolved by defining ingestion lag against the producer's timestamp); and Dex, which had been named as the demo IdP, supporting neither CIBA nor step-up (the product name is left unpinned until a spike settles it).

**Present before this revision and only now surfaced** — the identity layer caught in a circular dependency (split out as its own unit); whether revalidation re-fetches the fact snapshot never having been settled, which left D5's preservation of approvals not holding (settled as reuse of the fixed snapshot); and the verdict when no policy matches never having been defined (settled as a fail-closed deny invariant).

### 2026-08-10 — Landing strategy

Filled the gap where the plan said nothing about how work lands. (This revision precedes the U0 entry below.) The implementation unit is used as the PR unit as it stands, and the tier structure that cuts the stack at the dependency graph's join points was settled (D25). The four sections of a PR body (background, approach, rationale, where to look closely) were pinned into the plan's landing strategy as well — in particular alongside the rule that keeps the rationale section citing this decision log rather than re-arguing it.

### 2026-08-10 — U0 falsification spike results incorporated

Three premises were checked by actually running them. Two held, one was revised.

**What was revised** — an end-to-end CIBA demonstration in the demo bundle turned out not to stand up, and D26 was added. The format constraints on `binding_message` and `amr`'s default emptiness were confirmed alongside it, revising R3, R28, AE6, F2 and U10. This is the first case of the falsification device actually falsifying something, and it caught it before implementation, so the cost was a document revision and nothing else.

**What held** — U4's premise that a per-segment audit chain has at least an order of magnitude more throughput than a single global chain held, and one instance's exclusive claim on a `writer_id` was pinned as a correctness requirement. The AuthZEN harness is reproducible in CI and the Access Evaluation profile can be selected on its own — though the runner exits 0 regardless of the result, so U5 cannot stand a gate on it without a wrapper that parses the output.

The observations and the conditions they were measured under are in `docs/spike-results.md`.

### 2026-08-10 — Landing procedure fix: deleting a parent branch closes the child PR

Running D25's stack procedure for real caught on the first tier. Squash-merging `#1` with `--delete-branch` left `#3`, which stood on top of it, not retargeted but **closed**, and a PR whose base branch is gone does not reopen even when the branch is restored. There was no way out but to raise it again under a new number.

Review had pointed this risk out in advance, and it was treated at the time as an unconfirmed claim and left out of the procedure. Now that it is confirmed, the **order** of merge, rebase, retarget and delete is pinned as a rule. A parent with children is deleted only after the children have been moved.

The lesson runs ahead of the procedure — an unconfirmed risk a review names must be either refuted or confirmed; it must not be left alone on the grounds that it is unconfirmed.

### 2026-08-10 — An authorization hole came out from under the gap U15 reported

U15 reported "there is no way to read the schema in force, so editing an existing policy is impossible" as a missing capability, and noted alongside it, as a side effect, that the console therefore cannot carry `schema_before`, which leaves R33's `on_error` weakening invisible to the classifier.

Digging into the second item, it was not a gap but a **hole**. The classifier's entire before side was under the proposer's control, and that covered not only the schema but reducing a quorum, widening the approver set and narrowing a trigger. D27 is the answer to it.

Two lessons. What a unit writes down as a "side effect" can be larger than the main item — this was caught because U15 wrote it down instead of hiding it. And after this fix the `schema-read` endpoint settled into being **a form-rendering capability requirement rather than a security requirement**. Closing the hole first changed the nature of the original request.
