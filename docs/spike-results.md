---
title: STAMP U0 Falsification Spike Results
date: 2026-08-10
unit: U0
plan: docs/requirements.md
---

# STAMP U0 Falsification Spike Results

The three premises standing on the thinnest evidence in the plan were run for real, at the point where falsification was cheapest. The output is the decision; the spike code was discarded — only this document remains.

Each item closes one of three ways. **Confirmed** (the premise holds) · **Revised** (a negative result, naming which decisions and demo bundle composition it forces a change to) · **Unresolved** (no conclusion within the deadline; the default adopted and the recheck point are recorded).

| # | Item | Status | Units affected |
|---|---|---|---|
| S1 | CIBA / acr step-up capability of a self-hostable IdP | **Revised** | U10, U18, R28 |
| S2 | Concurrent insert throughput and check-latency order of magnitude of the segmented audit chain | **Confirmed** | U4, U5, U17 |
| S3 | CI reproducibility and profile selection of the AuthZEN interop harness | **Confirmed** | U5 |

**Measurement environment.** Docker 29.4.0, containers on aarch64/linux (a Linux VM on macOS), 10 logical cores on the host. Keycloak 26.4.7, PostgreSQL 17.10 (alpine, untuned — `shared_buffers=128MB`, `fsync=on`, `synchronous_commit=on`), Node v22.21.1, `openid/authzen` at commit `6fb7fa85c86acda14710f9f0f161da9aaa801a45` (2026-07-27). Image pulls and access to github.com worked normally for all three items — none was left unresolved for network reasons.

---

## S1. CIBA / acr step-up capability of a self-hostable IdP — **Revised**

### What was checked

The plan delegates MFA to "a self-hostable IdP that actually supports CIBA or RFC 9470 step-up" (R28, U10), and deferred confirming that such an IdP exists to U0. Dex is a federation broker and implements neither the CIBA grant nor acr-based step-up, so it was never a candidate. Keycloak was set as the primary candidate, and four questions were asked of it — does the CIBA grant actually stand up, can `binding_message` carry decision context, does CIBA require a separate server, and does `acr` step-up work with `acr`, `amr`, and `auth_time` landing in the token.

### How

Keycloak 26.4.7 was brought up in a container with `start-dev --features=ciba,preview`, and a dedicated realm was built with a confidential client with the CIBA grant enabled and one user. The discovery document was read, requests were sent directly to the backchannel authentication endpoint, an ACR→LoA mapping and a conditional authentication sub-flow were configured, and an authorization code flow was scripted end to end and the ID token claims decoded.

### Observations

**The CIBA surface is real.** Discovery lists the `urn:openid:params:grant-type:ciba` grant, `backchannel_authentication_endpoint`, and `backchannel_token_delivery_modes_supported: ["poll","ping"]`.

**`binding_message` has a format constraint.** A string carrying an amount and a payee was rejected.

```
{"error":"invalid_binding_message","error_description":"the binding_message value has to be
 max 50 characters in length and must contain only basic plain-text characters without spaces"}
```

A 50-character cap, **no spaces**, and basic plain-text characters only. A short reference code like `TXN-4417` passes.

**CIBA requires an external decoupled authentication server.** A well-formed request fails at the next step with a 503.

```
{"error":"server_error","error_description":"Failed to send authentication request"}
RuntimeException: Authentication Channel Request URI not set properly.
  at HttpAuthenticationChannelProvider.checkAuthenticationChannel(...)
```

The only implementation registered under the `ciba-auth-channel` SPI is `ciba-http-auth-channel`, an adapter that delegates authentication to an external HTTP endpoint. Keycloak does not ship an authentication-device (AD) side implementation — running CIBA end to end means building that server ourselves and adding it to the demo compose file as a third service.

**acr step-up works once configured.** Setting the realm attribute `acr.loa.map` to `{"gold":2,"silver":1}` and attaching a `Condition - Level of Authentication` (`loa-condition-level=2`) conditional sub-flow under a copy of the `forms` browser flow makes an `acr_values=gold` request execute the higher-assurance authentication step, and the ID token comes back with `acr='gold'` and `auth_time` present. `acr_values=silver` returned `acr='silver'`.

**An unsatisfiable acr is not an error — it is a silent downgrade.** Before configuration, both `acr_values=2` and the OIDC essential-claim form (`claims={"id_token":{"acr":{"essential":true,"values":["2"]}}}`) returned `acr='1'` without error. After configuration, requesting `acr_values=platinum`, which is not in the mapping, returned `acr='gold'` without error. Whether the requested value was honored can only be known by **validating the response**.

**`amr` is empty by default.** The `oidc-amr-mapper` exists but is not on the default client scope; the claim is absent entirely until the mapper is attached, and even after attaching it the value was `[]` following password authentication. Neither `auth-username-password-form` nor `auth-otp-form` exposes a config property to set an AMR value.

### Status and implications — **Revised**

The capability premise itself holds. A self-hostable IdP has both CIBA and acr step-up, and **the demo IdP is settled as Keycloak.** Three points in the plan need to change, however.

1. **An end-to-end CIBA demonstration in the demo bundle does not hold up (R28, U18).** Adding the IdP to compose is not enough to make CIBA run — a purpose-built decoupled authentication server is also needed, which for demo convenience amounts to building an authentication-approval UI ourselves and is out of scope for v1. **The demo's default delegated-MFA path is pinned to the RFC 9470 step-up redirect, and U18's "the delegated MFA flow succeeds end to end in the demo bundle" scenario is read against that path.** CIBA stays as U10's contract and client implementation, verified against a mock OP — U10 already states the fallback "if the IdP does not support CIBA, fall back to the step-up redirect flow," and this simply makes that fallback the demo's default.
2. **U10's approach of serializing decision context into `binding_message` cannot be used as written.** The IdP rejects any string beyond 50 characters or containing spaces. Only a short reference code derived from the correlation identifier is carried there, and the human-readable amount and payee are fetched by the approval screen through a decision lookup instead. This change is consistent with the existing decision that "`binding_message` is display-only, not a cryptographic binding, and binding is the correlation identifier's job" — it only needs the format constraint stated explicitly.
3. **`amr` validation is dropped as a required condition (U10, R3, AE6).** Because the default-configuration IdP returns an empty array, putting `amr` into the satisfaction conditions would make the delegated-MFA challenge structurally unsatisfiable. `acr` allowlist / policy-requirement satisfaction and the `auth_time` floor stay required, and `amr` is demoted to an optional condition checked only when present.

There is also a point where the plan was already right. **Because the IdP does not tell the caller whether the requested `acr` was honored, U10's requirement that "`acr` belongs to the operator allowlist and satisfies the policy requirement" is not a convenience check — it is the only line of defense.** Without it, a silently downgraded low-assurance authentication satisfies the challenge as-is.

---

## S2. Throughput and check-latency of the segmented audit chain — **Confirmed**

### What was checked

U4 hinges on splitting the audit chain into `(writer_id, seq, prev_hash)` segments with instance-local append. Two questions were asked — does segmenting actually change the order of magnitude, and what order of magnitude is the storage round trip on the check path, including a cache miss.

**This is not a benchmark, it is an order-of-magnitude probe.** Nothing was tuned, the client runs in the same container as the database so there is no network hop, and the numbers below are not used as the basis for any absolute target.

### How

An `audit_log(writer_id, seq, prev_hash, hash, payload, created_at)` table, keyed by `(writer_id, seq)`, was created in a `postgres:17-alpine` container, and a single `INSERT ... SELECT` that reads its own segment's head with `LEFT JOIN LATERAL` and computes `sha256(prev_hash || payload)` was driven with `pgbench`. Each pgbench client owned its own writer segment via `:client_id`, mimicking the real deployment shape (instance = writer). The control configuration has every client writing a single chain `w0`, serialized with `pg_advisory_xact_lock`. The check probe is a transaction that looks up one policy row and one fact row (in a 200,000-row table), each by primary key.

### Observations

| Configuration | Clients | TPS | Mean latency |
|---|---|---|---|
| Segmented chain (writer = client) | 1 | 383 | 2.6 ms |
| Segmented chain | 8 | 4,653 | 1.7 ms |
| Segmented chain | 32 | 11,885 | 2.7 ms |
| Single global chain (advisory-lock serialized) | 32 | 508 | 63.0 ms |
| Check probe (1 policy row + 1 fact row) | 8 | 48,921 | 0.16 ms |
| Check probe | 32 | 40,158 | 0.80 ms |

Segmented append is on the order of **10⁴ inserts/second** at 32 writers, and a single global chain at the same concurrency is on the order of **10²–10³** — a gap of at least one order of magnitude. Running 32 writers for 20 seconds produced 234,847 rows across 32 segments; re-chaining them with a `lag(hash)` window found **zero broken links, zero hash mismatches**.

The storage round trip on the check path is **under 1 ms**.

The single-global-chain control also surfaced something incidental. Sending append statements without an explicit transaction makes concurrent clients die immediately with `duplicate key value violates unique constraint "audit_log_pkey" ... (w0, 1)`. Per-segment append is lock-free only as long as one writer owns that segment exclusively.

### Status and implications — **Confirmed**

U4's premise — that segmenting changes the throughput order of magnitude — holds. Three things follow.

1. **`writer_id` must be exclusively owned by one instance.** Two processes claiming the same `writer_id` fail append on a primary-key collision, which is a correctness problem, not a performance one. U4's implementation must acquire the writer identifier exclusively at boot, and a collision must be treated as a boot failure, not papered over with retries.
2. **Storage is not the dominant term in the check verdict's latency budget.** The order of magnitude of a cache-miss cost is set by the remote HTTP fact source (10¹–10² ms), not by the policy/fact row lookup (10⁻¹ ms). U5/U6's latency discussion can stay focused on the remote source's timeout and cache policy.
3. **U4's stance of not asserting insert throughput as a requirement stands.** The numbers above were taken untuned, on the same host, with no network hop, and will not reproduce on a shared CI runner. The current design, where the U17 bench only records the numbers as an artifact, is correct as is.

---

## S3. CI reproducibility and profile selection of the AuthZEN interop harness — **Confirmed**

### What was checked

U5 treats "passing official interop conformance" as completion evidence. Two questions were asked — is the harness reproducible in CI, and can the Access Evaluation profile alone be selected.

### How

`openid/authzen` was cloned to find where and what shape the harness is, its dependencies were installed and it was built, and it was run for real against a disposable mock PDP that echoes back the fixtures' expected values. Both a failure path (an unreachable PDP) and three profile variants were run, checking exit codes each time.

### Observations

**The harness is a standalone script inside the repo.** It is just `interop/authzen-todo-backend/test/runner.ts` and the JSON fixtures in the same directory. The harness itself does not stand up the Todo backend application — it only hits `POST {PDP}/access/v1/evaluation` (and `/evaluations`). `yarn install --frozen-lockfile` took 5 seconds and `yarn build` took 2 — no native build, no failures. With no external service dependency, **pinning the commit and vendoring the fixtures makes offline reproduction in CI possible.**

**The profile is chosen as a spec-variant argument.** It is the second argument of `yarn test <pdp-url> <spec-version> <format>`.

| Variant | `evaluation` cases | `evaluations` cases |
|---|---|---|
| `authorization-api-1_0-00` | 40 | none |
| `authorization-api-1_0-01` (default) | 40 | none |
| `authorization-api-1_0-02` | 40 | 3 |

`-00` and `-01` run **only** the single Access Evaluation endpoint. The batch endpoint (`/access/v1/evaluations`) is an increment that only `-02` adds, and the Subject/Resource/Action Search profiles are not in the harness at all. Running `-01` against the mock PDP confirmed **40/40 PASS**, and running `-02` split 4 cases out of 43 as FAIL, including all 3 batch cases — the profile boundary is real.

**The harness is not by itself a CI gate.** `runner.ts` exits 0 regardless of the result. A run against an unreachable address, where all 40 cases came back ERROR, still exited with **0**.

### Status and implications — **Confirmed**

It is reproducible and the profile is selectable. U5's conformance-scope decision (pass the full Access Evaluation profile) stands as is. There is something U5 must handle at implementation time, though.

1. **`.github/workflows/conformance.yml` must not rely on the harness's exit code.** It needs a wrapper that parses the `console` output and fails if any line is not PASS. Without that wrapper, hooking the exit code up means CI is always green and the gate sits silently empty — the same class of failure the plan already flagged when it warned about the `branches:` filter in U1.
2. **The conformance target is set at `authorization-api-1_0-01`'s 40 cases.** If the batch endpoint is not in v1 scope there is no reason to target `-02`; if it is, that only adds 3 cases. The fixture set is 40 cases, so U5's `testdata/conformance/` porting work should be sized to that.
3. **The harness commit is pinned.** Because the fixtures update on the repo's main branch, an upstream change will break our CI unless the commit is fixed via a submodule or vendoring. The baseline commit is `6fb7fa85c86acda14710f9f0f161da9aaa801a45`.

---

## What remains

The spike code was discarded — no artifact survives outside this document. The plan changes the three items above call for (S1's three) are applied by whoever owns the plan and the decision log.

S1 confirmed capability, not operational fitness. The demo IdP's container image size and boot time feed directly into U18's quickstart time budget, so at the point U18 starts, the full compose boot time is measured once, and this is reopened only if it exceeds budget.

### 2026-08-11 — S1's remaining item closed (U6)

**Measured, and within budget. Not reopening.**

This is a real measurement of the demo bundle (`deploy/demo/`) standing up and `scripts/quickstart.sh` completing. The measurement environment is the same machine as above (a Linux VM on macOS, Docker, 10 logical host cores), with Keycloak 26.4.7, PostgreSQL 17 alpine, and Apache Kafka 3.9.1.

| Condition | Script start → first verdict (check) | Script start → everything complete |
|---|---|---|
| Default profile, all demo images removed first (including every pull) | 42s | **45s** |
| Kafka overlay, same conditions | 38s | **43s** |
| Default profile, warm image cache | 24s | 27s |

Image pull dominates, and standing up all the containers accounts for most of the 45s. `docker build --no-cache` was a separate 29s (the Go module and npm `--mount=type=cache` caches are preserved by design, so that much stays warm). Even adding the worst-case combination together, total time stays under 100 seconds.

AE9's initial target is 15 minutes, so there is **headroom of two orders of magnitude.** The Keycloak image, at 458MB, is the largest item in the bundle, but this measurement's conclusion is that it is nowhere near a size that threatens the budget. There is no longer any reason to keep open the option of switching to a lighter IdP.

CI runs both profiles on every PR, each on a genuinely clean runner, and uploads `deploy/demo/.run/quickstart-timings-<profile>.txt` as an artifact — if the numbers above regress, it will show up there.
