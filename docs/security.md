# Security

What STAMP protects, how, and — because this repository ships a demo bundle —
exactly which of the demo's settings would be defects anywhere else.

## Nothing that is a credential or a trust decision has a default

A missing DSN, a missing issuer, a missing audience each fail the boot with a
message naming the variable. A process that started with a guessed issuer would
be verifying tokens against something nobody chose, and a process that fell back
to a default database would be writing an audit chain nobody reads.

Everything that is a tuning knob does have a default, and the default is the
safe direction: fail-closed audit, no fail-open fact sources, no loopback or
private egress, a governance floor of one approver, `STAMP_AUTHORING_MODE=both`
on top of origin separation rather than instead of it.

The one shape of misconfiguration this rule cannot catch is a value that is
present and wrong, which is why the two settings that would fail *open* —
`STAMP_AUTHORING_MODE` and `STAMP_MFA_ACR_VALUES` — refuse the boot rather than
falling back. An unrecognized authoring mode does not quietly become `both`: the
only direction that setting can be wrong in is "I thought I closed that, and it
is open", so refusing to start is the only safe failure.

## Secrets are injected as files or secret references

| Secret | How it arrives | Never |
|---|---|---|
| Audit checkpoint signing key | `STAMP_AUDIT_CHECKPOINT_KEY_FILE`, a mounted PEM | there is deliberately **no** variable that carries the key itself |
| Database credentials | inside `STAMP_DSN`, from a secret store | in an image, a chart value, or a log |
| OIDC client secrets | held by the *workload*, not by STAMP | STAMP verifies tokens; it holds no client secret for the PEP |
| Webhook signing secrets | `STAMP_EXTERNAL_TARGETS`, a JSON document or a path to one | in a policy — a policy names a target, it cannot name a URL |
| Group directory credentials | `STAMP_IDP_GROUP_SOURCES`, likewise | reachable from any policy document |

Signing keys carry an identifier so that rotation is a new file and a new id;
keep the retired key's public half in `STAMP_AUDIT_CHECKPOINT_VERIFY_KEYS` and
everything it signed stays verifiable without being re-signed. That variable
names *retired* identifiers only: the active key's public half is derived from
the signing key, and naming the active id there is a configuration warning.

The quickstart asserts the negative directly — after a full run it greps every
generated credential and the private key against every container log and against
the console's configuration document, and fails the run on a hit.

## The demo bundle ships no credentials, and that is R42's answer here

R42 asks that a start-up on demo-only credentials be refused outside a demo
profile. The runtime has no notion of a profile, and this unit decided **not to
invent one.** The reasoning:

- A profile flag is a denylist wearing a different hat. It can only refuse the
  exact credentials someone thought to list, so an operator who copies the demo
  compose file and changes one character passes it. A control with a silently
  permissive path is worse than no control, because it is *reported* as a
  control.
- The flag would itself be a new fail-open switch: a boot-time value whose
  "demo" setting disables a check. Settings like that get turned on by whoever
  is trying to make something start, which is precisely the population the check
  exists for.
- The strong form of the requirement is achievable without any runtime concept:
  **make the demo credentials not exist.** They are generated per installation
  by `scripts/quickstart.sh` into an untracked `deploy/demo/.env`, resolved into
  the Keycloak realm at import through `${PLACEHOLDER}` substitution, and the
  audit checkpoint key is generated inside a container on first `up`. There is
  no credential in this repository that a non-demo deployment could be started
  with, so there is nothing for a runtime check to recognize.

**Residual risk, stated rather than hidden.** This closes "somebody ships our
demo credentials". It does not close "somebody promotes their own demo
installation to production" — the generated `.env` is a real credential set, and
nothing stops it being copied. What guards that direction is everything else on
this page being visibly false of the demo: plaintext OIDC, a dev-mode IdP, a
disposable database. A runtime profile flag would not have closed that direction
either. The open question is tracked as a follow-up issue rather than answered
by a check that would not hold.

## What the demo does that a real deployment must not

Every one of these is a deliberate, load-bearing choice in
`deploy/demo/docker-compose.yml`, and every one of them is wrong outside a
laptop.

| Demo setting | Why it is there | What a real deployment does |
|---|---|---|
| `STAMP_OIDC_ALLOW_INSECURE_TRANSPORT=true` (and the console and MFA equivalents) | the demo IdP is plaintext HTTP on localhost | leaves all three unset; TLS everywhere, and the flags exist for loopback development only |
| Keycloak `start-dev` | one container, no external database, no TLS | a production Keycloak with its own store, TLS, and a hardened realm |
| `STAMP_AUDIT_CHECKPOINT_INTERVAL=10s` | so the quickstart has something signed to verify within its runtime | the five-minute default, or longer |
| Checkpoint signing key on a shared container volume | there is nowhere else to put it in a compose file | a mounted secret from a KMS or secret store, readable by the `api` role alone |
| Postgres on `tmpfs`, one superuser | `docker compose down` leaves nothing behind | durable storage, and the per-role credentials `STAMP_DB_ROLE_*` provisions |
| `STAMP_POLICY_REFRESH_INTERVAL=2s` | so the demo's "the answer changed" steps are not a wait | the default; this is a load knob, not a safety one |
| Kafka with `PLAINTEXT` and no ACLs (overlay) | a single-node broker for one topic | ACLs on the topic are **mandatory**: without them the topic is an unauthenticated write into somebody's velocity aggregate, because the Kafka path has no per-request credential to scope |
| A password-only IdP with `acr` class `1` | there is no second factor to enrol in a demo | an `acr` allowlist that names a class the IdP only issues after a real step-up |
| All five roles in one process | one container is easier to read | `--roles` split across tiers, with the console and API surfaces separated |

## The controls that are not configuration

- **Two kinds of caller, and the mount table enforces it.** The PEP surface
  admits workload credentials, the console surface admits end-user ones, and the
  callback surface admits workload and public ones. A route mounted on one
  listener is not reachable through another, because the other listener's router
  has never heard of it. The rules are stated a second time in the code paths
  that matter — an approval is recorded under the `sub` of an end-user token and
  a workload credential is never an approver, checked in the challenge handler
  and not only in the mount table.
- **An inactive role has no routes, not forbidden ones.** A `--roles=api`
  process answers 404 on the console bundle rather than 403, because the routes
  were never mounted.
- **The egress gate is deployment configuration, not policy data.** A policy
  names a source; an operator decides what that source may dial. A fact source
  whose URL is not on `STAMP_EGRESS_ALLOW` fails the boot — the quickstart
  asserts exactly this, with a throwaway process that refuses to start.
- **A velocity source may not fail open.** A limit that switched itself off when
  ingestion broke would be the cheapest attack there is on it. A synchronous
  fact source may fail open, and only if the operator sets
  `STAMP_FACT_ALLOW_FAIL_OPEN` — a schema that asks for it without that flag is
  refused at load.
- **A group directory that cannot answer means the challenge is not issued,**
  whatever the declaration's failure behaviour says. There is no fail-open shape
  for "who is permitted to approve this".
- **The policy set export is gated per caller and fail-closed.** Its output
  carries every approver identity, every quorum threshold and every internal
  call target in one document — that is, which transactions can be split under
  which threshold to avoid approval. It requires `policy.author` or `audit.read`
  in `STAMP_CAPABILITY_CLAIM`, and a token without the claim gets nothing. In
  the demo only `ann` has it.
- **A revision's `before` face is written by the server.** The classifier that
  decides how many approvals a change needs compares the proposal against what
  is in force; a proposer who could state the past could write their own
  classification.
- **One pending revision at a time,** so an approver always reviews one diff
  against the current effective state, with four documented ways out of the
  resulting lock. Every one of them is rate limited.
- **The audit chain is a hash chain per writer, and checkpoints are what make it
  more than that.** Whoever can write the database can recompute every hash, and
  the result re-chains perfectly; what they cannot produce is a signature over a
  head, made with a key the database does not hold and published outside it.
  `stamp audit verify` distinguishes four outcomes and the one to alert on
  alongside a mismatch is `7`, no verdict — zero checkpoints produce zero
  faults, so a command that called "nothing to verify" a pass would call a
  control that quietly stopped working a healthy one.
- **The console has no backend of its own.** Its API base address comes from a
  server-rendered document and from nothing else — not a query string, not a
  fragment, not `localStorage`, all three of which are writable by whoever can
  send an approver a link, and the console holds that approver's token. Every
  console response carries a CSP whose `connect-src` names only the configured
  API origin and the IdP, and CI checks in both directions that the console
  calls nothing outside the declared public contract.

## Reporting

STAMP is pre-v1 and has not been audited. If you find something, open an issue —
and if it is exploitable, say so in the title rather than in a proof of concept.
