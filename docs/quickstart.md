# Quickstart

From nothing to a decision that waited for two approvers, in one command.

```sh
git clone https://github.com/d0lim/stamp && cd stamp
scripts/quickstart.sh
```

You need `docker` (with Compose v2), `curl`, `jq` and `openssl`. You do **not**
need a Go toolchain or Node: the `stamp` CLI is invoked inside the image, which
is also how an operator who has only the container would do it.

## The script is the procedure

There is no numbered list in this document, and that is deliberate. A procedure
written twice drifts, and the copy nobody executes is the one that rots. So
`scripts/quickstart.sh` is the canonical statement of how STAMP is installed and
driven, **CI runs it on both demo profiles on every pull request**, and this
page explains what it does and why. If you want the steps, read the script — it
is written to be read, and each step prints what it asserted.

## What it proves

Each of these is an assertion in the script, and a failure of any one of them
fails the run.

- **A `check`.** The stateless, AuthZEN-compatible path: a small domestic
  transfer is allowed by `routine-transfer`. The same request against a policy
  that carries a challenge is a deny with reason `requires_decision` — there is
  nowhere for a pending approval to live in a call that returns immediately.
- **A `decide`, with the approval collected.** A transfer of 25,000 creates a
  decision that stays `pending`, shows up in `bob`'s approval inbox, and
  resolves to `allowed` when the second of two named approvers submits. Each
  approval echoes the binding hash from the review it was made against, so an
  approval is an approval of the thing the approver saw.
- **A velocity deny.** Three events of 25,000 arrive through the profile's
  ingestion adapter; the account's daily total crosses its ceiling; the same
  small transfer that was allowed a moment ago is now denied with
  `condition_not_met`. The limit is a term in the policy, not a mechanism beside
  it.
- **The authoring path, end to end.** `ann` logs in through the demo IdP with
  the console's own client and PKCE, submits the revision document the form
  builder produces, `bob` and `cid` approve it out of their inbox, the revision
  takes effect, and the answer to a request changes as a result.
- **The file path round trip.** The effective set — including the policy that
  was authored through the console API — is exported to a directory and applied
  back, and STAMP reports no change. The two authoring paths agree on one set.
- **The audit chain.** `stamp audit verify` runs the way an auditor runs it,
  with the checkpoint public key and no signing key in its environment, and
  exits 0.
- **Two refusals.** A process configured with a fact source that reaches outside
  and no egress allowlist does not start. And none of the generated credentials,
  nor the checkpoint private key, appears in any container log or in the
  console's configuration document.

- **A delegated MFA challenge, completed in a browser.** `dana` is sent to the
  demo IdP by the address the decision response carries, signs in at the real
  login form, and the IdP redirects back to that challenge's own callback path.
  STAMP redeems the authorization code with the PKCE verifier it kept, checks the
  `acr` on the ID token that comes back — which is the only thing standing
  between a silently downgraded login and a satisfied step-up — and the decision
  resolves. On the way, a redirect echoing a `state` this deployment never issued
  is refused before any token call is made. See
  [`deploy/demo/README.md`](../deploy/demo/README.md) for how the three seams fit
  together.

## The bootstrap token and the lock are steps, not footnotes

On its first start with the `api` role, STAMP installs the reserved governance
policy and prints a one-time bootstrap token. Until governance is locked, that
token is what authorizes a governance action — which means the installer is a
solo administrator, and an unused token raises a critical audit warning on a
timer until it is spent.

The quickstart therefore reads that token out of the container's log (an
operator reads it off their terminal), uses it to load the example policies, and
then locks governance on a quorum of two out of `ann`, `bob` and `cid` before it
does anything else. Every revision after that point collects two approvals,
including the one the script submits next. Leaving those two steps out of an
install guide is how an installation ends up with one person who can change
every policy in it and no record that anyone chose that.

Locking cannot be undone from inside the running system. Recovery is the offline
procedure in [`docs/break-glass.md`](break-glass.md).

## Two profiles

```sh
scripts/quickstart.sh                  # default: no broker, HTTP ingest
scripts/quickstart.sh --profile kafka  # the Kafka ingestion overlay
```

The default profile has no message broker at all. Both must produce the same
velocity deny; CI asserts that by running the same script against both.

## Useful flags

| Flag | Effect |
|---|---|
| `--keep` | leave the stack up afterwards and print where the console and the IdP are |
| `--no-fresh` | reuse whatever is already running instead of tearing it down first |
| `--profile kafka` | add the broker overlay |

With `--keep`, the console is at `http://localhost:18782/console/`. Log in as
`ann`; her password is `DEMO_USER_PASSWORD` in `deploy/demo/.env`, which the
script generated on its first run. Tear the stack down with:

```sh
docker compose -f deploy/demo/docker-compose.yml down -v
```

## Credentials

The demo ships none. `scripts/quickstart.sh` generates every password and client
secret it needs into `deploy/demo/.env`, which is not tracked; delete that file
to rotate all of them. `docker compose up` before the script has run fails and
says so. The reasoning, and what that arrangement does and does not protect you
from, is in [`docs/security.md`](security.md).

## How long it takes

The run writes `deploy/demo/.run/quickstart-timings-<profile>.txt` with a
timestamp against each milestone, and the CI job uploads it as an artifact on
every pull request. On a warm machine — images pulled, image layers cached — the
whole thing is well under a minute; a first run is dominated by pulling
Keycloak and building the image.
