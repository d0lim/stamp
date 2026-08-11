# Break-glass

Governance locking cannot be undone from inside the running system. This is the
way out, and it is deliberately outside it.

## When this is the answer

Exactly one situation: **the approver set can no longer reach the quorum the
lock installed.** People left, an IdP group emptied, a claim name changed, a
threshold was set higher than the set that remains. Nobody can approve a
revision, including the revision that would fix the approver set — the deadlock
governance is supposed to have, because a lock that a single administrator could
lift is not a lock.

Everything else has a cheaper answer. A CI job that applied the wrong directory
is a proposer withdrawal, which needs no quorum. A proposal nobody will approve
that is holding the serialization gate is withdrawn by the governance quorum,
or expires at the pending lifetime, or — on the file path — is replaced by the
next apply from the same origin. Read
[`docs/file-authoring.md`](file-authoring.md) before reaching for this page.

## What it does

```sh
stamp breakglass \
  --dsn "$STAMP_DSN" \
  --addr ":8080,:8081,:8082" \
  --actor "you@example.com" \
  --reason "quorum unreachable: two of three approvers offboarded, INC-4417" \
  --confirm
```

It connects to the database directly — not through the service, because the
service is what has to be stopped — resets the reserved governance policy to
solo-admin mode, writes a highest-severity record into the audit chain **in the
same transaction as the reset**, and prints a fresh bootstrap token once.

Afterwards the installation is exactly where a new one is: one token, no quorum,
and a critical audit warning on a timer until governance is locked again. Lock
it again as soon as the incident is over.

## It refuses to run while the service is up, in two ways

Both matter, and neither is a formality.

- **The listeners.** Every address given to `--addr` is probed, and the run is
  refused if any of them is already bound. Give it every address the deployment
  binds — a tier you forgot is a tier still serving decisions against the
  governance state this command is about to rewrite.
- **The audit writer claims.** A live process holds its writer claim in the
  database, so a `stamp` running on another host — one whose ports this command
  cannot probe — still stops it. `--addr` is a convenience; the claim is the
  control.

The reset is chained into its own audit segment (`breakglass`) rather than into
whatever the service was writing, so it cannot collide with a live instance's
writer and so the reset reads as its own sequence in the log.

## It is deliberately awkward

`--actor` and `--reason` are required and both land in the audit chain verbatim.
`--confirm` is required. None of that is a security control — the liveness check
and the audit record are. It is there so that nobody runs this by reflex, and so
that the log says who and why rather than only what.

Write the reason for the person who will read it during the next audit, not for
the shell you are typing it into. `"quorum unreachable after offboarding, INC-4417"`
is a reason. `"fix"` is not.

## Runbook

1. **Stop every `stamp` process against that database.** Scale the deployment to
   zero; do not leave a single replica of any tier. The command will refuse
   while one is up, which is the check working, not an obstacle to route around.
2. **Take a database backup.** This rewrites governance state.
3. **Run the command** with every listen address the deployment used, a real
   actor, and a real reason.
4. **Capture the token.** It is printed once and stored only as a digest. If it
   is lost, the only way to get another one is to run this again.
5. **Bring the service back up.**
6. **Fix the approver set and lock governance again**, in that order, using the
   token:
   ```sh
   STAMP_BOOTSTRAP_TOKEN="…" stamp policy lock \
     --threshold 2 --approvers ann,bob,cid
   ```
   The command prints the resolved set and the threshold and asks for an
   explicit confirmation before it sends anything, because what is being
   installed matters more than what was typed.
7. **Verify the chain** and keep the output with the incident record:
   ```sh
   stamp audit verify --dsn "$STAMP_DSN"
   ```
   Exit 0 means at least one checkpoint was verified and everything agrees; 6
   means the log and what was signed disagree; 7 means no verdict was reached,
   which includes "there was nothing to verify". Alert on 6 and 7 both.
8. **Confirm the record landed.** The reset is a critical-severity row in the
   `breakglass` segment carrying your name and your reason. If it is not there,
   the reset did not happen the way this document says it does, and that is the
   incident now.

## What it does not do

It does not touch policies, decisions, approvals already collected, or the audit
log's history. It resets governance mode and issues a token. A pending revision
that was blocking the gate is still pending afterwards — withdraw it with the
fresh token's authority if it is the thing in the way.
