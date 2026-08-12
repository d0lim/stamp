# Failure modes

What this deployment does when the things it depends on stop working.

Every claim on this page is held by a named test. That is the only reason to
trust a page like this one: a document that asserts behaviour with nothing
enforcing it becomes fiction the first time the behaviour moves, and the reader
has no way to tell which sentence went stale. Each row cites the test that
fails if the sentence stops being true. If you change one of these paths and a
cited test fails, this page is part of the change.

Run them:

```sh
go test -race ./internal/runtime/ -run TestTheSurfacesAnswerWhenTheDatabaseIsGone
go test -race -count=10 ./internal/api/ ./internal/stream/
```

The first needs a Docker daemon. It starts a real PostgreSQL, stands the process
up against it, and then **stops the container** — the failures below are a
database that is genuinely not running, not an injected error.

---

## The database is gone

This is the whole of the section, because every other dependency this system has
is either optional or already fails closed by construction (see
[Not covered here](#not-covered-here)).

| Surface | What the caller gets | Held by |
|---|---|---|
| `POST /access/v1/evaluation` (check) | `200` with `{"decision": false}` and reason `audit_unavailable` — a deny, not an error | `TestTheSurfacesAnswerWhenTheDatabaseIsGone/the_check_surface_refuses` |
| `POST /decisions` (decide) | `500 internal_error`, and **no decision row is created** | `.../the_decide_surface_refuses_and_creates_nothing`, `.../nothing_was_created_while_the_database_was_gone` |
| `POST /decisions/{id}/challenges/{n}/approvals` | `500 internal_error` — the evidence is refused, never accepted and lost | `.../a_challenge_takes_no_evidence` |
| `GET /decisions/{id}` | `500 internal_error` | `.../the_reads_refuse_rather_than_answer_from_nothing` |
| `GET /audit/decisions` | `500 internal_error` — never an empty history | `.../the_reads_refuse_rather_than_answer_from_nothing` |
| `GET /healthz` | `200 ok` | `.../liveness_stays_up_and_readiness_does_not_reopen` |
| `GET /readyz` | `200 ready` — see [the readiness note](#readyz-does-not-close-once-it-has-opened) | `.../liveness_stays_up_and_readiness_does_not_reopen` |

Two things about that table are worth reading twice.

**The check surface answers a deny, not a 500.** A policy enforcement point has
to do something with what it gets back, and a 500 with no verdict is not
something it can act on. So the refusal arrives as a decision object whose
reason is `audit_unavailable`, which a PEP can tell apart from a policy deny.

**The read surfaces answer 500 rather than an empty result.** An empty decision
history reads as "this deployment made no decisions", which is a statement an
auditor would act on. An error is the honest answer.

### Everything comes back on its own

No restart, no reconfiguration, no operator action. The same pool, the same
buffer, the same process: when the database returns, every surface in the table
above starts answering normally again — measured in the low hundreds of
milliseconds. A refusal that outlives its cause would be its own outage, so the
recovery is asserted as hard as the refusal.

Held by `TestTheSurfacesAnswerWhenTheDatabaseIsGone/every_surface_recovers`.

---

## Two fail-open windows, both bounded, neither fixed

These were found by observing the process rather than by reasoning about it.
Both are pinned by tests. Neither was changed, and the reasons are below.

### The check surface serves allows for one audit flush interval

The audit buffer is asynchronous on purpose — R32 chose one chain row per batch
over one row per judgment, because a synchronous append would put the chain's
serialization on every check. The consequence is that **the surface finds out
the chain is unreachable when a flush fails**, and until that moment it answers
from the policy set it is holding.

Measured, with a 50ms flush interval: between 2 and 56 allows over 6ms to 48ms.
The bound is the flush interval, so with the shipped default of one second it is
**about a second of allows**.

Those allows are not in the audit chain. They are not silent either: each is
counted as a loss, and once the database returns a `check.gap` marker naming the
window and the number of lost records is appended, and the chain still verifies.
An operator reading "fail closed" as *no allow is served that is not in the
chain* is reading a stronger promise than this process makes.

- Held by `.../the_check_surface_refuses` (the bound: the surface stops allowing
  quickly, and never allows again while the database is down) and
  `.../the_audit_loss_is_marked_in_the_chain` (the loss is marked and the chain
  still verifies).
- **Shorten the window** with `STAMP_AUDIT_FLUSH_INTERVAL`. The cost is one
  chain write per interval per instance whether or not there is traffic.
- **Not fixed** because closing it means making the audit write synchronous with
  the judgment, which is the trade R32 already made in the other direction. The
  window is a property of an asynchronous audit, not a bug in this one:
  detection cannot precede the first failed write.

### `/readyz` does not close once it has opened

The schema gate that answers `/readyz` **latches**. The first time it confirms
the database is at the schema this binary needs, it stops asking, and every
later probe is answered without touching the database. So a process that has
been found ready once reports ready for the rest of its life — including with no
database at all.

The Helm chart probes readiness every 5 seconds starting 2 seconds after the
container starts, so in a real deployment the gate is open within seconds of
boot and stays open.

This contradicts the closing paragraph of `internal/runtime/readiness.go`, which
reads *"A database that cannot be reached is reported unready rather than
ready."* That sentence is true exactly once — before the gate has opened. A
process that has never been probed successfully **does** answer `503` with
`database schema version is unreadable`.

- Held by `.../liveness_stays_up_and_readiness_does_not_reopen`. The test's
  baseline reads `/readyz` while the database is up, exactly as a kubelet would,
  which is what makes the assertion the one a deployment actually gets.
- **Not fixed.** The latch is deliberate and reasoned where it is implemented: a
  schema rolled backwards under a running pod must not pull the whole fleet out
  of service during the incident an operator is trying to work. And the
  operational cost of the divergence is small in the case that matters, because
  every replica loses the same database at the same instant — unreadiness would
  empty the Service rather than shed load onto a healthy peer.
- **What it means for you:** do not use `/readyz` as a database health signal.
  It answers "may a request routed here be served, as far as the schema gate
  ever determined", and that is all. Alert on the check tier's staleness metric
  and on the audit buffer's loss counter instead.

---

## The check tier's staged failure

Separate from the surfaces above, the in-process check tier has its own
behaviour when it cannot reach the database, and it is deliberate rather than
accidental.

| Time since the database went away | `CheckService.Evaluate` answers |
|---|---|
| Under `STAMP_POLICY_STALENESS_DEADLINE` (default 60s) | the held policy set's verdict, including allows |
| Over it | deny, with reason `policy_set_stale` |

The staging is the point. An ordinary failover — seconds of unavailability on a
five second poll — must not drop the whole check tier into deny at once, which
would be a far larger outage than the one it is reacting to. Past the deadline
the instance no longer knows what the effective policy set is, and any answer it
gave would be a guess.

What makes this safe in a shipped deployment is that it is not the only gate:
the served surface in front of it refuses on `audit_unavailable` long before the
staleness deadline expires, as the table at the top shows. A deployment that
sets `STAMP_AUDIT_FAIL_CLOSED=false` gives that up and keeps only the staleness
deadline — which is the operator's stated choice between a gap in the audit and
an outage, and it is worth knowing that the choice also buys up to a minute of
allows from a stale policy set.

Held by `TestTheSurfacesAnswerWhenTheDatabaseIsGone/the_in-process_check_tier_holds_its_snapshot_until_the_deadline`,
which pins both halves.

---

## Rate limits under concurrent load

R43's rate limits are enforced in-process by two token-bucket tables — one per
caller, one per subject — and every request charges both. The property an
operator needs is that the budget is *exact*: with a burst of B and any number
of requests in flight, exactly B are admitted. A budget that leaks under
contention makes the limit something the surface reports rather than something
it does.

| Claim | Held by |
|---|---|
| One key, many simultaneous charges: exactly the burst is admitted | `TestLimiterAdmitsExactlyTheBurstUnderConcurrentCharges` (`internal/stream`) |
| Both tables charged at once: each budget is exact, and pressure on one does not spend the other | `TestTwoLimiterTablesStayExactWhenBothAreChargedAtOnce` (`internal/stream`) |
| Goroutines charging one bucket with different — and out-of-order — instants cannot beat the budget | `TestAllowAtStaysExactWhenGoroutinesSupplyDifferentInstants`, `TestAllowAtNeverPaysMoreThanTheWindowEarned` (`internal/stream`) |
| 128 simultaneous decides admit exactly the burst, and every refusal has one audit record naming the budget that bound | `TestDecideBudgetsAreExactUnderConcurrentLoad` (`internal/api`) |
| A refused ingest event is not applied to the aggregate a policy later reads | `TestIngestRateLimitHoldsWhenSubmitsArriveTogether` (`internal/stream`) |

Each of those tests releases its goroutines through a barrier and then asserts
how many were inside the limiter at the same time, so that a run which happened
to serialize fails instead of passing quietly.

Remember what the limit is and is not: **it is per instance**, so N replicas
admit N times the configured rate. The absolute bound on what one subject can
accumulate is the outstanding-decision cap, which is counted in the database and
does hold across the fleet. Size a fleet by dividing.

---

## Not covered here

- **The identity provider.** Step-up is fail-closed by construction — the
  handler verifies the `acr` the IdP asserts and refuses without it — and an IdP
  that does not answer produces no token, so no step-up completes. It has not
  been exercised by stopping a real IdP.
- **Kafka.** The brokered ingest path's behaviour under broker loss is not
  asserted anywhere.
- **Partial network partitions**, where some replicas reach the database and
  others do not.
- **Recovering a damaged audit chain.** A marked gap is covered above; a chain
  whose rows are corrupt or missing is not.
