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
| `GET /healthz` | `200 ok` — liveness is not a database probe | `.../liveness_stays_up_and_readiness_closes` |
| `GET /readyz` | `503 not ready` — the pod takes itself out of its Service; see [the readiness note](#readyz-closes-when-this-process-stops-reaching-the-database) | `.../liveness_stays_up_and_readiness_closes` |

Three things about that table are worth reading twice.

**The two probes disagree, on purpose.** Liveness asks whether the process is
wedged and readiness asks whether a request routed here can be served. A
database that went away makes the second false and leaves the first true, and a
liveness probe that followed the database would restart every pod in a fleet
during an incident that no restart fixes.

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
milliseconds, and `/readyz` back to `200` within 2ms of the first probe after
the database returned. A refusal that outlives its cause would be its own
outage, so the recovery is asserted as hard as the refusal, and that goes double
for readiness: a pod that leaves its Service and never comes back is a larger
outage than the fail-open that behaviour replaced.

Held by `TestTheSurfacesAnswerWhenTheDatabaseIsGone/every_surface_recovers`.

---

## Two fail-open windows: one closed, one described

Both were found by observing the process rather than by reasoning about it, and
both were the same shape — the system's claims about itself had come apart from
what it did. They needed opposite fixes.

For `/readyz` the intent was right and the code was wrong: the comment in
`internal/runtime/readiness.go` said an unreachable database is reported
unready, and the code said that exactly once. **The code was changed.**

For the check surface the code is right and the claim was wrong: the window is a
property of an asynchronous audit, and the asynchrony is a trade R32 made
deliberately for the cost of the check path. **The claim was changed**, and the
size of the window is now pinned by tests so it cannot grow quietly.

### The check surface serves allows for one audit flush interval

The audit buffer is asynchronous on purpose — R32 chose one chain row per batch
over one row per judgment, because a synchronous append would put the chain's
serialization on every check. The consequence is that **the surface finds out
the chain is unreachable when a flush fails**, and until that moment it answers
from the policy set it is holding.

Measured by stopping a real Postgres under a running process, at two flush
intervals:

| `STAMP_AUDIT_FLUSH_INTERVAL` | allows served before the surface refused | over |
|---|---|---|
| 50ms (the test harness's) | 2 – 56 | 6 – 48ms |
| **1s (the shipped default)** | **276 – 364** | **769 – 826ms** |

The second row is five repeats at the interval a deployment actually runs, and
it is what the first row's mechanism predicts: the window is bounded by one
flush interval, and where in the interval the outage begins decides where in
that range a given incident lands.

Here is the promise, stated so it can be checked:

- **`STAMP_AUDIT_FAIL_CLOSED=true` guarantees** that once the buffer has
  *detected* it cannot write to the chain, the check surface refuses, and keeps
  refusing until the loss has been written into the chain as a gap marker.
- **It does not guarantee** that no allow is served outside the chain. Detection
  is a flush that fails, so one flush interval of judgments is answered from the
  policy set the surface holds and then dropped.
- **The dropped ones are counted, not silent.** A `check.gap` marker naming the
  window and the number of lost records is appended once the database returns,
  and the chain still verifies afterwards: a marked hole, not a clean chain that
  quietly skipped a window of traffic.

- Held by `.../the_check_surface_refuses` (the bound: the surface stops allowing
  quickly, and never allows again while the database is down),
  `.../the_audit_loss_is_marked_in_the_chain` (the loss is marked and the chain
  still verifies), and — the size of the window itself —
  `TestFailClosedEngagesOnTheFirstFailedFlush` and
  `TestTheUnauditedWindowIsBoundedByTheFlushInterval` (`internal/api`), which
  fail if detection ever comes to cost more than one flush.
- **Shorten the window** with `STAMP_AUDIT_FLUSH_INTERVAL`. The cost is one
  chain write per interval per instance whether or not there is traffic.
- **Not closed** because closing it means making the audit write synchronous
  with the judgment, which is the trade R32 already made in the other direction.
  The window is a property of an asynchronous audit, not a bug in this one:
  detection cannot precede the first failed write.
- **Not renamed.** `STAMP_AUDIT_FAIL_CLOSED` is not wrong about direction, only
  silent about when — and "when" belongs to the buffer, not to the switch.
  Renaming an environment variable breaks every values file, sealed secret and
  runbook that sets it, and no name short enough to be an environment variable
  could state the size of the window anyway, so this page has to say it either
  way.

### `/readyz` closes when this process stops reaching the database

This one used to be the other fail-open, and it is worth keeping the history on
the page. The schema gate that answers `/readyz` **latched**: the first time it
confirmed the database was at the schema this binary needs, it stopped asking,
so a pod that had been found ready once reported ready for the rest of its life
— including with no database at all. The Helm chart probes readiness every 5
seconds starting 2 seconds after the container starts, so in a deployment the
gate was open within seconds of boot and stayed open. A pod that could not serve
anything stayed in its Service and kept being sent traffic.

It now closes again. What closes it is **failures this process already observed
while serving** — not a health check on a timer. Every statement the process
issues reports whether it reached Postgres at all, which costs nothing because
the statements were happening anyway; three consecutive failures to reach the
server, with none succeeding in between, and the pod reports itself unready.

The details that matter when you are reading a graph at 3am:

- **A server that answers an error is a reachable server.** A statement timeout,
  a constraint violation, a missing column: the gate stays open through all of
  them, and the surfaces report them as failures. Only a statement that never
  got to a server counts — a connection that could not be made, or one reset
  mid-statement.
- **One failure is not enough, and that is deliberate.** A single pooled
  connection can be reset by an idle timeout, a proxy or a failover, and every
  replica shares one database — so a fleet that left its Service on one blip
  would empty the Service in unison rather than shed onto a healthy peer. Three
  consecutive, with any success clearing the count, is a pool that cannot
  produce a working connection rather than one connection that died.
- **A partially degraded database keeps the pod serving.** If some statements
  still get answers, the count keeps clearing and the pod keeps serving the
  requests it can serve.
- **It recovers by itself.** While the gate is closed, the probe reads the
  schema, exactly as it does before the gate has ever opened — which is the only
  thing left that can reach the database once Kubernetes has stopped routing to
  the pod. Measured back at `200` within 2ms of the first probe after the
  database returned. While the gate is open, the probe touches nothing: a
  readiness probe that queried a struggling database would add load to the thing
  that is already failing.
- **`/healthz` is unchanged and stays `200` throughout.** If liveness followed
  the database, the kubelet would restart pods that were going to recover.
- **The schema latch is unchanged.** A schema rolled *backwards* under a running
  pod still leaves it ready: a down migration is a manual act, and a gate that
  reopened on one would pull the fleet out of service during the incident an
  operator is trying to work.

- Held by `.../liveness_stays_up_and_readiness_closes` (503 with no database,
  `/healthz` still 200), `.../every_surface_recovers` (back to 200 when the
  database returns), `TestTheGateClosesOnObservedFailuresAndOpensOnTheNextGoodRead`
  and `TestTheSchemaGateStopsAskingOnceTheSchemaHasArrived` (`internal/runtime`,
  the threshold, the re-read and the fact that a healthy gate still asks
  nothing), and `TestReachabilityDistinguishesAnUnreachableServerFromAnAngryOne`
  (`internal/store`, the classification the whole thing rests on).
- **What it means for you:** `/readyz` is now a usable signal for *this pod
  cannot reach its database*, and it is not a general database health signal —
  it says nothing about a database that is reachable and unhappy. For those,
  alert on the check tier's staleness metric and on the audit buffer's loss
  counter. And expect a total database outage to take every pod out of every
  Service at once, because it will: that is the honest answer, and the traffic
  had nowhere healthy to go regardless.

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
the served surface in front of it refuses on `audit_unavailable` about a second
into the outage — one audit flush interval, as the section above measures —
which is far short of the staleness deadline. A deployment that
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

Each of those tests releases its goroutines through a barrier and then holds
them at a second one until every goroutine has arrived at the charge, so the
overlap is a fact of the test's construction rather than something the scheduler
had to grant. The earlier version only measured whether goroutines coincided and
required that two of them did; CI serialized all 512 on a runner with more than
one P and the build went red on a test whose subject was fine.

Remember what the limit is and is not: **it is per instance**, so N replicas
admit N times the configured rate — **measured, not assumed**: two instances on
one database, one caller, a configured burst of 3, and 6 requests admitted
(`TestTheDecideBudgetIsPerInstanceAndNotFleetWide`, `internal/runtime`). The
absolute bound on what one subject can accumulate is the outstanding-decision
cap, which is counted in the database and does hold across the fleet. Size a
fleet by dividing.

**A refused decide is a `200` carrying a denied decision whose reason is
`rate_limited`, not a `429`.** An authorization engine answers "denied"; it does
not error. Do not alert on 4xx to find rate limiting on this surface.

**The check surface has no budget, and that is R43's scope rather than a gap.**
R43 names decide creation, challenge issuance, external webhook dispatch,
approval submission, and revision-proposal operations — the things that create
state, spend an IdP call, or reach a third party. A stateless evaluation does
none of those. If a deployment needs the check surface bounded against volume,
that is a load-balancer or gateway concern, not one this engine currently claims.

---

## Saturation: what happens at the limits

The bounds below are the ones a deployment actually meets. Until 2026-08-14 all
three were documented and none had been driven to its boundary; these rows are
what was observed when they were.

| Boundary | Value | Observed behaviour | Held by |
|---|---|---|---|
| Rate-limiter table | `DefaultMaxRateEntries` = 8192 | Full table with nothing sweepable **refuses** a new key rather than admitting it unmetered; keys already in the table keep being charged; the table recovers once buckets refill | `TestLimiterRefusesANewKeyAtTheRealTableBound`, `TestLimiterAdmitsAgainOnceTheTableCanBeSwept` (`internal/stream`) |
| Audit buffer | `DefaultAuditCapacity` = 4096 **per flush interval** | Loss begins at exactly capacity + 1, not before; the loss is written to the chain as a gap marker naming the count and window; the first lost record alerts | `TestTheAuditBufferDropsOnlyOnceItIsFull`, `TestSaturationLeavesAMarkedGapRatherThanASilentHole` (`internal/api`) |
| Audit alert latch | `DefaultAuditAlertThreshold` = 1 | Clears only once the loss is marked **and** the queue has drained below half capacity — it stays up while the buffer is still full | `TestTheSaturationAlertClearsOnlyAfterTheLossIsRecorded`, `TestSaturationStillAlertsWhileThePressureHolds` (`internal/api`) |
| `STAMP_AUDIT_FAIL_CLOSED` under saturation | — | Engages on a **full buffer**, not only on an unreachable chain — a traffic spike produces the same refusal an outage does | `TestFailClosedFollowsSaturationNotOnlyChainFailure` (`internal/api`) |

The audit threshold is stated in **events per flush interval**, not as a rate,
because that is the unit the buffer decides in: it drops when the queue reaches
capacity between two flushes. Convert with your own
`STAMP_AUDIT_FLUSH_INTERVAL` — at the 1s default, 4096 events per second.

Two of these were open questions before they were measured. Whether
`STAMP_AUDIT_FAIL_CLOSED` covered saturation as well as chain failure was not
written down anywhere; it does. And the rate-limiter bound had only ever been
exercised at `MaxRateEntries: 2`, which proves the branch exists and says
nothing about 8192.

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
