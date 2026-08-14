# Engineering notes

Four defect classes have shown up repeatedly in this repository. They are written
down because each one is a shape rather than an incident: recognising the shape
is what stops the next instance, and every one of them recurred at least three
times before anyone named it.

If you are contributing, this is the most useful page here. It is not style
guidance — it is a list of ways this specific codebase has been wrong.

---

## 1. "Implemented but unreachable" — seen 7 times

`decide()` had no HTTP endpoint. The checkpoint subsystem had no caller.
Delegated MFA could not be walked end to end. The split topology could not serve
`POST /decisions`. Helm accepted a callback URL with nowhere to come back to.
`CIBA.Poll` had no caller. Four steps in the release workflow were unreachable
under every possible input.

**The pattern:** an unreachable path hides its own defects. A missing PKCE
parameter went unnoticed because the demo never walked the browser round trip
that would have used it — the bug was real the whole time, and the only reason
nobody saw it was that nothing executed the code.

**What to do:** when you add a capability, walk it from the outside. A unit test
proving the function works is not evidence that anything calls it.

---

## 2. "The guard is green while the real thing is red" — seen 7+ times

Four silent-pass guards in `quickstart.sh`. Console tests that stubbed an error
code the server never sends. A hand-written map in `chart_test.go` that was wrong
in exactly the same way the chart was wrong. CI dying quietly with exit 7. A
release workflow finishing green having published nothing.

**The rule this produced: every new check carries a self-check.** Plant the drift
the check exists to catch, confirm the check actually fails, and plant it **in
the real artifact** — the real chart snapshot, the real contract document, the
real console source — never in a fixture built for the test. A check verified
only against a fixture is a check of the fixture.

### 2a. Two ways to get a concurrency guard wrong

The sixth and seventh instances were both concurrency guards, and they are
mirror images of each other. Both measured "were two goroutines inside X at the
same time", and in both the length of X had nothing to do with the claim.

- **Window too wide.** A boot-race guard measured peak concurrency across the
  whole of `Migrate`. The migration lock polls for up to 90 seconds, so boots
  that lose it sit inside `Migrate` *structurally* — the peak was always the full
  count, including on all 143 runs where the unfixed code passed. The assertion
  could never have fired for the reason it was written for.
- **Window too narrow.** A limiter guard measured overlap inside a mutex-guarded
  critical section lasting nanoseconds. On a loaded CI runner the Go scheduler
  ran all 512 charges serially, the peak was 1, and the build went red on a test
  whose subject was fine. Worse, `Allow` takes a mutex — so at most one goroutine
  is ever *inside* the critical section by construction. The assertion was
  conceptually confused.

**The rule:** if you assert "N were inside X simultaneously", X's duration must
be related to what you are proving. And prefer to **construct** the overlap
rather than measure whether the scheduler granted it — a rendezvous that holds
every goroutine at the same point before releasing them removes the luck
entirely, and works at any `GOMAXPROCS`.

### 2b. A mutation going red is not enough — count the runs

One mutation audit recorded "red" next to "1 failure in 130 runs" and concluded
the guard was verified. Those two facts contradict each other: **1 in 130 means a
single CI run catches the doubly-broken code about 1% of the time.** That is not
red, it is almost green, and a refactor deleting the fix would have landed
cleanly.

Record the run count, then read what it means. If a guard can be made
deterministic, make it deterministic — the three guards that replaced that one
each fail on the first run, in under a tenth of a second.

---

## 3. Enumerate the mechanism, not the incident

The same boot race was fixed three times. Each fix recorded the SQLSTATE that
incident had produced, and each was incomplete, because `CREATE TABLE IF NOT
EXISTS` can lose the race in three different places:

| Stage | Catalogue checked | Code raised |
|---|---|---|
| `heap_create_with_catalog()` → `get_relname_relid()` | `pg_class` | `42P07` |
| `TypeCreate()` | `pg_type` (the table's implicit row type) | `42710` |
| Both pre-checks pass, then the physical insert | `pg_type_typname_nsp_index` | `23505` |

Which one fires is pure scheduling luck. **The set is closed** — two pre-checks
and one unique index, with no fourth place to lose — but you only know that once
you write down the mechanisms. A list of incidents is short by exactly the
incidents you have not had yet.

Giving up on enumeration is not the answer either. Widening to the whole
SQLSTATE class looks like the robust move and is not: class 42 contains `42501
insufficient_privilege`, so a predicate named "is this a duplicate object" would
answer *yes* to "you are not allowed to create this" — and a least-privilege
deployment would boot believing a schema it never confirmed.

---

## 4. A hand-written list is wrong in the same way as the thing it guards

`chart_test.go` kept a hand-written role→surface map, and it drifted in lockstep
with the chart it was supposed to catch. That is why `mounted-routes.json` and
`error-codes.json` are now **derived from the code** and compared, rather than
maintained alongside it.

**A measured example:** a hand count of this project's error-code vocabulary came
to 29, arrived at by reading the literals at `writeError` call sites. The real
number is 48. The 19 that were missed are returned as *values* by five helper
functions — `approvalError`, `auditReadError`, `decisionError`, `noSuchDecision`,
`mfaError` — so they appear as a literal at no call site at all. They are exactly
the codes a human reading call sites cannot see, which is why
`console/contract/error-codes.json` is derived from the code and compared rather
than maintained.

This paragraph had the wrong numbers in it until they were checked against the
derived artifact — it said 28 and four. Fitting, for the section it is in.

---

## Where the evidence lives

- `docs/testing/mutation-matrix.md` — the record of planting defects in real
  production code and observing whether the suite noticed. Includes the cases
  where no meaningful mutation could be constructed, and one case where this
  project's own first attempt at a guard was empty.
- `docs/operations/failure-modes.md` — what each surface actually answers when a
  dependency dies or a limit saturates. Every claim cites the test that holds it.
- `docs/requirements.md`, `docs/decisions/stamp-decision-log.md` — the R-ID and
  D-ID canon that code comments cite.
