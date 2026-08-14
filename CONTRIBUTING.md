# Contributing to STAMP

Thanks for looking. STAMP is an authorization engine, so the bar here is a
little unusual: most of the work is not making a feature exist, it is making the
failure modes observable and keeping them that way.

Start with **[`docs/engineering-notes.md`](docs/engineering-notes.md)**. It lists
the four defect classes that have recurred in this repository and the rules they
produced. It is the most useful page for a new contributor, and it will explain
why some of the conventions below look strict.

## Getting set up

You need Go (the version in `go.mod`), Docker (the test suite runs a real
PostgreSQL via testcontainers — nothing is mocked), and Node if you touch the
console.

```
make help          # every target, with descriptions
make test          # the suite, with the race detector
make land          # every gate a PR must pass
```

`make land` runs `fmt-check vet lint test vulncheck chart-check contracts`. If it
passes locally it should pass in CI; if it does not, that difference is itself a
bug worth reporting.

Run `make hooks` once to point git at the tracked hooks directory.

## Conventions

**Commit messages are English, in [Conventional
Commits](https://www.conventionalcommits.org/) form** — `fix(store): …`,
`test(api): …`, `docs: …`.

Write the body for someone who will read it in a year while trying to understand
why the code looks like this. In this repository commit bodies routinely carry
the reasoning behind a change, and that is deliberate: several of them are the
only surviving record of an alternative that was tried and rejected. A one-line
"fix bug" is not enough for anything that changes behaviour.

**Comments are load-bearing here.** The codebase has long explanatory comments,
and they are not clutter to be trimmed — many exist specifically to stop a future
reader from making a plausible-looking change that would reintroduce a defect. If
you find a comment that no longer matches the code, that is a bug: fix the
comment in the same commit.

**Requirements and decisions have stable IDs.** Code comments cite `R43`, `D25`,
and friends; those resolve to [`docs/requirements.md`](docs/requirements.md) and
[`docs/decisions/stamp-decision-log.md`](docs/decisions/stamp-decision-log.md).
The numbering is stable — IDs are never reused or renumbered, and gaps are fine.
If you change behaviour that a requirement pins, say so in the PR.

## Tests

New behaviour needs a test, but the standard is narrower than that:

**Every new check should carry a self-check.** Before you trust a guard, plant
the defect it exists to catch and confirm it actually goes red — and plant it in
the *real* artifact, not in a fixture built for the test. This repository has
been bitten repeatedly by checks that were green while the thing they guarded was
broken; [`docs/testing/mutation-matrix.md`](docs/testing/mutation-matrix.md) is
the running record of that discipline, including the cases where the guard turned
out to be empty.

**For anything probabilistic, report the run count.** "The mutation went red" is
not a result; "1 failure in 130 runs" is, and it means something quite different.
Prefer a deterministic guard where one is constructible.

**Concurrency tests should construct the overlap, not hope for it.** Releasing
goroutines from a channel does not make them run simultaneously. See
`storm()` in `internal/stream/ratelimit_test.go` for the rendezvous pattern this
repository uses.

## Pull requests

- One coherent change per PR. If your branch has an urgent fix and an open-ended
  investigation in it, split them — the fix should not wait.
- Explain the *why* in the description, not just the *what*.
- CI must be green. A flaky test is a defect in the test, not noise to re-run
  past — if you hit one, say so in the PR even if a re-run passes.

## Security

Do not open a public issue for a vulnerability. See
[`SECURITY.md`](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the MIT
License, the same as the rest of the project.
