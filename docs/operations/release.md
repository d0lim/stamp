# Releasing

What `.github/workflows/release.yml` publishes, for each way it can be started,
and what nobody has checked yet.

**As of this page, that workflow has never executed.** `gh run list
--workflow=release.yml` returns nothing: no tag has ever been pushed and no
manual run has ever been dispatched. Everything below about what the workflow
*decides* is held by a test that reads the real file and runs the real step body
under `bash`; everything below about what the workflow *achieves* — a registry
that accepts the push, a token with the right scope, a keyless signature that
verifies — is unverified, and the last section says so plainly.

Run the tests that hold this page:

```sh
go test ./internal/release/ -run 'TestTheGate|TestOnlyATagPush|TestEveryGatedStep|TestWhich|TestTheChecks|TestARealRelease|TestTheArtifactCheck' -v
```

`-v` matters: two of them print tables that this page copies, and a table that
has drifted from the workflow is worse than no table.

---

## Only a tag publishes

The gate is one `if` in the `gates` job, and it reads the trigger and nothing
else:

| How the run started | `version` | `publish` |
| --- | --- | --- |
| Push of a tag matching `v*.*.*` | the tag without its `v` | `true` |
| Manual dispatch, `unreleased=true` | the `version` input | `false` |
| Manual dispatch, `unreleased=false` | the `version` input | `false` |
| Manual dispatch, a version the repo has never shipped | the `version` input | `false` |

Two consequences worth saying out loud.

**No manual run can publish anything.** The `unreleased` input does not change
that; it only decides where the release notes come from. If you dispatch the
workflow expecting a release, you will get a green run and an empty registry.

**Nothing validates the dispatched `version`.** A rehearsal at `9.9.9` packages
a chart at `9.9.9` and reports success. It cannot publish it, so the cost is a
misleading rehearsal rather than a bad release — but read the version in the
run's log rather than trusting the input you typed.

Held by `TestTheGateAnswersTheSameThingEveryTime` and
`TestOnlyATagPushCanPublish`.

---

## Which steps run, for each input

Eight steps carry an `if:` on the gate's answer. Seven run only on a real
release; one runs only on a rehearsal. There is no third case, because
`publish` has no third value.

| Step | Job | Tag push | Any dispatch |
| --- | --- | --- | --- |
| log in to the registry | `image` | runs | skips |
| install cosign | `image` | runs | skips |
| sign the image by digest | `image` | runs | skips |
| install cosign | `artifacts` | runs | skips |
| sign every file in the manifest | `artifacts` | runs | skips |
| publish the chart | `artifacts` | runs | skips |
| publish the release | `artifacts` | runs | skips |
| rehearsal summary | `artifacts` | skips | runs |

Two branches decide things without an `if:`, so they do not appear in a run log
at all:

- the `:latest` tag is added to the image's tag list **only** when `publish` is
  true, so a rehearsal cannot move it;
- `build the artifacts` picks its arguments in the shell:

  | Input | `scripts/release-artifacts.sh` is called with | Release notes come from |
  | --- | --- | --- |
  | Tag push `v1.2.3` | `--version 1.2.3 --image ghcr.io/…:1.2.3` | `## [1.2.3]` |
  | Dispatch, `unreleased=true` | `--version <input> --unreleased` | `## [Unreleased]` |
  | Dispatch, `unreleased=false` | `--version <input>` | `## [<input>]` |

Held by `TestEveryGatedStepRunsUnderSomeInput` (which fails, by name, on any
gated step that runs under no input at all, or under every input),
`TestTheImageTagsEachInputProduces`,
`TestWhichArtifactArgumentsEachInputProduces` and
`TestARealReleaseNeverShipsUnreleasedNotes`.

---

## Before you push the first tag

`scripts/release-artifacts.sh` exits 1 when the CHANGELOG section it is told to
read is empty, and it runs at the **top** of the `artifacts` job — before every
publishing step in it. So a missing section is not a missing release note. It is
the entire second half of the release never happening.

**At the time of writing, `CHANGELOG.md` has only `## [Unreleased]`.** No
version section exists. That means:

- **a tag push today fails**, at `build the artifacts`, looking for
  `## [<the tag>]`;
- **and it fails after the `image` job has already pushed and signed the
  image**, because `image` does not depend on `artifacts`. The registry would
  hold a signed `1.2.3` and `latest` with no chart, no SBOM and no GitHub
  release next to them;
- a dispatch with `unreleased=false` fails the same way, for the same reason.

So, before tagging `vX.Y.Z`:

1. Add a `## [X.Y.Z]` section to `CHANGELOG.md` with content under it, and land
   it on the branch you are tagging.
2. Rehearse: dispatch the workflow with `version = X.Y.Z` and `unreleased`
   **unchecked**. That makes the run take its notes from `## [X.Y.Z]` — the
   same section the real release will read — instead of from `## [Unreleased]`.
   A green rehearsal in that configuration is the closest thing to a dry run of
   the real notes path that exists.
3. Read the rehearsal summary in the run's step summary. It lists what `dist/`
   holds and what a real tag would sign.
4. Then tag.

Held by `TestWhichInputsCanReachTheEndOfTheArtifactsJob`, which prints the
section each input needs and whether the CHANGELOG can supply it, and fails if
the default rehearsal path has nothing to build from.

---

## The two checks that cannot be skipped

Each publishing job ends with a step that reads what is actually there and fails
if it does not match what `publish` claimed:

- **`the image this run promised exists`** — on a release, the three gated steps
  must have succeeded, the build must have a digest, and the reference must
  resolve in the registry. On a rehearsal, all three must have been *skipped*
  and the locally loaded image must exist.
- **`the artifacts this run promised exist`** — on both paths, `dist/` must hold
  the notes, the packaged chart, the checksums and the signing manifest, and the
  checksums must verify. On a release, every file the manifest names must have a
  `.sig`, `.pem` and `.cosign.bundle` beside it, the manifest must name an
  image, the chart must be pullable from the registry and the GitHub release
  must exist. On a rehearsal, there must be no signature files at all and no
  `image:` line in the manifest.

**Neither step carries an `if:`, and that is deliberate.** A check written as
`if: needs.gates.outputs.publish == 'true'` would skip in exactly the runs where
`publish` was wrong — the only runs it was written for. So they run on every
path, and on a run that publishes nothing they assert that publishing nothing is
what was intended.

If one of these fails, the release is *partial*, not absent. Read the job it
failed in and undo by hand: an image and a `latest` tag may already be in the
registry.

Held by `TestTheChecksAreNotGatedOnWhatTheyCheck` (the check on the checks),
`TestTheChecksPassTheRunsTheyAreMeantToPass`,
`TestTheChecksFailWhenNothingWasPublished` and
`TestTheArtifactCheckReadsTheArtifactsAndNotTheLog`. The last two pull the step
bodies out of the real workflow and run them under `bash` against a fabricated
runner, because the workflow cannot be dispatched from where those tests were
written.

---

## What is still unverified

Everything above is about *decisions*, and decisions are the part that can be
tested without running the workflow. The following have never executed, are
covered by no test, and will be exercised for the first time on the first real
tag. Watch them by eye.

| Not yet known to work | What to look at on the first run |
| --- | --- |
| `GITHUB_TOKEN` can write packages to `ghcr.io` | `log in to the registry`, then the push in `build` |
| The multi-arch build (`linux/amd64,linux/arm64`) succeeds | `build` — a rehearsal only ever builds one architecture |
| Keyless cosign signing works from this workflow's OIDC identity | `sign the image by digest`; `id-token: write` is set, but the Fulcio round trip has never run |
| `helm registry login` and `helm push` accept the same token | `publish the chart` |
| `gh release create` can create a release | `publish the release`; the job has `contents: write` |
| The image SBOM (`syft scan <image>`) works against a remote reference | `build the artifacts` — a rehearsal scans the source tree instead, which is a different code path in the script |
| The signature files verify for a third party | Nothing checks this. `cosign verify` needs the identity and issuer, and no consumer of these artifacts exists yet |

The two verification steps turn most of these from "green and empty" into "red
and specific", which is the improvement this page can honestly claim. They do
not turn any of them into "known to work".

**A `workflow_dispatch` would close a good part of this table without any risk**
— it cannot publish. It was not available to whoever wrote this page. Dispatch
one before you tag.
