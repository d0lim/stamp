# The file authoring path

The path for authoring policy as a directory and submitting it with `stamp policy apply`. It is **a first-class path equal to** form authoring — both feed the same revision pipeline (D10, D22).

**git holds the desired state; the engine holds the effective state.** That git is not the source of truth is this path's premise — merge permission does not become policy-change permission, a revision taking effect enters the same transaction as pending-decision re-evaluation, and the form builder holds no git credentials.

## The directory is the unit

`apply` reads one directory as the desired state of a policy set. It collects `.yaml` and `.yml` files recursively through subdirectories, and ignores everything else.

**A policy's identifier is the `id` inside the document, not the file name.** Moving a file, renaming it, or splitting one file into ten has no effect on the comparison — a rename is no change, not a delete followed by a create.

```
policies/
  schema.yaml                # kind: Schema — the schema the policies are written against
  policies/high-value.yaml   # kind: Policy
  policies/offshore.yaml
```

## Only file-origin policies are compared

Every policy gets an authoring origin (`form` or `file`) at creation (R54, D23). `apply`'s desired-state comparison is scoped **to file-origin policies only**.

- A **file-origin** policy missing from the directory → proposed for deletion
- A **console-origin** policy missing from the directory → nothing happens
- A policy present in the directory and not currently in effect → proposed for creation

Without this scoping, the product doesn't work in its default configuration. A policy made through the console isn't in the file directory, so CI's next apply would compute it as a deletion and propose wiping the console policy on every run.

### Adopting a console-origin policy

Placing a document with the same identifier as a console-origin policy in the directory produces one of three outcomes.

| Document content | Result |
|---|---|
| Identical to the policy in effect | No change — this is why an `export` artifact can be `apply`'d back as-is |
| Differs, no adoption declaration | Rejected as `origin_conflict` |
| Differs, adoption declared | Included in the revision proposal as a take-ownership item |

Adoption is possible only through **an explicit declaration in a file document**. There is no implicit transfer, and it is not a CLI flag — the declaration has to show up in the diff and go through review.

```yaml
# adopt.yaml — an adoption declaration does not live in the same file as the policy document
apiVersion: stamp/v1
kind: Adoption
policies:
  - high-value
```

Once adopted, the policy is owned by the file path, and the console can only view it.

## There is no partial apply

Static validation runs over the whole set. If even one document fails, **the proposal itself is never created** and nothing else applies either — the documents that passed validation could really be one half each of two dependent pairs.

Mitigation classification is also set-wide — if even one document is a mitigation, the whole revision is treated as a mitigation.

## Payload limits

| Limit | Default | Checked | Environment variable |
|---|---|---|---|
| Document count | 1000 | before parsing | `STAMP_APPLY_MAX_DOCUMENTS` |
| Bytes per document | 1 MiB | before parsing | `STAMP_APPLY_MAX_DOCUMENT_BYTES` |
| Total payload bytes | 32 MiB | before parsing | `STAMP_APPLY_MAX_TOTAL_BYTES` |
| Policy count | 1000 | validation | `STAMP_APPLY_MAX_POLICIES` |
| Condition AST node count | 512 | validation | `STAMP_APPLY_MAX_CONDITION_NODES` |
| Condition nesting depth | 32 | validation | `STAMP_APPLY_MAX_CONDITION_DEPTH` |

The first three are decided before parsing. A condition's node count can't be known without reading the condition, so the last three are checked at validation, by which point the payload is already bounded in bytes.

## The serialization gate and its four resolution paths

One pending revision at a time (D24) — so an approver always reviews exactly one diff against the current effective state. The rejection returns the identifier of the proposal in progress along with its collection status.

```
409 revision_pending
{"error":"revision_pending","pending_revision":{"id":"...","origin":"form","threshold":3,"collected":1}}
```

The lock clears through four paths.

| Situation | Resolution path |
|---|---|
| CI applies against the wrong directory | Withdrawal by the proposer — no quorum needed |
| An unapprovable proposal is holding the slot | Withdrawal by governance quorum |
| No approver takes action | Pending-lifetime ceiling (24h default) |
| CI applies on every merge | **A new proposal from the same origin replaces the existing one** |

Replacement is scoped to the file path. A file proposal is a statement about *the whole set*, so the next merge's proposal fully supersedes the previous one — but two console proposals are two different intents from two different people, and letting the later one erase the earlier would wipe out a colleague's in-review revision with no withdrawal record. A console-proposal deadlock is resolved by the other three paths.

On replacement, approvals already collected are invalidated — the approval's binding hash covers the delta digest, so an approval for a different change set cannot carry over.

All four paths are rate-limited (default: 10 per minute per origin). Tune it with `STAMP_REVISION_RATE_WINDOW` and `STAMP_REVISION_RATE_BURST`; the pending-lifetime ceiling is `STAMP_REVISION_TTL`.

## Authoring mode

An operator setting enforced as a server-side API refusal, not a hidden UI element. Set with `STAMP_AUTHORING_MODE`.

| Mode | Console policy authoring | File apply |
|---|---|---|
| `both` (default) | allowed | allowed |
| `file` | refused | allowed |
| `console` | allowed | refused |

**An unrecognized value fails startup.** If a typo silently fell back to `both`, the door the operator meant to close would stay open with no word said about it — the only way this setting can go wrong is "thought it was closed but it's open," so refusing to start is the only safe failure.

**Approving, auditing, dry-run evaluation, and lock actions stay available in every mode.** If the lock screen went dark along with the authoring module, an operator who turned on `file` mode at install time would be stuck as a sole administrator.

## Export

`export` writes the entire effective policy set out in file-authoring format. It's the entry point for a deployment that started on the console to move to file authoring, and **applying the exported result back as-is is judged as no change.**

The artifact holds the approver identity list, quorum thresholds, and internal call targets all at once — meaning one document says exactly which transaction split under which threshold would evade approval. So it requires caller authentication, requires either policy-authoring or audit capability, and logs the caller's identity and the number of policies produced to the audit trail. A refusal is audited too.

The deployment configures the capability source. The default implementation reads a verified token claim, named by `STAMP_CAPABILITY_CLAIM` and defaulting to `stamp_capabilities` if unset. The value is a string list carrying `policy.author` or `audit.read`.

```json
{ "sub": "ann", "stamp_capabilities": ["policy.author"] }
```

**A token with no claim holds no capability.** Configuring a capability source is a different thing from granting anyone a capability, and the gate is fail-closed per caller — point it at a claim name the IdP never issues and you've configured a deployment where every export is refused, and that's the safe direction to fail in. The alternative is any authenticated console user walking away with the full approver list.

## CLI

```bash
export STAMP_API=https://stamp.example.com
export STAMP_TOKEN="$(get-token)"

stamp policy export --dir policies/          # the effective set, as a directory
stamp policy apply  --dir policies/          # prints the proposal identifier and exits immediately
stamp policy apply  --dir policies/ --wait   # blocks until it's decided
stamp policy lock   --threshold 2 --approvers ann,bob,cid
```

By default, `apply` returns the revision proposal's identifier and exits immediately — governance is asynchronous, so it doesn't synchronously return "applied." `--wait` blocks until the outcome is decided and distinguishes the result by exit code.

| Exit code | Meaning |
|---|---|
| 0 | took effect, or no change, or (without `--wait`) proposal created |
| 1 | refused, usage error, or transport failure |
| 3 | revision rejected |
| 4 | withdrawn or replaced while waiting |
| 5 | `--wait` timed out — the revision is still pending |

Before locking, a bootstrap token is required (`--bootstrap-token` or `$STAMP_BOOTSTRAP_TOKEN`).

`stamp policy lock` prints the resolved approver set and quorum, waits for explicit confirmation, and then locks. Locking cannot be undone from inside the running system.
