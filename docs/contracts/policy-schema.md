---
contract: policy-schema
version: 1.0.0
source: internal/policy
---

# Policy schema contract

The contract that fixes the form and the meaning of a policy document. One of the three public contracts, versioned with semver (R11). The source of truth is the Go types and the YAML codec in `internal/policy`, and this document is that source of truth rendered for a person to read — where the two disagree, the code wins.

`apiVersion`'s major is this contract's major. While the document envelope is `stamp/v1`, this contract is 1.x.

## Version rules

| Change | Level |
|---|---|
| Removing a field, a node kind, a challenge kind or a source kind, or changing what one means; tightening validation so that documents that used to load are refused | major |
| Adding an optional field, adding a new node kind, challenge kind or source kind, adding a new diagnostic code | minor |
| A correction that does not change how an existing document is interpreted | patch |

A document that states `apiVersion: stamp/v1` goes on being read for the whole of 1.x. An `apiVersion` that is not known is refused with the `unknown_api_version` diagnostic rather than guessed at.

## The document envelope

A file is a YAML stream, and one document is either one schema or one policy. Every document has two fields.

```yaml
apiVersion: stamp/v1
kind: Schema   # or Policy
```

A policy's identifier is the `id` inside the document, not the file's name (`docs/file-authoring.md`).

## The schema document

```yaml
apiVersion: stamp/v1
kind: Schema
entities:
  - name: user
    attributes:
      department: string
      clearance: int
actions:
  - transfer
  - name: refund
    description: Cancel a payment
sources:
  - name: daily_transfer_total
    kind: event
    params:
      - {account: string}
    returns: double
    on_error: deny
```

- **`entities`** — a `name` and `attributes` (attribute name → type). Attribute names and entity names match `^[a-z][a-z0-9_]*$`.
- **`actions`** — either a bare name or `{name, description}`. A name matches `^[a-z0-9][a-z0-9._-]*$`.
- **`sources`** — `name`, `kind`, `params`, `returns`, `on_error`. `params` is a list of single-key mappings and **is not sorted, because the order they are declared in is the calling convention.**

**Types**: `bool`, `int`, `double`, `string`, `timestamp`, `duration`, and the list `list<type>`. The ordering comparisons (`lt`, `le`, `gt`, `ge`) cannot be used on `bool` or on a list.

**Source kinds**: `static`, `http`, `event`, `idp_group`. Each kind's transport configuration (URL, credential, TTL) lives in the operator's deployment configuration rather than in a policy document — a policy names it and nothing more (D21).

**`on_error`**: `deny` (the default) or `allow`. `allow` is loaded only on a deployment where the operator has turned on `STAMP_FACT_ALLOW_FAIL_OPEN` (R36).

## The policy document

```yaml
apiVersion: stamp/v1
kind: Policy
id: high-value-transfer
description: A transfer above the threshold
subject: user
resource: account
context: request        # optional
actions: [transfer]
condition:
  all:
    - {left: {field: request.amount}, op: gt, right: 10000}
    - {left: {field: user.department}, in: [finance, treasury]}
challenges:
  - type: quorum
    threshold: 2
    approvers: {claim: manager_of}
```

`subject`, `resource` and `context` are the three roles a condition may refer to, and referring to a role that was not declared is refused with `unbound_role`.

A policy has **no allow or deny field.** A policy either holds or does not hold, and a policy carrying so much as one challenge is a policy the stateless check path cannot answer — that judgment is the single criterion separating `check` from `decide` (D3).

## Conditions

There are three kinds of node and no extension point. This is why a condition can guarantee its termination and its cost (D12).

| Node | YAML | Note |
|---|---|---|
| Logical | `{all: [...]}`, `{any: [...]}`, `{not: <condition>}` | `not` takes a single operand and not a list |
| Comparison | `{left: <operand>, op: <operator>, right: <operand>}` | `op` is one of `eq`, `ne`, `lt`, `le`, `gt`, `ge` |
| Membership | `{left: <operand>, in: <operand>}`, `{left: ..., not_in: ...}` | |

There are three operands.

| Operand | YAML |
|---|---|
| Field reference | `{field: "<role>.<attribute>"}` |
| Source call | `{source: "<name>", args: [...]}` |
| Literal | A bare scalar or sequence, or `{value: ..., type: "<type>"}` |

A type YAML cannot infer (`timestamp`, `duration`, an empty list) is written with its `type` alongside. A `timestamp` serializes as RFC3339Nano UTC and a `duration` in Go's duration notation (`72h`).

## challenge declarations

There are four challenge kinds and the set is closed. What each kind means and how it is handled is fixed by the [challenge interface contract](challenge-interface.md).

| Kind | Fields |
|---|---|
| `quorum` | `threshold`, `approvers` |
| `mfa` | `mode` (`delegated` by default; `direct` is declared only and refused at load), `acr_values` |
| `delay` | `duration`, `cancellable_by` (optional) |
| `external` | `target` — the name of an entry in the operator's allowlist, not a URL |

An approver set is exactly one of three things: `{members: [...]}`, `{claim: "..."}`, `{source: ..., args: [...]}`.

## Normalization and round-tripping

`Set.Normalize` sorts entities, actions, sources and policies by name, attributes by name and challenges by kind, and fills in the defaults. A source's `params` alone keeps its declared order. That export → apply is a no-op is a consequence of this normalization (U19).

## Validation

A refusal comes back as a list of diagnostics carrying JSON Pointers. The codes are these.

`invalid_yaml`, `invalid_document`, `unknown_api_version`, `unknown_kind`, `unknown_key`, `missing_field`, `invalid_name`, `invalid_value`, `unknown_type`, `duplicate`, `unknown_entity`, `unknown_action`, `unknown_attribute`, `unbound_role`, `unknown_source`, `type_mismatch`, `arity_mismatch`, `invalid_operand`, `invalid_operator`, `limit_exceeded`, `unknown_challenge`, `unsupported`, `cel_compile`.

**An unknown key is refused rather than ignored** (`unknown_key`). If a mistyped field disappeared quietly, a policy without the control it was meant to carry would pass.

Default bounds: 1MiB per document, 1000 policies, 512 condition nodes, condition depth 32. An operator can lower them with `STAMP_APPLY_MAX_*`.
