# Security policy

STAMP is an authorization engine. A vulnerability here is not a bug in a
feature — it is a way to get a decision you were not entitled to, or to make one
disappear from the audit chain. Please treat it accordingly.

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**). That opens a private thread visible only
to the maintainers.

Useful things to include, in rough order of value:

- What an attacker gets — a decision they should not have, a bypassed challenge,
  a forged or erased audit record, a denial of service against boots or
  judgments.
- The smallest reproduction you have. A failing test against this repository is
  ideal; a request sequence is fine.
- The deployment shape it needs: which surfaces are exposed (`pep`, `console`,
  `callback`), which roles are in use, whether the demo bundle's settings are
  involved.

Expect an acknowledgement within a few days. This is a small project — if you do
not hear back, please ping the thread rather than assuming it was ignored.

## Scope

**In scope**

- Authorization bypass on either evaluation path (`check()` or `decide()`).
- Anything that lets a caller obtain, skip, or forge a challenge — quorum, MFA,
  delay, external.
- Audit integrity: forging a chain entry, erasing one, or producing a gap that
  verification does not report.
- Privilege escalation across the database roles, or across the three listener
  surfaces.
- Governance bypass: applying a policy revision without the approvals its own
  classification requires.
- Secret disclosure, SSRF through fact sources, and the egress allowlist.

**Out of scope**

- The demo bundle's deliberately weak settings. `docs/security.md` enumerates
  exactly which of them would be defects anywhere else — they exist so the
  quickstart runs without a credential ceremony, and they are documented as
  unsafe. A report that the demo uses a known password is not a finding.
- Missing rate limits on the stateless `check()` surface. R43 scopes rate
  limiting to the operations that create state, spend an IdP call, or reach a
  third party; bounding `check()` by volume is a gateway concern. See
  `docs/operations/failure-modes.md`.
- Denial of service that requires already-authenticated access and produces no
  effect beyond load, unless it defeats a documented bound.
- Findings against a configuration the documentation explicitly warns against.

If you are unsure whether something is in scope, report it — a wrong guess in
that direction costs very little.

## Supported versions

Pre-v1. Only the latest release and `main` receive fixes. Once v1 ships this
section will state a real support window.

## Disclosure

Please give us a reasonable window to ship a fix before publishing. We will
credit you in the release notes unless you would rather we did not.
