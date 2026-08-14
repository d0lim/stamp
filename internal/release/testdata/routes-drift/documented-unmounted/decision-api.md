---
contract: decision-api
version: 1.0.0
---

# Fixture: the document promises an endpoint nothing mounts

The three rows are the aligned ones; the inbox route is missing from the
rendering beside this file. A consumer written against a contract that lists an
endpoint the binary never mounts gets a 404 and no way to tell it from a role
that is switched off.

## Endpoints

| Method and path | Surface | Auth | Roles |
|---|---|---|---|
| `POST /decisions` | PEP | workload | `decide` |
| `GET /decisions/inbox` | console | user | `decide` |
| `POST /decisions/{id}/challenges/{ordinal}/mfa` | callback | public | `decide` |
