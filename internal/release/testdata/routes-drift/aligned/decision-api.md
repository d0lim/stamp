---
contract: decision-api
version: 1.0.0
---

# Fixture: the document and the routes agree

Three endpoints and nothing else. A fixture that mirrored the real document
would go stale every time a route was added, and what these fixtures exercise is
the set difference, not the size of the set.

This one is the control: it shares the parsers and the comparison with its three
siblings, so a fixture set that failed for a structural reason shows up as this
test failing rather than as three drift assertions quietly passing.

## Endpoints

| Method and path | Surface | Auth | Roles |
|---|---|---|---|
| `POST /decisions` | PEP | workload | `decide` |
| `GET /decisions/inbox` | console | user | `decide` |
| `POST /decisions/{id}/challenges/{ordinal}/mfa` | callback | public | `decide` |
