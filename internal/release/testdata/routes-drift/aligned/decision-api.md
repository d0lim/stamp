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

## 엔드포인트

| 메서드·경로 | 표면 | 인증 | 역할 |
|---|---|---|---|
| `POST /decisions` | PEP | workload | `decide` |
| `GET /decisions/inbox` | console | user | `decide` |
| `POST /decisions/{id}/challenges/{ordinal}/mfa` | callback | public | `decide` |
