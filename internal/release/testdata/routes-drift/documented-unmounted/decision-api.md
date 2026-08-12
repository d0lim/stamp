---
contract: decision-api
version: 1.0.0
---

# Fixture: the document promises an endpoint nothing mounts

The three rows are the aligned ones; the inbox route is missing from the
rendering beside this file. A consumer written against a contract that lists an
endpoint the binary never mounts gets a 404 and no way to tell it from a role
that is switched off.

## 엔드포인트

| 메서드·경로 | 표면 | 인증 | 역할 |
|---|---|---|---|
| `POST /decisions` | PEP | workload | `decide` |
| `GET /decisions/inbox` | console | user | `decide` |
| `POST /decisions/{id}/challenges/{ordinal}/mfa` | callback | public | `decide` |
