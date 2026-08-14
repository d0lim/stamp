---
contract: decision-api
version: 1.0.0
---

# Fixture: the document puts an endpoint on the wrong listener

`POST /decisions` is documented on the console surface behind an end-user token
and is mounted on the PEP surface behind a workload credential. A listener is
not a path prefix here — a caller that believed this row would point a workload
at the console listener and get a 404 from a router that never heard of the
route.

## Endpoints

| Method and path | Surface | Auth | Roles |
|---|---|---|---|
| `POST /decisions` | console | user | `decide` |
| `GET /decisions/inbox` | console | user | `decide` |
| `POST /decisions/{id}/challenges/{ordinal}/mfa` | callback | public | `decide` |
