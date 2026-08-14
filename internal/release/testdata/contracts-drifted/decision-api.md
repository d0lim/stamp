---
contract: decision-api
version: 1.0.0
---

# Fixture: correctly versioned

Present so that the drift fixture fails for one reason and not three.

## Endpoints

The gate also refuses a decision API document with no endpoint table, so the
fixture carries one row. Its contents are not compared here — that comparison is
internal/release/routes_test.go's, against the real document.

| Method and path | Surface | Auth | Roles |
|---|---|---|---|
| `POST /decisions` | PEP | workload | `decide` |
