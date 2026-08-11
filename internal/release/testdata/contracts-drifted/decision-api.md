---
contract: decision-api
version: 1.0.0
---

# Fixture: correctly versioned

Present so that the drift fixture fails for one reason and not three.

## 엔드포인트

The gate also refuses a decision API document with no endpoint table, so the
fixture carries one row. Its contents are not compared here — that comparison is
internal/release/routes_test.go's, against the real document.

| 메서드·경로 | 표면 | 인증 | 역할 |
|---|---|---|---|
| `POST /decisions` | PEP | workload | `decide` |
