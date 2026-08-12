---
contract: decision-api
version: 1.0.0
---

# Fixture: a callback endpoint is served and the document does not say so

The mfa callback row has been deleted. This is the shape #44 describes: a route
lands, the version gate reads the same three constants it always read, and the
public contract denies an endpoint that is reachable from outside the perimeter.

## 엔드포인트

| 메서드·경로 | 표면 | 인증 | 역할 |
|---|---|---|---|
| `POST /decisions` | PEP | workload | `decide` |
| `GET /decisions/inbox` | console | user | `decide` |
