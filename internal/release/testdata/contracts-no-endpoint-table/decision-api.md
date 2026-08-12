---
contract: decision-api
version: 1.0.0
---

# Fixture: the endpoint table has been deleted

The version is right and the document is present, so every check the gate ran
before this one passes. What is gone is the table the structural comparison
consumes — and the failure mode this fixture pins is that deleting it would
otherwise make internal/release/routes_test.go pass against nothing while the
release gate still reported three correctly versioned contracts.

## 엔드포인트

이 절에 표가 없다.
