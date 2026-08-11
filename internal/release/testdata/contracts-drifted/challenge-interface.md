---
contract: challenge-interface
version: 2.0.0
---

# Fixture: the document's version drifted from the code

internal/challenge/contract.go ships ContractVersion = "1.0.0". A document
claiming 2.0.0 is the failure this gate exists for: a stated version that is
believed and wrong.
