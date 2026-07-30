---
"@pagopa/io-wallet-oid4vp": patch
---

Backport the IT-Wallet 1.4.4 LTS conditional `x5c` Request Object rule to OID4VP SDK profiles V1_3 and V1_4, allowing federation signers when `client_id` uses `openid_federation` while preserving x5c requirements for `x509_hash`.
