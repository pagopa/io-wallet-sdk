---
"@pagopa/io-wallet-oid4vp": patch
---

Make `kid` optional in the V1_3/V1_4 authorization request header schema for `x509_hash` client IDs, which authenticate via `x5c` alone; `kid` remains mandatory for `openid_federation`/legacy client IDs.
