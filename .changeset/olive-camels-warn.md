---
"@pagopa/io-wallet-oauth2": minor
---

fix(oauth2): align client attestation PoP JWT payload with IT-Wallet specs

Adds a local IT-Wallet client attestation PoP JWT schema, keeps `exp` optional for v1.3 and v1.4 PoP JWTs, and restricts accepted PoP signing algorithms to ES256, ES384, and ES512.
