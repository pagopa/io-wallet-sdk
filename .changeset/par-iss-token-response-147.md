---
"@pagopa/io-wallet-oauth2": minor
---

fix: PAR Request Object `iss` is always the `client_id` (all versions, as required by the specs); Token Response for `V1_4` (specs 1.4.7) and `V1_5` requires `token_type: DPoP` and `authorization_details` with `credential_identifiers`, in both `fetchTokenResponse` and `createAccessTokenResponse` (new optional `config`)
