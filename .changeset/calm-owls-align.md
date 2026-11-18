---
"@pagopa/io-wallet-oauth2": minor
"@pagopa/io-wallet-oid-federation": minor
---

feat: align IT-Wallet V1_4 to specs 1.4.7

- oauth2: PAR for V1_4 requires `scope` and at least one `openid_credential` in `authorization_details`, signs the request object with `typ: oauth-authz-req+jwt` and makes `idphinting` optional; Wallet Attestation `exp - iat` must be strictly lower than 24 hours.
- oid-federation: V1_4 metadata uses `openid_wallet_provider` instead of `wallet_solution`, and `federation_entity` requires `homepage_uri` or `organization_uri`.
