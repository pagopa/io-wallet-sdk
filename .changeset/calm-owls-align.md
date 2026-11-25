---
"@pagopa/io-wallet-oauth2": minor
"@pagopa/io-wallet-oid-federation": minor
---

feat: align IT-Wallet V1_4 to specs 1.4.7

- oauth2:
  - PAR (all versions): request object `exp` defaults to `iat` + 300s (previously 1 hour). `createPushedAuthorizationRequest` throws if `expiresAt` is not after `issuedAt` or exceeds it by more than 300s, and `verifyPushedAuthorizationRequest` rejects `exp - iat` > 300s.
  - PAR V1_4: requires `scope` and at least one `openid_credential` in `authorization_details`, makes `idphinting` optional, and uses `typ: oauth-authz-req+jwt` (verification rejects `jwt`, still accepted for V1_0 and V1_3).
  - Wallet Attestation V1_4: `exp - iat` must be less than 24 hours (previously exactly 24 hours was accepted), on creation and verification.
  - PAR and Wallet Attestation V1_4 creation validate `iat`, `exp` and `nbf` on the whole seconds written to the JWT.
- oid-federation: V1_4 metadata uses `openid_wallet_provider` (legacy `wallet_solution` still accepted), and `federation_entity` requires `homepage_uri` or `organization_uri`.
