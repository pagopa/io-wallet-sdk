---
"@pagopa/io-wallet-oauth2": minor
"@pagopa/io-wallet-oid-federation": minor
---

feat: align IT-Wallet V1_4 to specs 1.4.7

- oauth2: the PAR request object lifetime is capped at 300 seconds. `createPushedAuthorizationRequest` now defaults `exp` to 5 minutes after `iat` (previously 1 hour) and throws when `expiresAt` is more than 300 seconds after `issuedAt`; `verifyPushedAuthorizationRequest` rejects request objects whose `exp - iat` exceeds 300 seconds. PAR for V1_4 requires `scope` and at least one `openid_credential` in `authorization_details`, signs the request object with `typ: oauth-authz-req+jwt` and makes `idphinting` optional; `verifyPushedAuthorizationRequest` rejects request objects whose `typ` is not `oauth-authz-req+jwt` (V1_0 and V1_3 still accept `jwt`); Wallet Attestation `exp - iat` must be strictly lower than 24 hours.
- oid-federation: V1_4 metadata uses `openid_wallet_provider`, while still accepting the legacy `wallet_solution` key for backward compatibility, and `federation_entity` requires `homepage_uri` or `organization_uri`.
