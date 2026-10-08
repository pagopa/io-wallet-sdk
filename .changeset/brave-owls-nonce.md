---
"@pagopa/io-wallet-oauth2": minor
"@pagopa/io-wallet-utils": minor
---

Support generic OAuth 2.0 clients in the token and pushed authorization requests:

- `createTokenDPoP` accepts an optional `nonce` for the DPoP JWT (RFC 9449, Section 8).
- `fetchTokenResponse` accepts a DPoP proof factory and retries once with the nonce required by the server (`use_dpop_nonce`).
- `fetchTokenResponse` and `fetchPushedAuthorizationResponse` make `walletAttestation` and `clientAttestationDPoP` optional, to support public clients. The Client Attestation PoP can also be a factory, to use a fresh one on retry.
- New helpers `fetchWithDpopNonceRetry`, `getRequiredDpopNonce` and `getClientAttestationHeaders`, the `zDpopNonceErrorResponse` schema, and new `DPOP_NONCE` and `WWW_AUTHENTICATE` header constants.
