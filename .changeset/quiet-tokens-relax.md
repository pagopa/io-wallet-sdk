---
"@pagopa/io-wallet-oauth2": patch
---

Align the access token schemas to RFC 6749: the authorization code token request accepts the optional `client_id` required by public clients (Section 4.1.3), and the `token_type` of the token response is case insensitive (Section 5.1), normalized to `Bearer` or `DPoP`.
