---
"@pagopa/io-wallet-oid-federation": minor
"@pagopa/io-wallet-oid4vci": minor
---

- `oid-federation` : added APTITUDE schemas for `openid-credential-issuer` and `oauth-authorization-server`.
- `oid4vci` : introduced `fetchMetadataAptitude` method that behaves as `fetchMetadataV1_4` with the only differences being the new parser uses the newly added APTITUDE schemes and that the fallback case, in case `authorization_servers` is missing from the `openid-credential-issuer` metadata, before assuming `oauth_authorization_server` metadata is inlined in the issuer config, tries to retrieve it from the `.well-known/oauth-authorization-server` endpoint of the issuer.
