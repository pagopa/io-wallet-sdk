---
"@pagopa/io-wallet-oid4vci": patch
---

- Added scope?: never to ExtractGrantDetailsResultV1_4
- Made credentialIssuerMetadata mandatory in BaseValidateCredentialOfferOptions
- Removed inline substitution of oauth_authorization_servers with the one of the external authorizationServer in the issuer EC returned by fetchMetadata.
