---
"@pagopa/io-wallet-oid4vci": minor
"@pagopa/io-wallet-oauth2": minor
---

Refined credential offer related functionalities by:

- adding the issuerState optional field in create-authorization-request in the oauth2 package.
- adding checks of the offer's authorization_server field.
- adding support for ITW v1.4 offer,
- adding the authorization_server field to fetch the metadata from the issuer-suggested server in case of a credential offer flow.
- improving the `fetchMetadata` federation path by making it fetch another OID-FED EC in case the `openid-credential-issuer.authorization_servers` is present and doesn't specify the issuer itself.
