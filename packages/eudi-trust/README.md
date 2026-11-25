## @pagopa/io-wallet-eudi-trust

Trust evaluation for the EUDI Wallet ecosystem, following the IT-Wallet [Trust Evaluation](https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html) specification:

- validation of the Lists of Trusted Entities (LoTE, ETSI TS 119 602);
- retrieval of the Trust Anchors published in a LoTE;
- X.509 certificate chain validation against those Trust Anchors;
- validation of Wallet-Relying Party Access Certificates (WRPAC);
- validation of Wallet-Relying Party Registration Certificates (WRPRC);
- verification of the authorization of a Wallet-Relying Party.

## Installation

```bash
pnpm add @pagopa/io-wallet-eudi-trust @pagopa/io-wallet-utils
```

## The flow

| Step | What                                                                                                           | API                                                                       |
| ---- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| 1    | Fetch the LoTE and authenticate it against the certificates published in the Official Journal of the EU (OJEU) | `fetchAndValidateLoTE` (or `validateLoTE` for an already downloaded LoTE) |
| 2    | Retrieve the candidate Trust Anchors of the relevant service                                                   | `getTrustAnchors`                                                         |
| 3    | Validate the JWS `x5c` chain against those Trust Anchors                                                       | `validateCertificateChain`                                                |
| 4    | Verify the JWS signature with the public key of the validated signing certificate                              | `verifyJwt` from `@pagopa/io-wallet-utils`                                |

`validateCertificateChainAgainstLoTE` performs steps 2-3 in a single call, given a LoTE validated at step 1. A validated LoTE can be reused until its `NextUpdate`.

`validateWRPAC` and `validateWRPRC` cover the whole flow for WRPAC and WRPRC.

Which LoTE and which service to use depends on the signed object:

| Signed object                                                        | LoTE profile                        | Service type identifier                                                                                    |
| -------------------------------------------------------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| PID                                                                  | `LoTEProfile.EUPIDProvidersList`    | `http://uri.etsi.org/19602/SvcType/PID/Issuance`                                                           |
| Wallet Instance Attestation                                          | `LoTEProfile.EUWalletProvidersList` | `http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance`                                                |
| JWS signed with a WRPAC (Credential Issuer Metadata, Request Object) | `LoTEProfile.EUWRPACProvidersList`  | `http://uri.etsi.org/19602/SvcType/WRPAC/Issuance` (use `validateWRPAC`)                                   |
| WRPRC                                                                | `LoTEProfile.EUWRPRCProvidersList`  | `http://uri.etsi.org/19602/SvcType/WRPRC/Issuance` (use `validateWRPRC`)                                   |
| PuB-EAA                                                              | `LoTEProfile.EUPubEAAProvidersList` | `http://uri.etsi.org/19602/SvcType/PubEAA/Issuance`                                                        |
| EAA                                                                  | `LoTEProfile.EUEAAProvidersList`    | `http://uri.etsi.org/19602/SvcType/EAA/Issuance`                                                           |
| mDL                                                                  | `LoTEProfile.mDLProvidersList`      | `http://trust.ec.europa.eu/lists/mDL/SvcType/Issuance` or `http://uri.etsi.org/19602/SvcType/mDL/Issuance` |

## Callbacks

Like the rest of the SDK, the package performs no cryptography and no network access by itself: they are provided by the consumer through callbacks.

| Callback                     | Purpose                                                                   |
| ---------------------------- | ------------------------------------------------------------------------- |
| `fetch`                      | Download the LoTE                                                         |
| `hash`                       | Check the `x5t#o` header of the LoTE and of the WRPRC                     |
| `verifyJwt`                  | Verify JWS signatures, with a `jwk` or `x5c` signer                       |
| `getX509CertificateMetadata` | Parse a certificate: subject, issuer, validity, extensions and public key |
| `verifyX509CertificateChain` | RFC 5280 path validation of a chain against one Trust Anchor              |

These callbacks are external: the package does not implement them, and the caller must provide them (e.g. with `node:crypto`, `@peculiar/x509` or `pkijs`, or the platform APIs). In the examples below, `callbacks` is an object providing all of them.

Types for `getX509CertificateMetadata` and `verifyX509CertificateChain` are exported as `GetX509CertificateMetadataCallback` and `VerifyX509CertificateChainCallback`. `verifyX509CertificateChain` should also perform the revocation checks, as the package does not.

## WRPAC

`validateWRPAC` checks the content of a Wallet-Relying Party Access Certificate and validates its chain against the Trust Anchors of a Providers of WRPAC LoTE. It returns the parsed WRPAC and the Trust Anchor that validated its chain. It does not verify the signature of the object carrying the WRPAC: do that as in step 4 above.

See the following example for the complete authentication flow: the signed Credential Issuer metadata carries the WRPAC in its `x5c` header. It is authenticated by validating the WRPAC, then verifying the signature with the public key of the WRPAC.

```typescript
import {
  LoTEProfile,
  fetchAndValidateLoTE,
  validateWRPAC,
} from "@pagopa/io-wallet-eudi-trust";
import { decodeJwt, verifyJwt } from "@pagopa/io-wallet-utils";

/** Certificates of the LoTE signer, from the OJEU publication. */
const ojeuCertificates = ["MIIC9TCCApugAwIBAg..."];
/** The signed Credential Issuer metadata, fetched with `Accept: application/jwt`. */
const signedMetadata = "eyJhbGciOiJFUzI1NiIsIn...";

const wrpacProvidersLote = await fetchAndValidateLoTE({
  callbacks,
  ojeuUrl: "https://eur-lex.europa.eu/oj/direct-access.html",
  profile: LoTEProfile.EUWRPACProvidersList,
  trustedCertificates: ojeuCertificates,
  loteUrl: "https://example.com/lists/wrpac-providers.json",
});

const { header, payload } = decodeJwt({ jwt: signedMetadata });

// 1. Validate the WRPAC, which is the first certificate of the x5c header
const { wrpac } = await validateWRPAC({
  callbacks,
  wrpacLote: wrpacProvidersLote,
  wrpacChain: header.x5c,
});

// 2. Verify the signature with the public key of the validated WRPAC
await verifyJwt({
  compact: signedMetadata,
  header,
  payload,
  signer: { alg: header.alg, method: "jwk", publicJwk: wrpac.publicJwk },
  verifyJwtCallback: callbacks.verifyJwt,
});
```

## WRPRC

`validateWRPRC` decodes a Wallet-Relying Party Registration Certificate, verifies its JAdES signature with the first `x5c` certificate, and validates the `x5c` chain against the Trust Anchors of a Providers of WRPRC LoTE. It returns the decoded `header`, the `wrprc` payload and the `trustAnchor`.

```typescript
import {
  LoTEProfile,
  fetchAndValidateLoTE,
  validateWRPRC,
} from "@pagopa/io-wallet-eudi-trust";

/** Certificates of the LoTE signer, from the OJEU publication. */
const ojeuCertificates = ["MIIC9TCCApugAwIBAg..."];
const wrprcJwt = "eyJhbGciOiJFUzI1NiIsIn...";

const wrprcProvidersLote = await fetchAndValidateLoTE({
  callbacks,
  ojeuUrl: "https://eur-lex.europa.eu/oj/direct-access.html",
  profile: LoTEProfile.EUWRPRCProvidersList,
  trustedCertificates: ojeuCertificates,
  loteUrl: "https://example.com/lists/wrprc-providers.json",
});

const { wrprc } = await validateWRPRC({
  callbacks,
  wrprcLote: wrprcProvidersLote,
  wrprcJwt,
});
```

The status of the WRPRC is not checked. Its consistency with the interaction is checked by `verifyWRPAuthorization`.

### Authorization

`verifyWRPAuthorization` checks that a Wallet-Relying Party is authorized for an interaction, given its validated WRPAC and WRPRC:

- the WRPRC `sub` matches the `organizationIdentifier` of the WRPAC subject;
- the WRPRC `entitlements` include at least one of the expected `entitlements`, e.g. `WRP_ENTITLEMENTS.SERVICE_PROVIDER` for a Relying Party, or `WRP_ENTITLEMENTS.PID_PROVIDER` for a PID Provider, in URI or OID form;
- the WRPRC `provides_attestations` register every attestation type in `providedAttestations`, with an exact match on `vct` for SD-JWT VC and on `doctype` for mdoc.

For example, during Credential Issuance, where the registration certificate is the `registration_cert` entry of the `issuer_info` of the metadata:

```typescript
import {
  WRP_ENTITLEMENTS,
  validateWRPAC,
  validateWRPRC,
  verifyWRPAuthorization,
} from "@pagopa/io-wallet-eudi-trust";

const { wrpac } = await validateWRPAC({
  callbacks,
  wrpacChain: header.x5c,
  wrpacLote: wrpacProvidersLote,
});
const { wrprc } = await validateWRPRC({
  callbacks,
  wrprcLote: wrprcProvidersLote,
  wrprcJwt,
});

verifyWRPAuthorization({
  entitlements: [
    WRP_ENTITLEMENTS.QEAA_PROVIDER,
    WRP_ENTITLEMENTS.PUB_EAA_PROVIDER,
    WRP_ENTITLEMENTS.NON_Q_EAA_PROVIDER,
  ],
  providedAttestations: [
    { doctype: "org.iso.18013.5.1.mDL", format: "mso_mdoc" },
  ],
  wrpac,
  wrprc,
});
```

## PID

```typescript
import {
  LoTEProfile,
  fetchAndValidateLoTE,
  validateCertificateChainAgainstLoTE,
} from "@pagopa/io-wallet-eudi-trust";
import { decodeJwt, verifyJwt } from "@pagopa/io-wallet-utils";

/** Certificates of the LoTE signer, from the OJEU publication. */
const ojeuCertificates = ["MIIC9TCCApugAwIBAg..."];
/** The PID, an SD-JWT VC. */
const sdJwtVc = "eyJhbGciOiJFUzI1NiIsIn...";

// 1. Fetch and validate the PID Providers LoTE
const pidLote = await fetchAndValidateLoTE({
  callbacks,
  ojeuUrl: "https://eur-lex.europa.eu/oj/direct-access.html",
  profile: LoTEProfile.EUPIDProvidersList,
  trustedCertificates: ojeuCertificates,
  loteUrl: "https://example.com/lists/pid-providers.json",
});

// Only the issuer-signed JWT of the SD-JWT VC is signed with the Sign/Seal certificate
const [issuerSignedJwt] = sdJwtVc.split("~");
const { header, payload } = decodeJwt({ jwt: issuerSignedJwt });

// 2-3. Validate the chain against the Trust Anchors of the PID issuance
//      service, narrowed by the Authority Key Identifier, the issuer name or the
//      issuer organizationIdentifier of the last certificate of the chain.
await validateCertificateChainAgainstLoTE({
  callbacks,
  chain: header.x5c,
  lote: pidLote,
  profile: LoTEProfile.EUPIDProvidersList,
  serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PID/Issuance",
});

// 4. Verify the signature with the public key of the validated signing certificate
const { publicJwk } = await callbacks.getX509CertificateMetadata(header.x5c[0]);

await verifyJwt({
  compact: issuerSignedJwt,
  header,
  payload,
  signer: { alg: header.alg, method: "jwk", publicJwk },
  verifyJwtCallback: callbacks.verifyJwt,
});
```

The same flow applies to a Wallet Instance Attestation (`LoTEProfile.EUWalletProvidersList`, `.../SvcType/WalletSolution/Issuance`) and a PuB-EAA (`LoTEProfile.EUPubEAAProvidersList`, `.../SvcType/PubEAA/Issuance`).

To split steps 2 and 3, retrieve the candidates with `getTrustAnchors` and pass them to `validateCertificateChain`.

## Errors

- `LoTEError`: the LoTE is expired, not signed by an OJEU certificate, signed with a certificate not matching the scheme operator or not valid, or of an unexpected type.
- `JAdESError`: the `x5t#o` header does not match the signer certificate, or the signature (LoTE, WRPRC) or its time-based claims are invalid.
- `CertificateChainError`: no candidate Trust Anchor, or no Trust Anchor validating the chain.
- `JwtVerificationError` (from `@pagopa/io-wallet-utils`): invalid signature, or expired JWS, when verifying with `verifyJwt`.
- `AuthorizationError`: the WRPRC does not belong to the WRPAC subject (`BINDING_FAILED`), does not include the expected entitlements (`WRONG_ENTITLEMENT`) or does not register a provided attestation type (`ATTESTATION_TYPE_NOT_REGISTERED`).
- `ValidationError` (from `@pagopa/io-wallet-utils`): malformed LoTE, WRPRC or WRPAC.

## Not supported yet

- LoTE pivots: the LoTE signer must be one of the OJEU certificates.
- Revocation checking, unless performed by `verifyX509CertificateChain`.
- Trusted Lists (QEAA, qualified status of PuB-EAA providers).
- Historical keys (`ServiceHistory`).
- mdoc (COSE `x5chain`) signatures.
