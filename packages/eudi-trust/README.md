## @pagopa/io-wallet-eudi-trust

Trust evaluation for the EUDI Wallet ecosystem, following the IT-Wallet [Trust Evaluation](https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html) specification:

- validation of the Lists of Trusted Entities (LoTE, ETSI TS 119 602);
- retrieval of the Trust Anchors published in a LoTE;
- X.509 certificate chain validation against those Trust Anchors;
- trust evaluation of a JWS (PID, Wallet Instance Attestation, Credential Issuer
  Metadata, WRPRC, ...): validation of its signature with the public key of its
  signing certificate, and of that certificate chain against a Trust Anchor.

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

`evaluateJwsTrust` performs steps 2-4 in a single call, given a LoTE validated at step 1. A validated LoTE can be reused until its `NextUpdate`.

Which LoTE and which service to use depends on the signed object:

| Signed object                                                        | LoTE profile                        | Service type identifier                                                  |
| -------------------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------ |
| PID                                                                  | `LoTEProfile.EUPIDProvidersList`    | `http://uri.etsi.org/19602/SvcType/PID/Issuance`                         |
| Wallet Instance Attestation                                          | `LoTEProfile.EUWalletProvidersList` | `http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance`              |
| JWS signed with a WRPAC (Credential Issuer Metadata, Request Object) | `LoTEProfile.EUWRPACProvidersList`  | `http://uri.etsi.org/19602/SvcType/WRPAC/Issuance`                       |
| WRPRC                                                                | `LoTEProfile.EUWRPRCProvidersList`  | `http://uri.etsi.org/19602/SvcType/WRPRC/Issuance` (use `validateWRPRC`) |
| PuB-EAA                                                              | `LoTEProfile.EUPubEAAProvidersList` | `http://uri.etsi.org/19602/SvcType/PubEAA/Issuance`                      |

## Callbacks

Like the rest of the SDK, the package performs no cryptography and no network access by itself: they are provided by the consumer through callbacks.

| Callback                     | Purpose                                                       |
| ---------------------------- | ------------------------------------------------------------- |
| `fetch`                      | Download the LoTE                                             |
| `hash`                       | Check the `x5t#o` header of the LoTE                          |
| `verifyJwt`                  | Verify JWS signatures, with a `jwk` or `x5c` signer           |
| `getX509CertificateMetadata` | Parse a certificate: subject, issuer, validity and public key |
| `verifyX509CertificateChain` | RFC 5280 path validation of a chain against one Trust Anchor  |

A Node.js implementation:

```typescript
import type {
  GetX509CertificateMetadataCallback,
  VerifyX509CertificateChainCallback,
} from "@pagopa/io-wallet-eudi-trust";

import { type CallbackContext, zJwk } from "@pagopa/io-wallet-utils";
import {
  X509Certificate,
  constants,
  createHash,
  createPublicKey,
  verify,
} from "node:crypto";

const toCertificate = (der: string) =>
  new X509Certificate(Buffer.from(der, "base64"));

const parseName = (name: string) =>
  name.split("\n").map((attribute) => {
    const separator = attribute.indexOf("=");
    return [
      attribute.slice(0, separator),
      attribute.slice(separator + 1),
    ] as const;
  });

const getX509CertificateMetadata: GetX509CertificateMetadataCallback = (
  der,
) => {
  const certificate = toCertificate(der);
  const subject = parseName(certificate.subject);

  return {
    country: subject.find(([key]) => key === "C")?.[1],
    issuerOrganizationIdentifier: parseName(certificate.issuer).find(
      ([key]) => key === "organizationIdentifier",
    )?.[1],
    notAfter: new Date(certificate.validTo),
    notBefore: new Date(certificate.validFrom),
    organizations: subject.filter(([key]) => key === "O").map(([, v]) => v),
    publicJwk: zJwk.parse(certificate.publicKey.export({ format: "jwk" })),
  };
};

// Full RFC 5280 path validation, including revocation checking, e.g. with
// @peculiar/x509 or pkijs. Return true only if `trustAnchor` validates `chain`.
declare const verifyX509CertificateChain: VerifyX509CertificateChainCallback;

const DIGESTS: Record<string, string> = {
  ES256: "sha256",
  ES384: "sha384",
  ES512: "sha512",
  PS256: "sha256",
  PS384: "sha384",
  PS512: "sha512",
  RS256: "sha256",
  RS384: "sha384",
  RS512: "sha512",
};

const verifyJwtCallback: CallbackContext["verifyJwt"] = (
  signer,
  { compact },
) => {
  const publicKey =
    signer.method === "jwk"
      ? createPublicKey({ format: "jwk", key: signer.publicJwk })
      : signer.method === "x5c"
        ? toCertificate(signer.x5c[0] ?? "").publicKey
        : undefined;
  const digest = DIGESTS[signer.alg];
  if (!publicKey || !digest) return { verified: false };

  const [header, payload, signature = ""] = compact.split(".");
  const verified = verify(
    digest,
    Buffer.from(`${header}.${payload}`),
    {
      key: publicKey,
      ...(signer.alg.startsWith("ES") && { dsaEncoding: "ieee-p1363" }),
      ...(signer.alg.startsWith("PS") && {
        padding: constants.RSA_PKCS1_PSS_PADDING,
      }),
    },
    Buffer.from(signature, "base64url"),
  );

  return verified
    ? {
        signerJwk: zJwk.parse(publicKey.export({ format: "jwk" })),
        verified,
      }
    : { verified };
};

export const callbacks = {
  fetch: globalThis.fetch,
  getX509CertificateMetadata,
  hash: (data: Uint8Array, alg: string) =>
    createHash(alg.replace("-", "")).update(data).digest(),
  verifyJwt: verifyJwtCallback,
  verifyX509CertificateChain,
};
```

## Step by step: a PID

```typescript
import {
  LoTEProfile,
  fetchAndValidateLoTE,
  getTrustAnchors,
  validateCertificateChain,
} from "@pagopa/io-wallet-eudi-trust";
import { decodeJwt, verifyJwt } from "@pagopa/io-wallet-utils";

/** Certificates of the LoTE signer, from the OJEU publication. */
declare const ojeuCertificates: string[];
/** The PID, an SD-JWT VC. */
declare const sdJwtVc: string;

// 1. Fetch and validate the PID Providers LoTE
const pidLote = await fetchAndValidateLoTE({
  callbacks,
  ojeuUrl: "https://eur-lex.europa.eu/oj/direct-access.html",
  profile: LoTEProfile.EUPIDProvidersList,
  trustedCertificates: ojeuCertificates,
  url: "https://development.trust.tech.ec.europa.eu/lists/eudiw/pid-providers.json",
});

// Only the issuer-signed JWT of the SD-JWT VC is signed with the Sign/Seal certificate
const [issuerSignedJwt = ""] = sdJwtVc.split("~");
const { header, payload } = decodeJwt({ jwt: issuerSignedJwt });
const [signingCertificate, ...intermediates] = header.x5c ?? [];
if (!signingCertificate) throw new Error("Missing x5c");
const chain: [string, ...string[]] = [signingCertificate, ...intermediates];

// 2. Retrieve the Trust Anchors of the PID issuance service, narrowed to the
//    provider identified by the issuer of the last certificate of the chain
const { issuerOrganizationIdentifier } =
  await callbacks.getX509CertificateMetadata(
    chain.at(-1) ?? signingCertificate,
  );
const trustAnchors = getTrustAnchors({
  issuerOrganizationIdentifier,
  lote: pidLote.document,
  profile: LoTEProfile.EUPIDProvidersList,
  serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PID/Issuance",
});

// 3. Validate the chain: returns the Trust Anchor that validated it
const trustAnchor = await validateCertificateChain({
  callbacks,
  chain,
  trustAnchors,
});

// 4. Verify the signature with the public key of the validated signing certificate
const { publicJwk } =
  await callbacks.getX509CertificateMetadata(signingCertificate);
await verifyJwt({
  compact: issuerSignedJwt,
  header,
  payload,
  signer: { alg: header.alg, method: "jwk", publicJwk },
  verifyJwtCallback: callbacks.verifyJwt,
});
```

## One call: `evaluateJwsTrust`

`evaluateJwsTrust` decodes the JWS (a JWT, or an SD-JWT of which only the issuer-signed JWT is verified), verifies its signature with the public key of the first `x5c` certificate, checks `exp` and `nbf`, and validates the `x5c` chain against the LoTE: the JWS is trusted only if both succeed. It returns the decoded `header` and `payload`, the `signer` and the `trustAnchor`.

### PID

```typescript
import { evaluateJwsTrust } from "@pagopa/io-wallet-eudi-trust";

const pid = await evaluateJwsTrust({
  callbacks,
  jwt: sdJwtVc,
  lote: pidLote, // validated as in step 1 above
  profile: LoTEProfile.EUPIDProvidersList,
  serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PID/Issuance",
});
```

### Wallet Instance Attestation

```typescript
declare const walletInstanceAttestation: string;

const walletProvidersLote = await fetchAndValidateLoTE({
  callbacks,
  ojeuUrl: "https://eur-lex.europa.eu/oj/direct-access.html",
  profile: LoTEProfile.EUWalletProvidersList,
  trustedCertificates: ojeuCertificates,
  url: "https://development.trust.tech.ec.europa.eu/lists/eudiw/wallet-providers.json",
});

const wia = await evaluateJwsTrust({
  callbacks,
  jwt: walletInstanceAttestation,
  lote: walletProvidersLote,
  profile: LoTEProfile.EUWalletProvidersList,
  serviceTypeIdentifier:
    "http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance",
});
```

### Credential Issuer Metadata signed with a WRPAC

```typescript
const wrpacProvidersLote = await fetchAndValidateLoTE({
  callbacks,
  ojeuUrl: "https://eur-lex.europa.eu/oj/direct-access.html",
  profile: LoTEProfile.EUWRPACProvidersList,
  trustedCertificates: ojeuCertificates,
  url: "https://development.trust.tech.ec.europa.eu/lists/eudiw/wrpac-providers.json",
});

const signedMetadata = await fetch(
  "https://issuer.eudiw.dev/.well-known/openid-credential-issuer",
  { headers: { Accept: "application/jwt" } },
).then((response) => response.text());

const metadata = await evaluateJwsTrust({
  callbacks,
  jwt: signedMetadata,
  lote: wrpacProvidersLote,
  profile: LoTEProfile.EUWRPACProvidersList,
  serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance",
});
```

To validate only a certificate chain, without a signed object, use `validateSignSealCertificate` (PID, WIA, PuB-EAA) or `validateWRPAC`.

## Errors

- `LoTEError`: the LoTE is invalid, expired, not signed by an OJEU certificate, or of an unexpected type.
- `CertificateChainError`: no candidate Trust Anchor, a Trust Anchor included in the chain, or no Trust Anchor validating the chain.
- `JwtVerificationError` (from `@pagopa/io-wallet-utils`): invalid signature, or expired JWS.
- `WRPRCError`: WRPRC not yet valid, or expired.
- `ValidationError` (from `@pagopa/io-wallet-utils`): malformed LoTE or JWS.

## Not supported yet

- LoTE pivots: the LoTE signer must be one of the OJEU certificates.
- Revocation checking, unless performed by `verifyX509CertificateChain`.
- Trusted Lists (QEAA, qualified status of PuB-EAA providers).
- Historical keys (`ServiceHistory`).
- mdoc (COSE `x5chain`) signatures.
