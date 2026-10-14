import {
  CallbackContext,
  JwtSignerWithJwk,
  decodeJwt,
  parseWithErrorHandling,
  verifyJwt,
  zJwtHeader,
  zJwtPayload,
  zTrustChain,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { LoTEProfile } from "../lote/constants";
import { zWRPAC } from "../wrpac";
import {
  ValidateLoTECertificateChainOptions,
  validateLoTECertificateChain,
} from "../x509/validate-certificate-chain";

const zX5cJwtHeader = zJwtHeader.extend({ x5c: zTrustChain });

export interface EvaluateJwsTrustOptions extends Omit<
  ValidateLoTECertificateChainOptions,
  "callbacks" | "chain"
> {
  callbacks: Pick<CallbackContext, "verifyJwt"> &
    ValidateLoTECertificateChainOptions["callbacks"];
  /**
   * A compact JWS, or an SD-JWT (`<issuer-signed JWT>~<disclosures>~`) of which
   * only the issuer-signed JWT is verified. The `x5c` header carries the chain.
   */
  jwt: string;
}

export interface JwsTrustEvaluation {
  /** The issuer-signed JWT. */
  compact: string;
  header: z.infer<typeof zX5cJwtHeader>;
  payload: z.infer<typeof zJwtPayload>;
  signer: JwtSignerWithJwk;
  /** The Trust Anchor that validated the `x5c` chain. */
  trustAnchor: string;
}

/**
 * EUDIW trust evaluation of a JWS carrying its signing certificate chain in
 * `x5c`, e.g. a PID, a Wallet Instance Attestation, a WRPRC or a WRPAC-signed
 * Request Object or Credential Issuer Metadata. It binds the JWS to a Trust
 * Anchor notified in a LoTE through signature validation (ETSI EN 319 102-1):
 * 1. the signature is cryptographically verified with the public key of the
 *    first `x5c` certificate, and `exp` and `nbf`, when present, are checked at
 *    `now`;
 * 2. the `x5c` chain is validated against the Trust Anchors of the LoTE.
 * This is the order of the IT-Wallet EUDIW Attestation Signature Validation and
 * of the WRPRC validation.
 *
 * When the LoTE is a Providers of WRPAC LoTE, the content of the signing WRPAC
 * is also checked (see `zWRPAC`).
 *
 * The LoTE must be validated beforehand (`validateLoTE`). Revocation is checked
 * only if done by `verifyX509CertificateChain`; artifact-specific checks, such as
 * the WRPRC status and authorization, are left to the caller.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#eudiw-attestation-signature-validation
 */
export async function evaluateJwsTrust(
  options: EvaluateJwsTrustOptions,
): Promise<JwsTrustEvaluation> {
  const [compact = ""] = options.jwt.split("~");
  const { header, payload } = decodeJwt({
    errorMessagePrefix: "Error decoding JWS:",
    headerSchema: zX5cJwtHeader,
    jwt: compact,
  });

  const signingCertificate = await options.callbacks.getX509CertificateMetadata(
    header.x5c[0],
  );

  if (options.profile === LoTEProfile.EUWRPACProvidersList) {
    parseWithErrorHandling(zWRPAC, signingCertificate, "Invalid WRPAC");
  }

  const { signer } = await verifyJwt({
    compact,
    errorMessage: "JWS signature verification failed.",
    header,
    now: options.now,
    payload,
    signer: {
      alg: header.alg,
      method: "jwk",
      publicJwk: signingCertificate.publicJwk,
    },
    verifyJwtCallback: options.callbacks.verifyJwt,
  });

  const trustAnchor = await validateLoTECertificateChain({
    ...options,
    chain: header.x5c,
  });

  return { compact, header, payload, signer, trustAnchor };
}
