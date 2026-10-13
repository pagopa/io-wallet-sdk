import {
  CallbackContext,
  dateToSeconds,
  decodeJwt,
  verifyJwt,
} from "@pagopa/io-wallet-utils";

import { WRPRCError } from "../errors";
import { LoTEProfile } from "../lote/constants";
import {
  ValidateLoTECertificateChainOptions,
  validateLoTECertificateChain,
} from "../x509/validate-certificate-chain";
import {
  WRPRCJwtHeader,
  WRPRCPayload,
  zWRPRCJwtHeader,
  zWRPRCPayload,
} from "./z-wrprc";

export interface ValidateWRPRCOptions extends Omit<
  ValidateLoTECertificateChainOptions,
  "callbacks" | "chain" | "profile" | "serviceTypeIdentifier"
> {
  callbacks: Pick<CallbackContext, "verifyJwt"> &
    ValidateLoTECertificateChainOptions["callbacks"];
  jwt: string;
}

export interface ValidatedWRPRC {
  compact: string;
  header: WRPRCJwtHeader;
  payload: WRPRCPayload;
  /** The Trust Anchor that validated the WRPRC signing certificate chain. */
  trustAnchor: string;
}

/**
 * IT-Wallet "Wallet-Relying Party Registration Certificate Validation", steps 1
 * and 3-6, for the JWT form (ETSI TS 119 475 clause 5.2.1):
 * 1. `typ` is `rc-wrp+jwt`;
 * 3. the signature is valid for the first `x5c` certificate;
 * 4-5. the `x5c` chain is validated against the Trust Anchors of the
 *    `WRPRC/Issuance` service of a Providers of WRPRC LoTE;
 * 6. `iat` and `exp`, when present, are valid at `now`.
 *
 * The algorithm (step 2), status (step 7) and consistency with the interaction
 * (step 8) are not checked.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#authorization-artifacts-validation
 */
export async function validateWRPRC(
  options: ValidateWRPRCOptions,
): Promise<ValidatedWRPRC> {
  const { compact, header, payload } = decodeJwt({
    headerSchema: zWRPRCJwtHeader,
    jwt: options.jwt,
    payloadSchema: zWRPRCPayload,
  });

  try {
    await verifyJwt({
      compact,
      header,
      payload,
      signer: { alg: header.alg, method: "x5c", x5c: header.x5c },
      skipTimeBasedValidation: true,
      verifyJwtCallback: options.callbacks.verifyJwt,
    });
  } catch (error) {
    throw new WRPRCError("Invalid WRPRC signature", {
      cause: error,
      code: "WRPRC_SIGNATURE_VERIFICATION_FAILED",
    });
  }

  const now = options.now ?? new Date();
  const trustAnchor = await validateLoTECertificateChain({
    ...options,
    chain: header.x5c,
    now,
    profile: LoTEProfile.EUWRPRCProvidersList,
    serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance",
  });

  const nowInSeconds = dateToSeconds(now);
  if (payload.iat !== undefined && payload.iat > nowInSeconds) {
    throw new WRPRCError("WRPRC was issued in the future", {
      code: "WRPRC_NOT_YET_VALID",
    });
  }
  if (payload.exp !== undefined && payload.exp <= nowInSeconds) {
    throw new WRPRCError("WRPRC has expired", { code: "WRPRC_EXPIRED" });
  }

  return { compact, header, payload, trustAnchor };
}
