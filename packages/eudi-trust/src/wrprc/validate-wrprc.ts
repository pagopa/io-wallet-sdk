import { dateToSeconds, decodeJwt } from "@pagopa/io-wallet-utils";

import { WRPRCError } from "../errors";
import { LoTEProfile } from "../lote/constants";
import {
  EvaluateJwsTrustOptions,
  evaluateJwsTrust,
} from "../trust-evaluation/evaluate-jws-trust";
import {
  WRPRCJwtHeader,
  WRPRCPayload,
  zWRPRCJwtHeader,
  zWRPRCPayload,
} from "./z-wrprc";

export type ValidateWRPRCOptions = Omit<
  EvaluateJwsTrustOptions,
  "profile" | "serviceTypeIdentifier"
>;

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
 * 1. `typ` is `rc-wrp+jwt`, and header and payload follow ETSI TS 119 475
 *    clause 5.2 (see `zWRPRCJwtHeader` and `zWRPRCPayload`);
 * 3. the signature is valid for the first `x5c` certificate;
 * 4-5. the `x5c` chain is validated against the Trust Anchors of the
 *    `WRPRC/Issuance` service of a Providers of WRPRC LoTE;
 * 6. `iat`, and `exp` when present, are valid at `now`.
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
    errorMessagePrefix: "Error decoding WRPRC:",
    headerSchema: zWRPRCJwtHeader,
    jwt: options.jwt,
    payloadSchema: zWRPRCPayload,
  });

  // Checked before the signature, which would otherwise reject an expired WRPRC
  // with a generic JWT verification error.
  const nowInSeconds = dateToSeconds(options.now ?? new Date());
  if (payload.exp !== undefined && payload.exp <= nowInSeconds) {
    throw new WRPRCError("WRPRC has expired", { code: "WRPRC_EXPIRED" });
  }

  const { trustAnchor } = await evaluateJwsTrust({
    ...options,
    profile: LoTEProfile.EUWRPRCProvidersList,
    serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance",
  });

  if (payload.iat > nowInSeconds) {
    throw new WRPRCError("WRPRC was issued in the future", {
      code: "WRPRC_NOT_YET_VALID",
    });
  }

  return { compact, header, payload, trustAnchor };
}
