import { CallbackContext, JwtSignerJwk } from "@openid4vc/oauth2";
import { dateToSeconds, parseWithErrorHandling } from "@pagopa/io-wallet-utils";

import { MrtdPopError } from "../errors";
import {
  MrtdValidationJwtHeader,
  MrtdValidationJwtPayload,
  zMrtdValidationJwtHeader,
  zMrtdValidationJwtPayload,
} from "./z-mrtd-pop";

const JWT_EXPIRY_SECONDS = 300;

/**
 * NFC-read document evidence from CIE (Italian ID card) containing:
 * - Data Groups (DG1, DG11) with personal information
 * - Security Objects of Document (SOD) for MRTD and IAS applications
 * - IAS public key and Anti-Cloning challenge signature
 *
 * It is alligned to the IT-Wallet v1.3 specs
 * @see IT-Wallet L2+ specification Section 12.1.3.5.3.5 (Validation JWT Structure)
 */
export interface MrtdDocumentData {
  /** Anti-Cloning signed challenge response (base64) */
  challengeSigned: string;
  /** Data Group 1 - MRZ info (base64) */
  dg1: string;
  /** Data Group 11 - additional personal data (base64) */
  dg11: string;
  /** IAS public key in DER format (base64) */
  iasPk: string;
  /** Security Object of Document for IAS (base64) */
  sodIas: string;
  /** Security Object of Document for MRTD (base64) */
  sodMrtd: string;
}

export interface CreateMrtdValidationJwtOptions {
  /** PID Provider identifier (JWT aud) */
  audience: string;
  callbacks: Pick<CallbackContext, "signJwt">;
  /** Wallet Instance identifier (JWT iss) */
  clientId: string;
  /** NFC-read document evidence */
  documentData: MrtdDocumentData;
  issuedAt?: Date;
  signer: JwtSignerJwk;
}

/**
 * Creates a signed JWT containing MRTD validation data for Phase 3 of L2+ flow.
 *
 * The JWT is sent to the PID Provider for cryptographic verification of the CIE document.
 * Includes Data Groups (DG1, DG11), Security Objects, and Anti-Cloning challenge response.
 *
 * @param options - Configuration including document data, signer, and callback context
 * @returns Signed JWT with typ="mrtd-ias+jwt"
 * @throws {MrtdPopError} If signer lacks kid or signing fails
 *
 * @see IT-Wallet L2+ specification Section 12.1.3.5.3.4 (MRTD PoP Validation Request)
 */
export async function createMrtdValidationJwt(
  options: CreateMrtdValidationJwtOptions,
): Promise<{ jwt: string }> {
  try {
    const kid = options.signer.publicJwk.kid;
    if (!kid) {
      throw new MrtdPopError("Signer must have a publicJwk.kid property");
    }

    const iat = dateToSeconds(options.issuedAt);

    const header = parseWithErrorHandling(zMrtdValidationJwtHeader, {
      alg: options.signer.alg,
      kid,
      typ: "mrtd-ias+jwt",
    } satisfies MrtdValidationJwtHeader);

    const payload = parseWithErrorHandling(zMrtdValidationJwtPayload, {
      aud: options.audience,
      document_type: "cie",
      exp: iat + JWT_EXPIRY_SECONDS,
      ias: {
        challenge_signed: options.documentData.challengeSigned,
        ias_pk: options.documentData.iasPk,
        sod_ias: options.documentData.sodIas,
      },
      iat,
      iss: options.clientId,
      mrtd: {
        dg1: options.documentData.dg1,
        dg11: options.documentData.dg11,
        sod_mrtd: options.documentData.sodMrtd,
      },
    } satisfies MrtdValidationJwtPayload);

    const { jwt } = await options.callbacks.signJwt(options.signer, {
      header,
      payload,
    });

    return { jwt };
  } catch (error) {
    if (error instanceof MrtdPopError) {
      throw error;
    }
    throw new MrtdPopError(
      `Error creating MRTD validation JWT: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
