import {
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
} from "@pagopa/io-wallet-utils";

import type { CredentialRequest, CredentialRequestOptions } from "./types";
import type { CredentialRequestV1_0 } from "./v1.0/z-credential";
import type { CredentialRequestV1_3 } from "./v1.3/z-credential";

import * as V1_0 from "./v1.0/create-credential-request";
import * as V1_3 from "./v1.3/create-credential-request";

function isV1_0Options(
  options: CredentialRequestOptions,
): options is V1_0.CredentialRequestOptionsV1_0 {
  return options.config.itWalletSpecsVersion === ItWalletSpecsVersion.V1_0;
}

function isV1_3Options(
  options: CredentialRequestOptions,
): options is V1_3.CredentialRequestOptionsV1_3 {
  return options.config.itWalletSpecsVersion === ItWalletSpecsVersion.V1_3;
}

/**
 * Creates a credential request according to the configured Italian Wallet specification version.
 *
 * Version Differences:
 * - v1.0: Returns singular `proof` object with explicit `proof_type` field
 * - v1.3: Returns plural `proofs` object with JWT array (batch support) and requires key attestation
 *
 * @param options - Request options including version config
 * @returns Version-specific credential request object
 * @throws {ItWalletSpecsVersionError} When version is not supported or keyAttestation is used with wrong version
 *
 * @example v1.0 - Basic credential request
 * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 });
 * const request = await createCredentialRequest({
 *   config,
 *   callbacks: { signJwt: mySignJwtCallback },
 *   clientId: "my-client-id",
 *   credential_identifier: "UniversityDegree",
 *   issuerIdentifier: "https://issuer.example.com",
 *   nonce: "c_nonce_value",
 *   signer: myJwtSigner
 * });
 * // Returns: { credential_identifier: "...", proof: { jwt: "...", proof_type: "jwt" } }
 *
 * @example v1.3 - Credential request with key attestation
 * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 });
 * const request = await createCredentialRequest({
 *   config,
 *   callbacks: { signJwt: mySignJwtCallback },
 *   clientId: "my-client-id",
 *   credential_identifier: "education_degree_unibo_2017_l31_informatica",
 *   issuerIdentifier: "https://issuer.example.com",
 *   keyAttestation: 'eyJ...', // Required for v1.3
 *   nonce: "c_nonce_value",
 *   signer: myJwtSigner
 * });
 * // Returns: { credential_identifier: "...", proofs: { jwt: ["..."] } }
 */

// Function overload for v1.0
export function createCredentialRequest(
  options: V1_0.CredentialRequestOptionsV1_0,
): Promise<CredentialRequestV1_0>;

// Function overload for v1.3
export function createCredentialRequest(
  options: V1_3.CredentialRequestOptionsV1_3,
): Promise<CredentialRequestV1_3>;

// Implementation signature (not callable by users)
export async function createCredentialRequest(
  options: CredentialRequestOptions,
): Promise<CredentialRequest> {
  const { config } = options;

  if (isV1_0Options(options)) {
    return V1_0.createCredentialRequest(options);
  }

  if (isV1_3Options(options)) {
    return V1_3.createCredentialRequest(options);
  }

  throw new ItWalletSpecsVersionError(
    "createCredentialRequest",
    (config as { itWalletSpecsVersion: string }).itWalletSpecsVersion,
    [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
  );
}
