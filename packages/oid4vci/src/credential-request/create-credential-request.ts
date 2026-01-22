import {
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
} from "@pagopa/io-wallet-utils";

import type {
  CredentialRequest,
  CredentialRequestOptions,
  CredentialRequestOptionsV1_0_2,
  CredentialRequestOptionsV1_3_3,
} from "./types";
import type { CredentialRequestV1_0_2 } from "./v1.0.2/z-credential";
import type { CredentialRequestV1_3_3 } from "./v1.3.3/z-credential";

import * as v1_0_2 from "./v1.0.2/create-credential-request";
import * as v1_3_3 from "./v1.3.3/create-credential-request";

/**
 * Creates a credential request according to the configured Italian Wallet specification version.
 *
 * Version Differences:
 * - v1.0.2: Returns singular `proof` object with explicit `proof_type` field
 * - v1.3.3: Returns plural `proofs` object with JWT array (batch support) and requires key attestation
 *
 * @param options - Request options including version config
 * @returns Version-specific credential request object
 * @throws {ItWalletSpecsVersionError} When version is not supported or keyAttestation is used with wrong version
 *
 * @example v1.0.2 - Basic credential request
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
 * @example v1.3.3 - Credential request with key attestation
 * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 });
 * const request = await createCredentialRequest({
 *   config,
 *   callbacks: { signJwt: mySignJwtCallback },
 *   clientId: "my-client-id",
 *   credential_identifier: "education_degree_unibo_2017_l31_informatica",
 *   issuerIdentifier: "https://issuer.example.com",
 *   keyAttestation: 'eyJ...', // Required for v1.3.3
 *   nonce: "c_nonce_value",
 *   signer: myJwtSigner
 * });
 * // Returns: { credential_identifier: "...", proofs: { jwt: ["..."] } }
 */

// Function overload for v1.0.2
export function createCredentialRequest(
  options: CredentialRequestOptionsV1_0_2,
): Promise<CredentialRequestV1_0_2>;

// Function overload for v1.3.3
export function createCredentialRequest(
  options: CredentialRequestOptionsV1_3_3,
): Promise<CredentialRequestV1_3_3>;

// Implementation signature (not callable by users)
export async function createCredentialRequest(
  options: CredentialRequestOptions,
): Promise<CredentialRequest> {
  const { config } = options;

  switch (config.itWalletSpecsVersion) {
    case ItWalletSpecsVersion.V1_0: {
      // Validate that keyAttestation is NOT provided for v1.0.2
      if ("keyAttestation" in options) {
        throw new ItWalletSpecsVersionError(
          "keyAttestation parameter",
          ItWalletSpecsVersion.V1_0,
          [ItWalletSpecsVersion.V1_3],
        );
      }
      return v1_0_2.createCredentialRequest(
        options as CredentialRequestOptionsV1_0_2,
      );
    }
    case ItWalletSpecsVersion.V1_3: {
      return v1_3_3.createCredentialRequest(
        options as CredentialRequestOptionsV1_3_3,
      );
    }
    default: {
      // Exhaustiveness check - ensures all versions are handled
      throw new ItWalletSpecsVersionError(
        "createCredentialRequest",
        (config as { itWalletSpecsVersion: string }).itWalletSpecsVersion,
        [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
      );
    }
  }
}
