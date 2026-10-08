import { HEADERS } from "@pagopa/io-wallet-utils";

import { ClientAttestationError } from "../errors";

/**
 * Client Attestation PoP JWT, either already created or created on demand,
 * so that a fresh one is used when a request is retried.
 */
export type ClientAttestationPoP = (() => Promise<string>) | string;

export interface ClientAttestationHeadersOptions {
  /**
   * The client attestation Demonstration of Proof-of-Possession (DPoP) token
   * Used for OAuth-Client-Attestation-PoP header to prove possession of the client key
   */
  clientAttestationDPoP?: ClientAttestationPoP;

  /**
   * The wallet attestation JWT that proves the client's identity and capabilities
   * Used for OAuth-Client-Attestation header
   */
  walletAttestation?: string;
}

/**
 * Builds the OAuth 2.0 Attestation-Based Client Authentication headers.
 *
 * Both values must be provided to authenticate with a Wallet Attestation. When none is
 * provided no header is returned, so that public clients can use the same requests.
 *
 * @param options - {@link ClientAttestationHeadersOptions}
 * @returns The `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers, if any.
 * @throws {ClientAttestationError} When only one of the two values is provided.
 */
export async function getClientAttestationHeaders(
  options: ClientAttestationHeadersOptions,
): Promise<Record<string, string>> {
  const { clientAttestationDPoP, walletAttestation } = options;

  if (!walletAttestation && !clientAttestationDPoP) return {};

  if (!walletAttestation || !clientAttestationDPoP) {
    throw new ClientAttestationError(
      "walletAttestation and clientAttestationDPoP must be provided together",
    );
  }

  return {
    [HEADERS.OAUTH_CLIENT_ATTESTATION]: walletAttestation,
    [HEADERS.OAUTH_CLIENT_ATTESTATION_POP]:
      typeof clientAttestationDPoP === "string"
        ? clientAttestationDPoP
        : await clientAttestationDPoP(),
  };
}
