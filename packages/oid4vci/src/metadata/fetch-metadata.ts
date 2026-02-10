import { CallbackContext, decodeJwt } from "@openid4vc/oauth2";
import { createFetcher, parseWithErrorHandling } from "@openid4vc/utils";
import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";
import {
  UnexpectedStatusCodeError,
  ValidationError,
  hasStatusOrThrow,
  zHttpsUrl,
} from "@pagopa/io-wallet-utils";

import { FetchMetadataError } from "../errors";
import { MetadataResponse, zMetadataResponse } from "./z-metadata-response";

export interface FetchMetadataOptions {
  /** Callback providing the fetch implementation */
  callbacks: Pick<CallbackContext, "fetch">;

  /**
   * Base URL of the Credential Issuer (e.g. "https://issuer.example.it").
   * The well-known paths are appended automatically.
   */
  credentialIssuerUrl: string;
}

/**
 * Attempts the federation discovery path.
 * Returns the normalised metadata object if successful, or undefined on any failure.
 */
async function tryFederationDiscovery(
  fetch: ReturnType<typeof createFetcher>,
  baseUrl: string,
): Promise<MetadataResponse | undefined> {
  try {
    const response = await fetch(`${baseUrl}/.well-known/openid-federation`);

    if (response.status !== 200) {
      return undefined;
    }

    const entityStatement = await response.text();
    const { payload } = decodeJwt({
      jwt: entityStatement,
      payloadSchema: itWalletEntityStatementClaimsSchema,
    });
    return {
      discoveredVia: "federation",
      metadata: payload.metadata as MetadataResponse["metadata"],
      openid_federation_claims:
        payload as MetadataResponse["openid_federation_claims"],
    };
  } catch (error) {
    if (error instanceof ValidationError) {
      throw error;
    }
    return undefined;
  }
}

/**
 * Executes the fallback OID4VCI discovery path:
 *   1. GET /.well-known/openid-credential-issuer
 *   2a. If authorization_servers[] is present → GET the first URL
 *   2b. If absent → the issuer JSON already contains the auth-server claims inline
 */
async function fallbackDiscovery(
  fetch: ReturnType<typeof createFetcher>,
  baseUrl: string,
): Promise<MetadataResponse> {
  const issuerResponse = await fetch(
    `${baseUrl}/.well-known/openid-credential-issuer`,
  );

  await hasStatusOrThrow(200, UnexpectedStatusCodeError)(issuerResponse);

  const issuerJson = (await issuerResponse.json()) as Record<string, unknown>;

  const authorizationServers = issuerJson.authorization_servers as
    | string[]
    | undefined;

  let oauthAuthorizationServer: Record<string, unknown>;

  if (authorizationServers && authorizationServers.length > 0) {
    const parsedUrl = zHttpsUrl.safeParse(authorizationServers[0]);
    if (!parsedUrl.success) {
      throw new ValidationError(
        "authorization_servers[0] is not a valid HTTPS URL",
      );
    }

    const authServerResponse = await fetch(
      `${parsedUrl.data}/.well-known/oauth-authorization-server`,
    );

    await hasStatusOrThrow(200, UnexpectedStatusCodeError)(authServerResponse);

    oauthAuthorizationServer = (await authServerResponse.json()) as Record<
      string,
      unknown
    >;
  } else {
    oauthAuthorizationServer = issuerJson;
  }

  return {
    discoveredVia: "oid4vci",
    metadata: {
      oauth_authorization_server:
        oauthAuthorizationServer as MetadataResponse["metadata"]["oauth_authorization_server"],
      openid_credential_issuer:
        issuerJson as MetadataResponse["metadata"]["openid_credential_issuer"],
    },
  };
}

/**
 * Performs the OID4VCI discovery flow for a Credential Issuer using a federation-first strategy.
 *
 * Attempts {@link https://openid.net/specs/openid-federation-1_0.html | OpenID Federation}
 * discovery first (`/.well-known/openid-federation`). On failure, falls back to the standard
 * OID4VCI well-known endpoints.
 *
 * When federation discovery succeeds, the full entity statement claims are
 * preserved in `openid_federation_claims`.
 * NOTE: It is included from IT Wallet v1.3, so MetadataResponse is designed to accommodate v1.3 metadata shapes.
 *
 * @param options - Configuration for metadata fetching
 * @returns Normalised metadata with `discoveredVia` indicating the discovery path used
 * @throws {UnexpectedStatusCodeError} If a fallback endpoint returns a non-200 status
 * @throws {ValidationError} If the response does not match the expected schema
 * @throws {FetchMetadataError} For any other unexpected error
 */
export async function fetchMetadata(
  options: FetchMetadataOptions,
): Promise<MetadataResponse> {
  try {
    const urlValidation = zHttpsUrl.safeParse(options.credentialIssuerUrl);
    if (!urlValidation.success) {
      throw new ValidationError(
        "credentialIssuerUrl must be a valid HTTPS URL",
      );
    }

    const fetch = createFetcher(options.callbacks.fetch);

    const federationResult = await tryFederationDiscovery(
      fetch,
      options.credentialIssuerUrl,
    );

    const raw =
      federationResult ??
      (await fallbackDiscovery(fetch, options.credentialIssuerUrl));

    return parseWithErrorHandling(
      zMetadataResponse,
      raw,
      "Failed to parse metadata response",
    );
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError
    ) {
      throw error;
    }
    throw new FetchMetadataError(
      `Unexpected error during metadata fetch: ${error instanceof Error ? error.message : String(error)}`,
      error,
    );
  }
}
