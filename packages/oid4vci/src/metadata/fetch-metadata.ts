import { CallbackContext, VerifyJwtCallback } from "@openid4vc/oauth2";
import { decodeJwt } from "@pagopa/io-wallet-oauth2";
import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";
import {
  UnexpectedStatusCodeError,
  ValidationError,
  createFetcher,
  hasStatusOrThrow,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { FetchMetadataError } from "../errors";
import {
  MetadataResponse,
  zMetadataResponse,
  zPartialIssuerMetadata,
} from "./z-metadata-response";

function ensureTrailingSlash(url: string): string {
  return url.endsWith("/") ? url : `${url}/`;
}

export interface FetchMetadataOptions {
  /** Callback providing the fetch implementation */
  callbacks: {
    /**
     * Optional JWT signature verification callback.
     * When provided, the entity statement signature retrieved via federation
     * discovery is verified using this callback.
     * When omitted, trust is derived solely from TLS (the default behaviour).
     */
    verifyJwt?: VerifyJwtCallback;
  } & Pick<CallbackContext, "fetch">;

  /**
   * Base URL of the Credential Issuer (e.g. "https://issuer.example.it").
   * The well-known paths are appended automatically.
   */
  credentialIssuerUrl: string;
}

/**
 * Attempts the federation discovery path.
 * Returns the normalised metadata object if successful or undefined.
 * In case of ValidationError, the error is re-thrown, as it indicates a non-compliant implementation that should be surfaced instead of falling back to the OID4VCI discovery.
 * For any other error (e.g. network issues, non-200 status code), undefined is returned to trigger the fallback mechanism.
 */
async function tryFederationDiscovery(
  fetch: ReturnType<typeof createFetcher>,
  baseUrl: string,
  verifyJwt?: VerifyJwtCallback,
): Promise<MetadataResponse | undefined> {
  try {
    const federationUrl = new URL(
      ".well-known/openid-federation",
      ensureTrailingSlash(baseUrl),
    ).toString();
    const response = await fetch(federationUrl);

    if (response.status !== 200) {
      return undefined;
    }

    const entityStatement = await response.text();
    const { header, payload } = decodeJwt({
      jwt: entityStatement,
      payloadSchema: itWalletEntityStatementClaimsSchema,
    });

    if (verifyJwt) {
      const jwtSigner = {
        alg: header.alg as string,
        kid: header.kid as string,
        method: "federation" as const,
      };
      const result = await verifyJwt(jwtSigner, {
        compact: entityStatement,
        header,
        payload,
      });
      if (!result.verified) {
        throw new ValidationError(
          "Entity statement signature verification failed",
        );
      }
    }

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
 *   1. GET {baseUrl}/.well-known/openid-credential-issuer
 *   2a. If authorization_servers[] is present → GET {authServerUrl}/.well-known/oauth-authorization-server
 *   2b. If absent → the issuer JSON already contains the auth-server claims inline
 *
 * Well-known paths are appended relative to the full base URL, preserving any
 * path segment (e.g. "https://issuer.example.it/v1" → "https://issuer.example.it/v1/.well-known/...").
 */
async function fallbackDiscovery(
  fetch: ReturnType<typeof createFetcher>,
  baseUrl: string,
): Promise<MetadataResponse> {
  const issuerUrl = new URL(
    ".well-known/openid-credential-issuer",
    ensureTrailingSlash(baseUrl),
  ).toString();
  const issuerResponse = await fetch(issuerUrl);

  await hasStatusOrThrow(200, UnexpectedStatusCodeError)(issuerResponse);

  const issuerJson = zPartialIssuerMetadata.parse(await issuerResponse.json());
  const authorizationServers = issuerJson.authorization_servers;

  let oauthAuthorizationServer: Record<string, unknown>;

  if (authorizationServers && authorizationServers.length > 0) {
    const parsedUrl = z.string().url().safeParse(authorizationServers[0]);
    if (!parsedUrl.success || !parsedUrl.data.startsWith("https://")) {
      throw new ValidationError(
        "authorization_servers[0] is not a valid HTTPS URL",
      );
    }

    const authServerUrl = new URL(
      ".well-known/oauth-authorization-server",
      ensureTrailingSlash(parsedUrl.data),
    ).toString();

    const authServerResponse = await fetch(authServerUrl);
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
 * discovery first (`.well-known/openid-federation` relative to `credentialIssuerUrl`). On failure,
 * falls back to the standard OID4VCI well-known endpoint `.well-known/openid-credential-issuer`.
 *
 * Well-known paths are appended relative to the full `credentialIssuerUrl`, preserving any path
 * segment (e.g. `"https://issuer.example.it/v1"` → `"https://issuer.example.it/v1/.well-known/..."`).
 * This is compliant with the URL spec: the base URL is normalised to end with `/` before resolution.
 *
 * When federation discovery succeeds, the full entity statement claims are
 * preserved in `openid_federation_claims`.
 * Signature verification of the entity statement is optional: supply `callbacks.verifyJwt` to enable it.
 * When omitted, trust is derived from TLS alone (successful retrieval from the well-known endpoint).
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
    const urlValidation = z.string().url().safeParse(options.credentialIssuerUrl);
    if (!urlValidation.success || !urlValidation.data.startsWith("https://")) {
      throw new ValidationError(
        "credentialIssuerUrl must be a valid HTTPS URL",
      );
    }

    const fetch = createFetcher(options.callbacks.fetch);

    const federationResult = await tryFederationDiscovery(
      fetch,
      options.credentialIssuerUrl,
      options.callbacks.verifyJwt,
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
