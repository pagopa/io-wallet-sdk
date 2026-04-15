import { CallbackContext, VerifyJwtCallback } from "@openid4vc/oauth2";
import { decodeJwt } from "@pagopa/io-wallet-oauth2";
import { itWalletEntityStatementClaimsSchema } from "@pagopa/io-wallet-oid-federation";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
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
  zMetadataResponseV1_0,
  zMetadataResponseV1_3,
  zPartialIssuerMetadata,
} from "./z-metadata-response";

interface RawFederationResult {
  discoveredVia: "federation";
  metadata: z.infer<typeof itWalletEntityStatementClaimsSchema>["metadata"];
  openid_federation_claims: z.infer<typeof itWalletEntityStatementClaimsSchema>;
}

interface RawOid4vciResult {
  discoveredVia: "oid4vci";
  metadata: {
    oauth_authorization_server: Record<string, unknown>;
    openid_credential_issuer: z.infer<typeof zPartialIssuerMetadata>;
  };
}

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
   * SDK configuration used to route discovery logic by IT-Wallet specification version.
   */
  config: IoWalletSdkConfig;

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
): Promise<RawFederationResult | undefined> {
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
      errorMessagePrefix: "Error decoding entity statement JWT:",
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
      metadata: payload.metadata,
      openid_federation_claims: payload,
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
): Promise<RawOid4vciResult> {
  const issuerUrl = new URL(
    ".well-known/openid-credential-issuer",
    ensureTrailingSlash(baseUrl),
  ).toString();
  const issuerResponse = await fetch(issuerUrl);

  await hasStatusOrThrow(200, UnexpectedStatusCodeError)(issuerResponse);

  const issuerJson = parseWithErrorHandling(
    zPartialIssuerMetadata,
    await issuerResponse.json(),
    "Failed to parse credential issuer metadata",
  );
  const authorizationServers = issuerJson.authorization_servers;

  let oauthAuthorizationServer: Record<string, unknown>;

  if (authorizationServers && authorizationServers.length > 0) {
    const parsedUrl = z.url().safeParse(authorizationServers[0]);
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
      oauth_authorization_server: oauthAuthorizationServer,
      openid_credential_issuer: issuerJson,
    },
  };
}

/**
 * Performs the OID4VCI discovery flow for a Credential Issuer, routing discovery
 * strategy and metadata schema validation based on the IT-Wallet specification version
 * provided in `config`.
 *
 * **v1.0**: Only `.well-known/openid-federation` is attempted. If federation discovery
 * fails, a `FetchMetadataError` is thrown — there is no OID4VCI fallback in v1.0.
 * Returns `MetadataResponseV1_0` with `discoveredVia: "federation"`.
 *
 * **v1.3**: Federation discovery is attempted first (`.well-known/openid-federation`).
 * On failure, falls back to `.well-known/openid-credential-issuer` + optional
 * `.well-known/oauth-authorization-server`. Returns `MetadataResponseV1_3`.
 *
 * Well-known paths are appended relative to the full `credentialIssuerUrl`, preserving
 * any path segment (e.g. `"https://issuer.example.it/v1"` →
 * `"https://issuer.example.it/v1/.well-known/..."`).
 *
 * When federation discovery succeeds, the full entity statement claims are
 * preserved in `openid_federation_claims`.
 * Signature verification of the entity statement is optional: supply
 * `callbacks.verifyJwt` to enable it. When omitted, trust is derived from TLS
 * alone (successful retrieval from the well-known endpoint).
 *
 * @param options - Configuration for metadata fetching, including `config` for version routing
 * @returns Normalised metadata with `discoveredVia` indicating the discovery path used
 * @throws {UnexpectedStatusCodeError} If a fallback endpoint returns a non-200 status (v1.3 only)
 * @throws {ValidationError} If the response does not match the expected schema
 * @throws {ItWalletSpecsVersionError} If `config.itWalletSpecsVersion` is not V1_0 or V1_3
 * @throws {FetchMetadataError} If federation discovery fails for v1.0, or for any other unexpected error
 */
export async function fetchMetadata(
  options: FetchMetadataOptions,
): Promise<MetadataResponse> {
  const { config } = options;
  try {
    const urlValidation = z.url().safeParse(options.credentialIssuerUrl);
    if (!urlValidation.success || !urlValidation.data.startsWith("https://")) {
      throw new ValidationError(
        "credentialIssuerUrl must be a valid HTTPS URL",
      );
    }

    const fetch = createFetcher(options.callbacks.fetch);

    if (config.isVersion(ItWalletSpecsVersion.V1_0)) {
      // v1.0: federation ONLY — no OID4VCI fallback
      const federationResult = await tryFederationDiscovery(
        fetch,
        options.credentialIssuerUrl,
        options.callbacks.verifyJwt,
      );
      if (!federationResult) {
        throw new FetchMetadataError(
          `Federation discovery failed for IT Wallet v1.0; no fallback available for credentialIssuerUrl ${options.credentialIssuerUrl}`,
        );
      }
      return parseWithErrorHandling(
        zMetadataResponseV1_0,
        federationResult,
        "Failed to parse v1.0 metadata response",
      );
    }

    if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
      // v1.3: federation-first, OID4VCI fallback
      const federationResult = await tryFederationDiscovery(
        fetch,
        options.credentialIssuerUrl,
        options.callbacks.verifyJwt,
      );
      const raw =
        federationResult ??
        (await fallbackDiscovery(fetch, options.credentialIssuerUrl));
      return parseWithErrorHandling(
        zMetadataResponseV1_3,
        raw,
        "Failed to parse v1.3 metadata response",
      );
    }

    throw new ItWalletSpecsVersionError(
      "fetchMetadata",
      config.itWalletSpecsVersion,
      [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
    );
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError ||
      error instanceof ItWalletSpecsVersionError ||
      error instanceof FetchMetadataError
    ) {
      throw error;
    }
    throw new FetchMetadataError("Unexpected error during metadata fetch", {
      cause: error,
    });
  }
}
