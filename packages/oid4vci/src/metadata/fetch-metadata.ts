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
  createVersionDispatcher,
  hasStatusOrThrow,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { assertAuthorizationServerAllowed } from "../credential-offer/validate-credential-offer";
import { CredentialOfferError, FetchMetadataError } from "../errors";
import {
  MetadataResponse,
  zMetadataResponseV1_0,
  zMetadataResponseV1_3,
  zMetadataResponseV1_4,
  zPartialIssuerMetadata,
} from "./z-metadata-response";

interface RawFederationResult {
  /**
   * Entity statement claims of the Authorization Server, present only when the
   * selected authorization server was resolved through a federation entity
   * distinct from the Credential Issuer. Preserves the AS metadata provenance
   * so its trust chain remains auditable.
   */
  authorization_server_federation_claims?: z.infer<
    typeof itWalletEntityStatementClaimsSchema
  >;
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
  /**
   * Optional Authorization Server URL selected from a credential offer.
   * When provided, it must be a valid HTTPS URL and exactly match one of
   * the Credential Issuer metadata authorization_servers.
   */
  authorizationServer?: string;

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
 * Resolves the authorization server for a federation discovery result, following
 * the IT-Wallet trust model (identical across v1.3 and v1.4).
 *
 * Per OID4VCI, each `authorization_servers` entry is an Authorization Server
 * identifier, and a co-located Credential Issuer uses its own identifier as the
 * Authorization Server identifier. The inline `oauth_authorization_server` is
 * attested within the Credential Issuer's own entity statement, so it is trusted
 * only as the issuer's own (co-located) authorization server — i.e. only when
 * the selected server equals the `credential_issuer` identifier. Any other
 * authorization server is resolved through its own federation trust chain.
 *
 * Selection of the authorization server to use:
 * - **Explicit (from the credential offer):** the offer's `authorization_server`
 *   must be one of the issuer's declared `authorization_servers`.
 * - **No selection, no `authorization_servers` declared:** the Credential Issuer
 *   is its own Authorization Server (co-located); the inline metadata is used.
 * - **No selection, `authorization_servers` declared:** the Credential Issuer
 *   itself when it is one of the declared servers (co-located), otherwise the
 *   first declared server. The spec leaves the multi-server, no-selection case
 *   undefined; defaulting to the first declared server matches the OID4VCI
 *   fallback path.
 *
 * When an authorization server is resolved via federation, the grafted metadata
 * replaces `oauth_authorization_server`, and the resolved entity statement is
 * preserved under `authorization_server_federation_claims` so its provenance
 * remains auditable.
 *
 * @throws {CredentialOfferError} If an authorization server selected from the
 *   credential offer is not among the issuer's `authorization_servers`.
 * @throws {ValidationError} If the selected authorization server cannot be
 *   resolved via federation or does not expose oauth_authorization_server metadata.
 */
async function applyFederationAuthorizationServerSelection(
  fetch: ReturnType<typeof createFetcher>,
  federationResult: RawFederationResult,
  authorizationServer?: string,
  verifyJwt?: VerifyJwtCallback,
): Promise<RawFederationResult> {
  const credentialIssuer =
    federationResult.metadata?.openid_credential_issuer?.credential_issuer;
  const authorizationServers =
    federationResult.metadata?.openid_credential_issuer?.authorization_servers;

  let selectedAuthorizationServer: string | undefined;

  if (authorizationServer) {
    // Explicit selection from the credential offer: it must be one of the
    // declared authorization servers.
    assertAuthorizationServerAllowed(authorizationServer, authorizationServers);
    selectedAuthorizationServer = authorizationServer;
  } else if (authorizationServers && authorizationServers.length > 0) {
    // No selection from the offer: prefer the Credential Issuer itself when it
    // is one of the declared servers (co-located), otherwise default to the
    // first declared server.
    selectedAuthorizationServer =
      credentialIssuer && authorizationServers.includes(credentialIssuer)
        ? credentialIssuer
        : authorizationServers[0];
  } else {
    // No declared servers: the Credential Issuer is its own Authorization Server.
    selectedAuthorizationServer = credentialIssuer;
  }

  // The inline authorization server is trusted only as the issuer's own
  // (co-located) one; everything else is resolved via federation.
  if (
    !selectedAuthorizationServer ||
    selectedAuthorizationServer === credentialIssuer
  ) {
    return federationResult;
  }

  const parsedSelectedAuthorizationServer = z
    .url()
    .safeParse(selectedAuthorizationServer);
  if (
    !parsedSelectedAuthorizationServer.success ||
    !parsedSelectedAuthorizationServer.data.startsWith("https://")
  ) {
    throw new ValidationError(
      "selected authorization server is not a valid HTTPS URL",
    );
  }

  const authorizationServerResult = await tryFederationDiscovery(
    fetch,
    parsedSelectedAuthorizationServer.data,
    verifyJwt,
  );

  if (!authorizationServerResult) {
    throw new ValidationError(
      `Federation discovery did not yield OpenID Federation metadata for authorization server '${selectedAuthorizationServer}'`,
    );
  }

  return {
    ...federationResult,
    authorization_server_federation_claims:
      authorizationServerResult.openid_federation_claims,
  };
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
  authorizationServer?: string,
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

  assertAuthorizationServerAllowed(authorizationServer, authorizationServers);

  let oauthAuthorizationServer: Record<string, unknown>;

  if (authorizationServers && authorizationServers.length > 0) {
    const selectedAuthorizationServer =
      authorizationServer ?? authorizationServers[0];
    const parsedUrl = z.url().safeParse(selectedAuthorizationServer);
    if (!parsedUrl.success || !parsedUrl.data.startsWith("https://")) {
      throw new ValidationError(
        "selected authorization server is not a valid HTTPS URL",
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
 * Fetch raw metadata with federation discovery or the available fallback mechanisms.
 * Metadata are returned raw without any version specific validation, that must be performed separately.
 */
const fetchMetadataWithFallbackDiscovery = async (
  options: FetchMetadataOptions,
): Promise<RawFederationResult | RawOid4vciResult> => {
  const fetch = createFetcher(options.callbacks.fetch);
  const federationResult = await tryFederationDiscovery(
    fetch,
    options.credentialIssuerUrl,
    options.callbacks.verifyJwt,
  );
  const raw = federationResult
    ? await applyFederationAuthorizationServerSelection(
        fetch,
        federationResult,
        options.authorizationServer,
        options.callbacks.verifyJwt,
      )
    : await fallbackDiscovery(
        fetch,
        options.credentialIssuerUrl,
        options.authorizationServer,
      );
  return raw;
};

async function fetchMetadataV1_0(
  options: FetchMetadataOptions,
): Promise<MetadataResponse> {
  const fetch = createFetcher(options.callbacks.fetch);
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

async function fetchMetadataV1_3(
  options: FetchMetadataOptions,
): Promise<MetadataResponse> {
  const raw = await fetchMetadataWithFallbackDiscovery(options);
  return parseWithErrorHandling(
    zMetadataResponseV1_3,
    raw,
    "Failed to parse v1.3 metadata response",
  );
}

async function fetchMetadataV1_4(
  options: FetchMetadataOptions,
): Promise<MetadataResponse> {
  const raw = await fetchMetadataWithFallbackDiscovery(options);
  return parseWithErrorHandling(
    zMetadataResponseV1_4,
    raw,
    "Failed to parse v1.4 metadata response",
  );
}

const dispatchFetchMetadata = createVersionDispatcher<
  FetchMetadataOptions,
  Promise<MetadataResponse>
>({
  [ItWalletSpecsVersion.V1_0]: (o) => fetchMetadataV1_0(o),
  [ItWalletSpecsVersion.V1_3]: (o) => fetchMetadataV1_3(o),
  [ItWalletSpecsVersion.V1_4]: (o) => fetchMetadataV1_4(o),
});

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
 * **v1.4**: Same discovery strategy as v1.3, validated against the v1.4 metadata schema.
 * Returns `MetadataResponseV1_4`.
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
 * @throws {UnexpectedStatusCodeError} If a fallback endpoint returns a non-200 status (v1.3/v1.4 only)
 * @throws {ValidationError} If the response does not match the expected schema
 * @throws {FetchMetadataError} If federation discovery fails for v1.0, or for any other unexpected error
 */
export async function fetchMetadata(
  options: FetchMetadataOptions,
): Promise<MetadataResponse> {
  try {
    const urlValidation = z.url().safeParse(options.credentialIssuerUrl);
    if (!urlValidation.success || !urlValidation.data.startsWith("https://")) {
      throw new ValidationError(
        "credentialIssuerUrl must be a valid HTTPS URL",
      );
    }

    return await dispatchFetchMetadata(options);
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError ||
      error instanceof ItWalletSpecsVersionError ||
      error instanceof CredentialOfferError ||
      error instanceof FetchMetadataError
    ) {
      throw error;
    }
    throw new FetchMetadataError("Unexpected error during metadata fetch", {
      cause: error,
    });
  }
}
