import { ValidationError } from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { FetchMetadataError } from "../../errors";
import { FetchMetadataOptions, fetchMetadata } from "../fetch-metadata";

const mockFetch = vi.fn();

vi.mock("@openid4vc/utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@openid4vc/utils")>();
  return {
    ...actual,
    createFetcher: () => mockFetch,
  };
});

// --- Fixture helpers ---

const mockJwks = {
  keys: [
    {
      e: "AQAB",
      kid: "test-key-1",
      kty: "RSA",
      n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    },
  ],
};

const credentialIssuerMetadata = {
  batch_credential_issuance: { batch_size: 1 },
  client_registration_types_supported: ["automatic"],
  credential_configurations_supported: {
    "urn:id.gov.it:itWallet:issued_credential:ts_ci": {
      authentic_sources: {
        dataset_id: "dataset-123",
        entity_id: "entity-456",
      },
      claims: [
        {
          display: [{ locale: "it-IT", name: "Nome" }],
          path: ["name"],
        },
      ],
      credential_metadata: {
        claims: [
          {
            display: [{ locale: "it-IT", name: "Nome" }],
            path: ["name"],
          },
        ],
        display: [{ locale: "it-IT", name: "Tessera Sanitaria" }],
      },
      credential_signing_alg_values_supported: ["ES256"],
      cryptographic_binding_methods_supported: ["did:example"],
      display: [{ locale: "it-IT", name: "Tessera Sanitaria" }],
      format: "dc+sd-jwt",
      proof_types_supported: {
        jwt: { proof_signing_alg_values_supported: ["ES256"] },
      },
      schema_id: "urn:id.gov.it:itWallet:schema:ts_ci:1.0",
      scope: "urn:id.gov.it:itWallet:issued_credential:ts_ci",
      vct: "urn:id.gov.it:itWallet:issued_credential:ts_ci",
    },
  },
  credential_endpoint: "https://issuer.example.it/credential",
  credential_hash_alg_supported: "SHA-256",
  credential_issuer: "https://issuer.example.it",
  deferred_credential_endpoint: "https://issuer.example.it/deferred",
  display: [{ locale: "it-IT", name: "Issuer Example" }],
  evidence_supported: ["vouch"],
  jwks: mockJwks,
  nonce_endpoint: "https://issuer.example.it/nonce",
  notification_endpoint: "https://issuer.example.it/notification",
  revocation_endpoint: "https://issuer.example.it/revocation",
  status_assertion_endpoint: "https://issuer.example.it/status-assertion",
  status_attestation_endpoint: "https://issuer.example.it/status-attestation",
  trust_frameworks_supported: ["it_wallet"],
};

const authorizationServerMetadata = {
  acr_values_supported: ["https://trust-anchor.eid-wallet.example.it/loa/low"],
  authorization_endpoint: "https://auth.example.it/authorize",
  authorization_signing_alg_values_supported: ["ES256"],
  client_attestation_pop_signing_alg_values_supported: ["ES256"],
  client_attestation_signing_alg_values_supported: ["ES256"],
  client_registration_types_supported: ["automatic"],
  code_challenge_methods_supported: ["S256"],
  dpop_signing_alg_values_supported: ["ES256"],
  grant_types_supported: ["authorization_code"],
  issuer: "https://auth.example.it",
  jwks: mockJwks,
  pushed_authorization_request_endpoint: "https://auth.example.it/par",
  request_object_signing_alg_values_supported: ["ES256"],
  require_signed_request_object: true,
  response_modes_supported: ["query"],
  response_types_supported: ["code"],
  scopes_supported: ["openid"],
  token_endpoint: "https://auth.example.it/token",
  token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"],
  token_endpoint_auth_signing_alg_values_supported: ["ES256"],
};

function base64UrlEncode(obj: unknown): string {
  const json = JSON.stringify(obj);
  return Buffer.from(json, "utf8").toString("base64url");
}

function buildFederationJwt(payload: Record<string, unknown>): string {
  const header = base64UrlEncode({ alg: "ES256", typ: "JWT" });
  const body = base64UrlEncode(payload);
  const signature = base64UrlEncode({ fake: "signature" });
  return `${header}.${body}.${signature}`;
}

// --- Tests ---

describe("fetchMetadata", () => {
  const baseOptions: FetchMetadataOptions = {
    callbacks: { fetch: mockFetch },
    credentialIssuerUrl: "https://issuer.example.it",
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should return normalised metadata when federation endpoint succeeds", async () => {
    const federationPayload = {
      exp: 1_700_003_600,
      iat: 1_700_000_000,
      iss: "https://issuer.example.it",
      jwks: mockJwks,
      metadata: {
        oauth_authorization_server: authorizationServerMetadata,
        openid_credential_issuer: credentialIssuerMetadata,
      },
      sub: "https://issuer.example.it",
    };

    mockFetch.mockResolvedValueOnce({
      status: 200,
      text: vi.fn().mockResolvedValue(buildFederationJwt(federationPayload)),
    });

    const result = await fetchMetadata(baseOptions);
    expect(result.discoveredVia).toBe("federation");
    expect(result.openid_federation_claims?.iss).toBe(
      "https://issuer.example.it",
    );
    expect(result.metadata.openid_credential_issuer?.credential_issuer).toBe(
      "https://issuer.example.it",
    );
    expect(result.metadata.oauth_authorization_server?.issuer).toBe(
      "https://auth.example.it",
    );
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockFetch).toHaveBeenCalledWith(
      "https://issuer.example.it/.well-known/openid-federation",
    );
  });

  it("should fall back to credential-issuer endpoint and fetch auth server when authorization_servers is present", async () => {
    const issuerWithAuthServers = {
      ...credentialIssuerMetadata,
      authorization_servers: ["https://auth.example.it"],
    };
    // Federation fails
    mockFetch.mockResolvedValueOnce({ status: 500 });
    // Credential issuer succeeds
    mockFetch.mockResolvedValueOnce({
      json: vi.fn().mockResolvedValue(issuerWithAuthServers),
      status: 200,
    });
    // Auth server succeeds
    mockFetch.mockResolvedValueOnce({
      json: vi.fn().mockResolvedValue(authorizationServerMetadata),
      status: 200,
    });

    const result = await fetchMetadata(baseOptions);
    expect(result.discoveredVia).toBe("oid4vci");
    expect(result.openid_federation_claims).toBeUndefined();
    expect(result.metadata.openid_credential_issuer?.credential_issuer).toBe(
      "https://issuer.example.it",
    );
    expect(result.metadata.oauth_authorization_server?.issuer).toBe(
      "https://auth.example.it",
    );
    expect(mockFetch).toHaveBeenCalledTimes(3);
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      "https://issuer.example.it/.well-known/openid-credential-issuer",
    );
    expect(mockFetch).toHaveBeenNthCalledWith(
      3,
      "https://auth.example.it/.well-known/oauth-authorization-server",
    );
  });

  it("should fall back and parse auth server inline when authorization_servers is absent", async () => {
    // Issuer acts as its own auth server: all auth-server claims are inline
    const issuerAsAuthServer = {
      ...credentialIssuerMetadata,
      ...authorizationServerMetadata,
    };

    // Federation fails
    mockFetch.mockResolvedValueOnce({ status: 404 });
    // Credential issuer succeeds (no authorization_servers)
    mockFetch.mockResolvedValueOnce({
      json: vi.fn().mockResolvedValue(issuerAsAuthServer),
      status: 200,
    });

    const result = await fetchMetadata(baseOptions);

    expect(result.discoveredVia).toBe("oid4vci");
    expect(result.openid_federation_claims).toBeUndefined();
    expect(result.metadata.openid_credential_issuer?.credential_issuer).toBe(
      "https://issuer.example.it",
    );
    expect(result.metadata.oauth_authorization_server?.issuer).toBe(
      "https://auth.example.it",
    );
    // Only federation + credential-issuer calls (no separate auth server fetch)
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("should fall back to credential-issuer when federation endpoint throws a network error", async () => {
    const issuerWithAuthServers = {
      ...credentialIssuerMetadata,
      authorization_servers: ["https://auth.example.it"],
    };

    mockFetch.mockRejectedValueOnce(new Error("Network error"));
    mockFetch.mockResolvedValueOnce({
      json: vi.fn().mockResolvedValue(issuerWithAuthServers),
      status: 200,
    });
    mockFetch.mockResolvedValueOnce({
      json: vi.fn().mockResolvedValue(authorizationServerMetadata),
      status: 200,
    });

    const result = await fetchMetadata(baseOptions);

    expect(result.discoveredVia).toBe("oid4vci");
    expect(result.openid_federation_claims).toBeUndefined();
    expect(result.metadata.openid_credential_issuer?.credential_issuer).toBe(
      "https://issuer.example.it",
    );
    expect(result.metadata.oauth_authorization_server?.issuer).toBe(
      "https://auth.example.it",
    );
  });

  it("should throw ValidationError when response does not match the schema", async () => {
    const invalidPayload = {
      exp: 1_700_003_600,
      iat: 1_700_000_000,
      iss: "https://issuer.example.it",
      jwks: mockJwks,
      metadata: {
        oauth_authorization_server: { invalid: true },
        openid_credential_issuer: { invalid: true },
      },
      sub: "https://issuer.example.it",
    };

    mockFetch.mockResolvedValueOnce({
      status: 200,
      text: vi.fn().mockResolvedValue(buildFederationJwt(invalidPayload)),
    });

    await expect(fetchMetadata(baseOptions)).rejects.toThrow(ValidationError);
  });

  it("should throw ValidationError when authorization_servers contains a non-HTTPS URL", async () => {
    const issuerWithHttpAuthServer = {
      ...credentialIssuerMetadata,
      authorization_servers: ["http://attacker.internal"],
    };

    // Federation fails
    mockFetch.mockResolvedValueOnce({ status: 500 });
    // Credential issuer succeeds with a malicious http:// authorization_servers entry
    mockFetch.mockResolvedValueOnce({
      json: vi.fn().mockResolvedValue(issuerWithHttpAuthServer),
      status: 200,
    });

    await expect(fetchMetadata(baseOptions)).rejects.toThrow(ValidationError);
    // No auth-server fetch should fire: federation + credential-issuer only
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("should throw FetchMetadataError on network error during fallback", async () => {
    // Federation fails
    mockFetch.mockResolvedValueOnce({ status: 500 });
    // Credential issuer network error
    mockFetch.mockRejectedValueOnce(new Error("Network failure"));

    await expect(fetchMetadata(baseOptions)).rejects.toThrow(
      FetchMetadataError,
    );
  });

  it("should throw ValidationError when credentialIssuerUrl is not a URL", async () => {
    await expect(
      fetchMetadata({ ...baseOptions, credentialIssuerUrl: "not-a-url" }),
    ).rejects.toThrow(ValidationError);

    expect(mockFetch).not.toHaveBeenCalled();
  });
});
