/* eslint-disable max-lines-per-function */
import { itWalletMetadataSchema } from "@pagopa/io-wallet-oid-federation";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CredentialOfferError, FetchMetadataError } from "../../errors";
import { FetchMetadataOptions, fetchMetadata } from "../fetch-metadata";
import {
  MetadataResponseV1_0,
  MetadataResponseV1_3,
  MetadataResponseV1_5,
  zMetadataResponse,
} from "../z-metadata-response";

const mockFetch = vi.fn();

vi.mock("@pagopa/io-wallet-utils", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-utils")>();
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

// v1.3 authorization server metadata (trust-anchor.eid-wallet URLs, dpop required)
const authorizationServerMetadataV1_3 = {
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

// Keep backward-compatible alias for existing tests
const authorizationServerMetadata = authorizationServerMetadataV1_3;

// v1.0 authorization server metadata (trust-registry.eid-wallet URLs, no dpop)
const authorizationServerMetadataV1_0 = {
  acr_values_supported: [
    "https://trust-registry.eid-wallet.example.it/loa/low",
  ],
  authorization_endpoint: "https://auth.example.it/authorize",
  authorization_signing_alg_values_supported: ["ES256"],
  client_registration_types_supported: ["automatic"],
  code_challenge_methods_supported: ["S256"],
  grant_types_supported: ["authorization_code"],
  issuer: "https://auth.example.it",
  jwks: mockJwks,
  pushed_authorization_request_endpoint: "https://auth.example.it/par",
  request_object_signing_alg_values_supported: ["ES256"],
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

// --- Configs ---

const configV1_3 = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
});

const configV1_0 = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
});

// --- Tests ---

const baseOptions: FetchMetadataOptions = {
  callbacks: { fetch: mockFetch },
  config: configV1_3,
  credentialIssuerUrl: "https://issuer.example.it",
};

const baseOptionsV1_0: FetchMetadataOptions = {
  callbacks: { fetch: mockFetch },
  config: configV1_0,
  credentialIssuerUrl: "https://issuer.example.it",
};

beforeEach(() => {
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

describe("fetchMetadata", () => {
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
    expect((result as MetadataResponseV1_3).openid_federation_claims?.iss).toBe(
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
    expect(
      (result as MetadataResponseV1_3).openid_federation_claims,
    ).toBeUndefined();
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
    expect(
      (result as MetadataResponseV1_3).openid_federation_claims,
    ).toBeUndefined();
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
    expect(
      (result as MetadataResponseV1_3).openid_federation_claims,
    ).toBeUndefined();
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

describe("fetchMetadata - v1.0", () => {
  it("should return MetadataResponseV1_0 with discoveredVia federation on success", async () => {
    const federationPayload = {
      exp: 1_700_003_600,
      iat: 1_700_000_000,
      iss: "https://issuer.example.it",
      jwks: mockJwks,
      metadata: {
        oauth_authorization_server: authorizationServerMetadataV1_0,
        openid_credential_issuer: credentialIssuerMetadata,
      },
      sub: "https://issuer.example.it",
    };

    mockFetch.mockResolvedValueOnce({
      status: 200,
      text: vi.fn().mockResolvedValue(buildFederationJwt(federationPayload)),
    });

    const result = await fetchMetadata(baseOptionsV1_0);
    expect(result.discoveredVia).toBe("federation");
    expect((result as MetadataResponseV1_0).openid_federation_claims?.iss).toBe(
      "https://issuer.example.it",
    );
    expect(result.metadata.oauth_authorization_server?.issuer).toBe(
      "https://auth.example.it",
    );
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockFetch).toHaveBeenCalledWith(
      "https://issuer.example.it/.well-known/openid-federation",
    );

    const calledUrls = mockFetch.mock.calls.map(
      (call) => (call as [string])[0],
    );
    expect(
      calledUrls.some((url) => url.includes("openid-credential-issuer")),
    ).toBe(false);
  });

  it("should throw FetchMetadataError when federation returns non-200 for v1.0", async () => {
    mockFetch.mockResolvedValueOnce({
      headers: new Headers(),
      status: 404,
      text: vi.fn().mockResolvedValue("Not Found"),
      url: "https://issuer.example.it/.well-known/openid-federation",
    });

    await expect(fetchMetadata(baseOptionsV1_0)).rejects.toThrow(
      FetchMetadataError,
    );
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("should throw ValidationError when federation entity statement has invalid schema for v1.0", async () => {
    // Valid JWT structure, but payload fails itWalletEntityStatementClaimsSchema validation
    const invalidEntityStatementPayload = {
      // Missing required fields like 'iss', 'sub', 'iat', 'exp', 'jwks', 'metadata'
      invalid_field: "this is not a valid entity statement",
    };

    mockFetch.mockResolvedValueOnce({
      status: 200,
      text: vi
        .fn()
        .mockResolvedValue(buildFederationJwt(invalidEntityStatementPayload)),
    });

    await expect(fetchMetadata(baseOptionsV1_0)).rejects.toThrow(
      ValidationError,
    );
  });

  it("should throw ValidationError when federation returns v1.3 metadata shape for v1.0", async () => {
    // v1.3 metadata has trust-anchor.eid-wallet ACR URLs and dpop_signing_alg_values_supported
    const federationPayload = {
      exp: 1_700_003_600,
      iat: 1_700_000_000,
      iss: "https://issuer.example.it",
      jwks: mockJwks,
      metadata: {
        oauth_authorization_server: authorizationServerMetadataV1_3,
        openid_credential_issuer: credentialIssuerMetadata,
      },
      sub: "https://issuer.example.it",
    };

    mockFetch.mockResolvedValueOnce({
      status: 200,
      text: vi.fn().mockResolvedValue(buildFederationJwt(federationPayload)),
    });

    await expect(fetchMetadata(baseOptionsV1_0)).rejects.toThrow(
      ValidationError,
    );
  });
});

describe("fetchMetadata - v1.3 rejects v1.0 metadata", () => {
  it("should throw ValidationError when federation returns v1.0 metadata shape for v1.3", async () => {
    // v1.0 metadata uses trust-registry.eid-wallet ACR URLs, no dpop
    const federationPayload = {
      exp: 1_700_003_600,
      iat: 1_700_000_000,
      iss: "https://issuer.example.it",
      jwks: mockJwks,
      metadata: {
        oauth_authorization_server: authorizationServerMetadataV1_0,
        openid_credential_issuer: credentialIssuerMetadata,
      },
      sub: "https://issuer.example.it",
    };

    mockFetch.mockResolvedValueOnce({
      status: 200,
      text: vi.fn().mockResolvedValue(buildFederationJwt(federationPayload)),
    });

    await expect(fetchMetadata(baseOptions)).rejects.toThrow(ValidationError);
  });
});

describe("fetchMetadata - base URL with path segment", () => {
  const pathBaseOptions: FetchMetadataOptions = {
    callbacks: { fetch: mockFetch },
    config: configV1_3,
    credentialIssuerUrl: "https://issuer.example.it/v1",
  };

  it("should call federation endpoint preserving base URL path segment", async () => {
    const federationPayload = {
      exp: 1_700_003_600,
      iat: 1_700_000_000,
      iss: "https://issuer.example.it/v1",
      jwks: mockJwks,
      metadata: {
        oauth_authorization_server: authorizationServerMetadata,
        openid_credential_issuer: {
          ...credentialIssuerMetadata,
          credential_issuer: "https://issuer.example.it/v1",
        },
      },
      sub: "https://issuer.example.it/v1",
    };

    mockFetch.mockResolvedValueOnce({
      status: 200,
      text: vi.fn().mockResolvedValue(buildFederationJwt(federationPayload)),
    });

    await fetchMetadata(pathBaseOptions);

    expect(mockFetch).toHaveBeenCalledWith(
      "https://issuer.example.it/v1/.well-known/openid-federation",
    );
  });

  it("should call credential-issuer endpoint preserving base URL path segment", async () => {
    const issuerWithAuthServers = {
      ...credentialIssuerMetadata,
      authorization_servers: ["https://auth.example.it/v1"],
      credential_issuer: "https://issuer.example.it/v1",
    };

    // Federation fails
    mockFetch.mockResolvedValueOnce({ status: 404 });
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

    await fetchMetadata(pathBaseOptions);

    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      "https://issuer.example.it/v1/.well-known/openid-credential-issuer",
    );
    expect(mockFetch).toHaveBeenNthCalledWith(
      3,
      "https://auth.example.it/v1/.well-known/oauth-authorization-server",
    );
  });
});

describe("fetchMetadata - offer authorization server compatibility", () => {
  describe("oid4vci fallback path", () => {
    it("should fetch the selected authorization server when it is in the issuer's authorization_servers list", async () => {
      const issuerWithAuthServers = {
        ...credentialIssuerMetadata,
        authorization_servers: [
          "https://auth.example.it",
          "https://other.example.it",
        ],
      };

      // Federation fails
      mockFetch.mockResolvedValueOnce({ status: 500 });
      // Credential issuer succeeds
      mockFetch.mockResolvedValueOnce({
        json: vi.fn().mockResolvedValue(issuerWithAuthServers),
        status: 200,
      });
      // Selected auth server succeeds
      mockFetch.mockResolvedValueOnce({
        json: vi.fn().mockResolvedValue(authorizationServerMetadata),
        status: 200,
      });

      const result = await fetchMetadata({
        ...baseOptions,
        authorizationServer: "https://auth.example.it",
      });

      expect(result.discoveredVia).toBe("oid4vci");
      expect(result.metadata.oauth_authorization_server?.issuer).toBe(
        "https://auth.example.it",
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        3,
        "https://auth.example.it/.well-known/oauth-authorization-server",
      );
    });

    it("should throw CredentialOfferError when the selected authorization server is not in the issuer's list", async () => {
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

      await expect(
        fetchMetadata({
          ...baseOptions,
          authorizationServer: "https://attacker.example.it",
        }),
      ).rejects.toThrow(CredentialOfferError);
      // No auth-server fetch should fire: federation + credential-issuer only
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it("should throw CredentialOfferError when an authorization server is selected but the issuer declares none", async () => {
      // Federation fails
      mockFetch.mockResolvedValueOnce({ status: 500 });
      // Credential issuer succeeds without an authorization_servers list
      mockFetch.mockResolvedValueOnce({
        json: vi.fn().mockResolvedValue(credentialIssuerMetadata),
        status: 200,
      });

      await expect(
        fetchMetadata({
          ...baseOptions,
          authorizationServer: "https://auth.example.it",
        }),
      ).rejects.toThrow(CredentialOfferError);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  // A co-located issuer attests its own authorization server inline, with an
  // issuer value equal to the Credential Issuer identifier.
  const coLocatedAuthorizationServerMetadata = {
    ...authorizationServerMetadata,
    issuer: "https://issuer.example.it",
  };

  describe("federation path", () => {
    it("should not perform a secondary fetch when the offer selects the credential issuer itself", async () => {
      const federationPayload = {
        exp: 1_700_003_600,
        iat: 1_700_000_000,
        iss: "https://issuer.example.it",
        jwks: mockJwks,
        metadata: {
          oauth_authorization_server: coLocatedAuthorizationServerMetadata,
          openid_credential_issuer: {
            ...credentialIssuerMetadata,
            authorization_servers: [
              "https://issuer.example.it",
              "https://as2.example.it",
            ],
          },
        },
        sub: "https://issuer.example.it",
      };

      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: vi.fn().mockResolvedValue(buildFederationJwt(federationPayload)),
      });

      const result = await fetchMetadata({
        ...baseOptions,
        authorizationServer: "https://issuer.example.it",
      });

      expect(result.discoveredVia).toBe("federation");
      expect(result.metadata.oauth_authorization_server?.issuer).toBe(
        "https://issuer.example.it",
      );
      // Selected AS is the credential issuer itself: no secondary fetch
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("should resolve a non-inline authorization server via federation when it is in the issuer's list", async () => {
      const issuerFederationPayload = {
        exp: 1_700_003_600,
        iat: 1_700_000_000,
        iss: "https://issuer.example.it",
        jwks: mockJwks,
        metadata: {
          // Inline AS differs from the selected one
          oauth_authorization_server: authorizationServerMetadata,
          openid_credential_issuer: {
            ...credentialIssuerMetadata,
            authorization_servers: [
              "https://issuer.example.it",
              "https://as2.example.it",
            ],
          },
        },
        sub: "https://issuer.example.it",
      };
      const authorizationServerFederationPayload = {
        exp: 1_700_003_600,
        iat: 1_700_000_000,
        iss: "https://as2.example.it",
        jwks: mockJwks,
        metadata: {
          oauth_authorization_server: {
            ...authorizationServerMetadata,
            issuer: "https://as2.example.it",
          },
        },
        sub: "https://as2.example.it",
      };

      // Issuer federation succeeds
      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: vi
          .fn()
          .mockResolvedValue(buildFederationJwt(issuerFederationPayload)),
      });
      // Selected authorization server federation succeeds
      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: vi
          .fn()
          .mockResolvedValue(
            buildFederationJwt(authorizationServerFederationPayload),
          ),
      });

      const result = await fetchMetadata({
        ...baseOptions,
        authorizationServer: "https://as2.example.it",
      });

      expect(result.discoveredVia).toBe("federation");
      // The issuer's inline oauth_authorization_server is retained; the selected
      // server is surfaced only through authorization_server_federation_claims.
      expect(result.metadata.oauth_authorization_server?.issuer).toBe(
        "https://auth.example.it",
      );
      // The selected authorization server's federation entity statement is
      // present and carries its own well-formed claims.
      const authorizationServerFederationClaims = (
        result as MetadataResponseV1_3
      ).authorization_server_federation_claims;
      expect(authorizationServerFederationClaims).toBeDefined();
      expect(authorizationServerFederationClaims?.iss).toBe(
        "https://as2.example.it",
      );
      expect(authorizationServerFederationClaims?.sub).toBe(
        "https://as2.example.it",
      );
      expect(authorizationServerFederationClaims?.jwks.keys).toHaveLength(1);
      expect(
        authorizationServerFederationClaims?.metadata
          ?.oauth_authorization_server?.issuer,
      ).toBe("https://as2.example.it");
      expect(mockFetch).toHaveBeenCalledTimes(2);
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        "https://as2.example.it/.well-known/openid-federation",
      );
    });

    it("should throw CredentialOfferError when a non-inline authorization server is not in the issuer's list", async () => {
      const federationPayload = {
        exp: 1_700_003_600,
        iat: 1_700_000_000,
        iss: "https://issuer.example.it",
        jwks: mockJwks,
        metadata: {
          oauth_authorization_server: authorizationServerMetadata,
          openid_credential_issuer: {
            ...credentialIssuerMetadata,
            authorization_servers: ["https://auth.example.it"],
          },
        },
        sub: "https://issuer.example.it",
      };

      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: vi.fn().mockResolvedValue(buildFederationJwt(federationPayload)),
      });

      await expect(
        fetchMetadata({
          ...baseOptions,
          authorizationServer: "https://attacker.example.it",
        }),
      ).rejects.toThrow(CredentialOfferError);
      // No secondary federation fetch for the rejected authorization server
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("should throw CredentialOfferError when a non-inline authorization server is selected but the issuer declares none", async () => {
      const federationPayload = {
        exp: 1_700_003_600,
        iat: 1_700_000_000,
        iss: "https://issuer.example.it",
        jwks: mockJwks,
        metadata: {
          oauth_authorization_server: authorizationServerMetadata,
          // No authorization_servers declared on the credential issuer
          openid_credential_issuer: credentialIssuerMetadata,
        },
        sub: "https://issuer.example.it",
      };

      mockFetch.mockResolvedValueOnce({
        status: 200,
        text: vi.fn().mockResolvedValue(buildFederationJwt(federationPayload)),
      });

      await expect(
        fetchMetadata({
          ...baseOptions,
          authorizationServer: "https://other.example.it",
        }),
      ).rejects.toThrow(CredentialOfferError);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    describe("without an offer-selected authorization server", () => {
      it("should not perform a secondary fetch when the issuer lists itself", async () => {
        const federationPayload = {
          exp: 1_700_003_600,
          iat: 1_700_000_000,
          iss: "https://issuer.example.it",
          jwks: mockJwks,
          metadata: {
            oauth_authorization_server: coLocatedAuthorizationServerMetadata,
            openid_credential_issuer: {
              ...credentialIssuerMetadata,
              authorization_servers: [
                "https://as2.example.it",
                "https://issuer.example.it",
              ],
            },
          },
          sub: "https://issuer.example.it",
        };

        mockFetch.mockResolvedValueOnce({
          status: 200,
          text: vi
            .fn()
            .mockResolvedValue(buildFederationJwt(federationPayload)),
        });

        const result = await fetchMetadata(baseOptions);

        expect(result.discoveredVia).toBe("federation");
        expect(result.metadata.oauth_authorization_server?.issuer).toBe(
          "https://issuer.example.it",
        );
        // Credential issuer is one of the declared servers: no secondary fetch
        expect(mockFetch).toHaveBeenCalledTimes(1);
      });

      it("should resolve the first declared server when the issuer does not list itself", async () => {
        const issuerFederationPayload = {
          exp: 1_700_003_600,
          iat: 1_700_000_000,
          iss: "https://issuer.example.it",
          jwks: mockJwks,
          metadata: {
            // Inline block present and retained on the result even though the
            // issuer is not among the declared servers; the selected server is
            // resolved separately via federation.
            oauth_authorization_server: authorizationServerMetadata,
            openid_credential_issuer: {
              ...credentialIssuerMetadata,
              authorization_servers: ["https://as2.example.it"],
            },
          },
          sub: "https://issuer.example.it",
        };
        const authorizationServerFederationPayload = {
          exp: 1_700_003_600,
          iat: 1_700_000_000,
          iss: "https://as2.example.it",
          jwks: mockJwks,
          metadata: {
            oauth_authorization_server: {
              ...authorizationServerMetadata,
              issuer: "https://as2.example.it",
            },
          },
          sub: "https://as2.example.it",
        };

        mockFetch.mockResolvedValueOnce({
          status: 200,
          text: vi
            .fn()
            .mockResolvedValue(buildFederationJwt(issuerFederationPayload)),
        });
        mockFetch.mockResolvedValueOnce({
          status: 200,
          text: vi
            .fn()
            .mockResolvedValue(
              buildFederationJwt(authorizationServerFederationPayload),
            ),
        });

        const result = await fetchMetadata(baseOptions);

        expect(result.discoveredVia).toBe("federation");
        // The issuer's inline oauth_authorization_server is retained even when
        // the selected server is resolved separately via federation.
        expect(result.metadata.oauth_authorization_server?.issuer).toBe(
          "https://auth.example.it",
        );
        expect(mockFetch).toHaveBeenCalledTimes(2);
        expect(mockFetch).toHaveBeenNthCalledWith(
          2,
          "https://as2.example.it/.well-known/openid-federation",
        );
      });
    });
  });
});

describe("fetchMetadata - verifyJwt callback", () => {
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

  it("should succeed when verifyJwt callback returns verified: true", async () => {
    const verifyJwt = vi.fn().mockResolvedValue({ verified: true });
    mockFetch.mockResolvedValueOnce({
      status: 200,
      text: vi.fn().mockResolvedValue(buildFederationJwt(federationPayload)),
    });

    const result = await fetchMetadata({
      ...baseOptions,
      callbacks: { ...baseOptions.callbacks, verifyJwt },
    });

    expect(result.discoveredVia).toBe("federation");
    expect(verifyJwt).toHaveBeenCalledOnce();
    const [jwtSigner] = verifyJwt.mock.calls[0] as [
      { alg: string; kid: string; method: string },
      unknown,
    ];
    expect(jwtSigner.method).toBe("federation");
    expect(jwtSigner.alg).toBe("ES256");
  });

  it("should throw ValidationError when verifyJwt callback returns verified: false", async () => {
    const verifyJwt = vi.fn().mockResolvedValue({ verified: false });
    mockFetch.mockResolvedValueOnce({
      status: 200,
      text: vi.fn().mockResolvedValue(buildFederationJwt(federationPayload)),
    });

    await expect(
      fetchMetadata({
        ...baseOptions,
        callbacks: { ...baseOptions.callbacks, verifyJwt },
      }),
    ).rejects.toThrow(ValidationError);
  });
});

describe("fetchMetadata - v1.5 signed metadata", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  const configV1_5 = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_5,
  });
  const issuerInfo = [
    { data: "eyJ...WRPRC", format: "registration_cert" },
    { data: { identifier: [] }, format: "registrar_dataset" },
  ];
  const signedPayload = {
    ...credentialIssuerMetadata,
    authorization_servers: ["https://auth.example.it"],
    iat: 1_700_000_000,
    iss: "https://issuer.example.it",
    issuer_info: issuerInfo,
    sub: "https://issuer.example.it",
  };
  const signedHeader = {
    alg: "ES256",
    typ: "openidvci-issuer-metadata+jwt",
    x5c: ["MIIB...leaf"],
  };

  const buildSignedMetadata = (
    header: Record<string, unknown> = signedHeader,
    payload: Record<string, unknown> = signedPayload,
  ) =>
    `${base64UrlEncode(header)}.${base64UrlEncode(payload)}.${base64UrlEncode({ fake: "signature" })}`;

  const mockResponses = (
    signedMetadata = buildSignedMetadata(),
    authServer: Record<string, unknown> = authorizationServerMetadata,
  ) => {
    mockFetch
      .mockResolvedValueOnce({
        status: 200,
        text: vi.fn().mockResolvedValue(signedMetadata),
      })
      .mockResolvedValueOnce({
        json: vi.fn().mockResolvedValue(authServer),
        status: 200,
      });
  };

  const optionsV1_5 = (
    verifyJwt = vi.fn().mockResolvedValue({ verified: true }),
  ): FetchMetadataOptions => ({
    callbacks: { fetch: mockFetch, verifyJwt },
    config: configV1_5,
    credentialIssuerUrl: "https://issuer.example.it",
  });

  it("should return verified metadata with signed_metadata and x5c", async () => {
    const verifyJwt = vi.fn().mockResolvedValue({ verified: true });
    const signedMetadata = buildSignedMetadata();
    mockResponses(signedMetadata);

    const result = (await fetchMetadata(
      optionsV1_5(verifyJwt),
    )) as MetadataResponseV1_5;

    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      "https://issuer.example.it/.well-known/openid-credential-issuer",
      { headers: { Accept: "application/jwt" } },
    );
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      "https://auth.example.it/.well-known/oauth-authorization-server",
    );
    expect(verifyJwt).toHaveBeenCalledWith(
      { alg: "ES256", method: "x5c", x5c: ["MIIB...leaf"] },
      expect.objectContaining({ compact: signedMetadata }),
    );
    expect(result.discoveredVia).toBe("oid4vci");
    expect(result.signed_metadata).toBe(signedMetadata);
    expect(result.x5c).toEqual(["MIIB...leaf"]);
    expect(result.metadata.openid_credential_issuer?.issuer_info).toEqual(
      issuerInfo,
    );
    expect(result.metadata.oauth_authorization_server?.issuer).toBe(
      "https://auth.example.it",
    );
  });

  it.each([
    [
      "parent_credentials only",
      { parent_credentials: ["urn:eudi:pid:it:1"] },
      true,
    ],
    ["neither authentic_sources nor parent_credentials", {}, false],
  ])(
    "should handle a credential configuration with %s",
    async (_, sourceFields, isValid) => {
      const [configId, config] = Object.entries(
        credentialIssuerMetadata.credential_configurations_supported,
      )[0] as [string, Record<string, unknown>];
      const configWithoutSources = { ...config };
      delete configWithoutSources.authentic_sources;
      mockResponses(
        buildSignedMetadata(signedHeader, {
          ...signedPayload,
          credential_configurations_supported: {
            [configId]: { ...configWithoutSources, ...sourceFields },
          },
        }),
      );

      const result = fetchMetadata(optionsV1_5());

      if (isValid) {
        await expect(result).resolves.toBeDefined();
      } else {
        await expect(result).rejects.toThrow();
      }
    },
  );

  it("should insert the well-known segment before path-based issuer and AS identifiers", async () => {
    const issuer = "https://issuer.example.it/tenant";
    const authServer = "https://auth.example.it/tenant";
    mockResponses(
      buildSignedMetadata(signedHeader, {
        ...signedPayload,
        authorization_servers: [authServer],
        credential_issuer: issuer,
        sub: issuer,
      }),
      { ...authorizationServerMetadata, issuer: authServer },
    );

    await fetchMetadata({ ...optionsV1_5(), credentialIssuerUrl: issuer });

    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      "https://issuer.example.it/.well-known/openid-credential-issuer/tenant",
      { headers: { Accept: "application/jwt" } },
    );
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      "https://auth.example.it/.well-known/oauth-authorization-server/tenant",
    );
  });

  it("should keep signed_metadata and x5c when parsed with zMetadataResponse", async () => {
    const signedMetadata = buildSignedMetadata();
    mockResponses(signedMetadata);

    const parsed = zMetadataResponse.parse(
      await fetchMetadata(optionsV1_5()),
    ) as MetadataResponseV1_5;

    expect(parsed.signed_metadata).toBe(signedMetadata);
    expect(parsed.x5c).toEqual(["MIIB...leaf"]);
  });

  it("should throw when verifyJwt is not provided", async () => {
    await expect(
      fetchMetadata({ ...optionsV1_5(), callbacks: { fetch: mockFetch } }),
    ).rejects.toThrow(ValidationError);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it.each([
    ["typ is wrong", { ...signedHeader, typ: "JWT" }],
    ["x5c is missing", { alg: "ES256", typ: signedHeader.typ }],
    ["alg is a MAC algorithm", { ...signedHeader, alg: "HS256" }],
  ])("should throw when %s", async (_, header) => {
    const verifyJwt = vi.fn();
    mockResponses(buildSignedMetadata(header));

    await expect(fetchMetadata(optionsV1_5(verifyJwt))).rejects.toThrow();
    expect(verifyJwt).not.toHaveBeenCalled();
  });

  it.each([
    ["sub", { ...signedPayload, sub: "https://other.example.it" }],
    [
      "credential_issuer",
      { ...signedPayload, credential_issuer: "https://other.example.it" },
    ],
  ])(
    "should throw ValidationError when %s differs from the requested issuer",
    async (_, payload) => {
      mockResponses(buildSignedMetadata(signedHeader, payload));

      await expect(fetchMetadata(optionsV1_5())).rejects.toThrow(
        ValidationError,
      );
    },
  );

  it.each([
    ["expired", { exp: Math.floor(Date.now() / 1000) - 60 }, /expired/],
    [
      "not yet valid",
      { nbf: Math.floor(Date.now() / 1000) + 3600 },
      /not yet valid/,
    ],
  ])(
    "should throw ValidationError when signed metadata is %s",
    async (_, claims, message) => {
      const verifyJwt = vi.fn();
      mockResponses(
        buildSignedMetadata(signedHeader, { ...signedPayload, ...claims }),
      );

      await expect(fetchMetadata(optionsV1_5(verifyJwt))).rejects.toThrow(
        message,
      );
      expect(verifyJwt).not.toHaveBeenCalled();
    },
  );

  it("should throw ValidationError when signature verification fails", async () => {
    mockResponses();

    await expect(
      fetchMetadata(
        optionsV1_5(vi.fn().mockResolvedValue({ verified: false })),
      ),
    ).rejects.toThrow(ValidationError);
    expect(mockFetch).toHaveBeenCalledOnce();
  });

  it("should throw CredentialOfferError when the selected authorization server is not declared", async () => {
    mockResponses();

    await expect(
      fetchMetadata({
        ...optionsV1_5(),
        authorizationServer: "https://evil.example.it",
      }),
    ).rejects.toThrow(CredentialOfferError);
  });

  it("should throw ValidationError when the authorization server issuer does not match", async () => {
    mockResponses(buildSignedMetadata(), {
      ...authorizationServerMetadata,
      issuer: "https://evil.example.it",
    });

    await expect(fetchMetadata(optionsV1_5())).rejects.toThrow(ValidationError);
  });
});

describe("itWalletMetadataSchema - v1.5 credential configurations", () => {
  const [configId, config] = Object.entries(
    credentialIssuerMetadata.credential_configurations_supported,
  )[0] as [string, Record<string, unknown>];
  const parentCredentials = ["urn:eudi:pid:it:1"];

  it("should accept a configuration with only parent_credentials", () => {
    const configWithoutSources = { ...config };
    delete configWithoutSources.authentic_sources;

    const parsed = itWalletMetadataSchema.parse({
      openid_credential_issuer: {
        ...credentialIssuerMetadata,
        credential_configurations_supported: {
          [configId]: {
            ...configWithoutSources,
            parent_credentials: parentCredentials,
          },
        },
      },
    });

    expect(
      parsed.openid_credential_issuer?.credential_configurations_supported[
        configId
      ],
    ).toMatchObject({ parent_credentials: parentCredentials });
  });

  it("should keep parent_credentials when authentic_sources is also present", () => {
    const parsed = itWalletMetadataSchema.parse({
      openid_credential_issuer: {
        ...credentialIssuerMetadata,
        credential_configurations_supported: {
          [configId]: { ...config, parent_credentials: parentCredentials },
        },
      },
    });

    expect(
      parsed.openid_credential_issuer?.credential_configurations_supported[
        configId
      ],
    ).toMatchObject({ parent_credentials: parentCredentials });
  });
});
