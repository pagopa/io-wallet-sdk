/* eslint-disable max-lines-per-function */
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  RequestLike,
} from "@pagopa/io-wallet-utils";
import { describe, expect, it } from "vitest";

import { Oauth2Error } from "../../errors";
import { preAuthorizedCodeGrantIdentifier } from "../APTITUDE/z-grant-types";
import { parseAccessTokenRequest } from "../parse-token-request";

const VALID_DPOP_JWT =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NDQ5OTk5OTksImp0aSI6InRlc3QtanRpIn0.signature";

const VALID_CLIENT_ATTESTATION_JWT =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.signature";

const VALID_CLIENT_ATTESTATION_POP_JWT =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.pop-signature";

function createMockRequest(headers?: Headers): RequestLike {
  return {
    headers: headers || new Headers(),
    method: "POST",
    url: "https://issuer.example.com/token",
  };
}

function createValidHeaders(): Headers {
  const headers = new Headers();
  headers.set("DPoP", VALID_DPOP_JWT);
  headers.set("OAuth-Client-Attestation", VALID_CLIENT_ATTESTATION_JWT);
  headers.set("OAuth-Client-Attestation-PoP", VALID_CLIENT_ATTESTATION_POP_JWT);
  return headers;
}

const v1_4Config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_4,
});

const aptitudeConfig = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.APTITUDE,
});

describe("parseAccessTokenRequest", () => {
  describe("Authorization code grant", () => {
    it("should parse valid authorization code grant request", () => {
      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        config: v1_4Config,
        request: createMockRequest(createValidHeaders()),
      });

      expect(result.accessTokenRequest).toEqual(accessTokenRequest);
      expect(result.grant).toEqual({
        code: "test-auth-code",
        grantType: "authorization_code",
      });
      expect(result.pkceCodeVerifier).toBe("test-code-verifier");
      expect(result.dpop.jwt).toBe(VALID_DPOP_JWT);
      expect(result.clientAttestation.walletAttestationJwt).toBe(
        VALID_CLIENT_ATTESTATION_JWT,
      );
      expect(result.clientAttestation.clientAttestationPopJwt).toBe(
        VALID_CLIENT_ATTESTATION_POP_JWT,
      );
    });

    it("should throw error when code is missing for authorization_code grant", () => {
      const accessTokenRequest = {
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow("Access token request validation failed");
    });

    it("should throw error when code_verifier is missing for authorization_code grant", () => {
      const accessTokenRequest = {
        code: "test-auth-code",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow("Access token request validation failed");
    });

    it("should throw error when redirect_uri is missing for authorization_code grant", () => {
      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow("Access token request validation failed");
    });

    it("should strip scope field when present for authorization_code grant", () => {
      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
        scope: "openid profile",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        config: v1_4Config,
        request: createMockRequest(createValidHeaders()),
      });

      // The scope field should be stripped from the validated request
      expect(result.accessTokenRequest).not.toHaveProperty("scope");
      expect(result.accessTokenRequest).toEqual({
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      });
    });
  });

  describe("Pre-authorized code grant", () => {
    it.each([undefined, "001234", "A+%&= code"])(
      "parses a pre-authorized request with transaction code %s without requiring PKCE",
      (txCode) => {
        const accessTokenRequest = {
          grant_type: preAuthorizedCodeGrantIdentifier,
          "pre-authorized_code": "opaque%2F+&= code",
          tx_code: txCode,
        };

        const result = parseAccessTokenRequest({
          accessTokenRequest,
          config: aptitudeConfig,
          request: createMockRequest(createValidHeaders()),
        });

        expect(result.accessTokenRequest).toEqual(accessTokenRequest);
        expect(result.grant).toEqual({
          grantType: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          preAuthorizedCode: "opaque%2F+&= code",
          txCode,
        });
        expect("pkceCodeVerifier" in result).toBe(false);
        expect(result.dpop.jwt).toBe(VALID_DPOP_JWT);
        expect(result.clientAttestation).toEqual({
          clientAttestationPopJwt: VALID_CLIENT_ATTESTATION_POP_JWT,
          walletAttestationJwt: VALID_CLIENT_ATTESTATION_JWT,
        });
      },
    );

    it.each([undefined, "", null, 123456])(
      "rejects a missing, empty or non-string pre-authorized code: %s",
      (code) => {
        expect(() =>
          parseAccessTokenRequest({
            accessTokenRequest: {
              grant_type: preAuthorizedCodeGrantIdentifier,
              "pre-authorized_code": code,
            },
            config: aptitudeConfig,
            request: createMockRequest(createValidHeaders()),
          }),
        ).toThrow("Access token request validation failed");
      },
    );

    it.each([123456, null, { length: 6 }])(
      "rejects a non-string transaction code: %s",
      (txCode) => {
        expect(() =>
          parseAccessTokenRequest({
            accessTokenRequest: {
              grant_type: preAuthorizedCodeGrantIdentifier,
              "pre-authorized_code": "issuer-code",
              tx_code: txCode,
            },
            config: aptitudeConfig,
            request: createMockRequest(createValidHeaders()),
          }),
        ).toThrow("Access token request validation failed");
      },
    );

    it("does not interpret authorization-code parameters as pre-authorized parameters", () => {
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest: {
            code: "authorization-code",
            code_verifier: "verifier",
            grant_type: preAuthorizedCodeGrantIdentifier,
            redirect_uri: "https://wallet.example.com/callback",
          },
          config: aptitudeConfig,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow("Access token request validation failed");
    });

    it.each([
      "DPoP",
      "OAuth-Client-Attestation",
      "OAuth-Client-Attestation-PoP",
    ])(
      "still requires the %s header for pre-authorized requests",
      (headerName) => {
        const headers = createValidHeaders();
        headers.delete(headerName);

        expect(() =>
          parseAccessTokenRequest({
            accessTokenRequest: {
              grant_type: preAuthorizedCodeGrantIdentifier,
              "pre-authorized_code": "issuer-code",
            },
            config: aptitudeConfig,
            request: createMockRequest(headers),
          }),
        ).toThrow(Oauth2Error);
      },
    );
  });

  describe("Refresh token grant", () => {
    it("should parse valid refresh token grant request", () => {
      const accessTokenRequest = {
        grant_type: "refresh_token",
        refresh_token: "test-refresh-token",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        config: v1_4Config,
        request: createMockRequest(createValidHeaders()),
      });

      expect(result.accessTokenRequest).toEqual(accessTokenRequest);
      expect(result.grant).toEqual({
        grantType: "refresh_token",
        refreshToken: "test-refresh-token",
      });
      expect(result.pkceCodeVerifier).toBeUndefined();
      expect(result.dpop.jwt).toBe(VALID_DPOP_JWT);
      expect(result.clientAttestation.walletAttestationJwt).toBe(
        VALID_CLIENT_ATTESTATION_JWT,
      );
      expect(result.clientAttestation.clientAttestationPopJwt).toBe(
        VALID_CLIENT_ATTESTATION_POP_JWT,
      );
    });

    it("should parse refresh token grant request with optional scope", () => {
      const accessTokenRequest = {
        grant_type: "refresh_token",
        refresh_token: "test-refresh-token",
        scope: "openid profile",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        config: v1_4Config,
        request: createMockRequest(createValidHeaders()),
      });

      expect(result.accessTokenRequest).toEqual(accessTokenRequest);
      expect(result.grant).toEqual({
        grantType: "refresh_token",
        refreshToken: "test-refresh-token",
      });
    });

    it("should throw error when refresh_token is missing for refresh_token grant", () => {
      const accessTokenRequest = {
        grant_type: "refresh_token",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow("Access token request validation failed");
    });

    it("should strip code field when present for refresh_token grant", () => {
      const accessTokenRequest = {
        code: "test-auth-code",
        grant_type: "refresh_token",
        refresh_token: "test-refresh-token",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        config: v1_4Config,
        request: createMockRequest(createValidHeaders()),
      });

      // The code field should be stripped from the validated request
      expect(result.accessTokenRequest).not.toHaveProperty("code");
      expect(result.accessTokenRequest).toEqual({
        grant_type: "refresh_token",
        refresh_token: "test-refresh-token",
      });
    });

    it("should strip code_verifier field when present for refresh_token grant", () => {
      const accessTokenRequest = {
        code_verifier: "test-code-verifier",
        grant_type: "refresh_token",
        refresh_token: "test-refresh-token",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        config: v1_4Config,
        request: createMockRequest(createValidHeaders()),
      });

      // The code_verifier field should be stripped from the validated request
      expect(result.accessTokenRequest).not.toHaveProperty("code_verifier");
      expect(result.accessTokenRequest).toEqual({
        grant_type: "refresh_token",
        refresh_token: "test-refresh-token",
      });
    });

    it("should strip redirect_uri field when present for refresh_token grant", () => {
      const accessTokenRequest = {
        grant_type: "refresh_token",
        redirect_uri: "https://client.example.com/callback",
        refresh_token: "test-refresh-token",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        config: v1_4Config,
        request: createMockRequest(createValidHeaders()),
      });

      // The redirect_uri field should be stripped from the validated request
      expect(result.accessTokenRequest).not.toHaveProperty("redirect_uri");
      expect(result.accessTokenRequest).toEqual({
        grant_type: "refresh_token",
        refresh_token: "test-refresh-token",
      });
    });
  });

  describe("Grant type validation", () => {
    it("should throw error for missing grant_type", () => {
      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow("Access token request validation failed");
    });

    it("should throw error for invalid grant_type", () => {
      const accessTokenRequest = {
        grant_type: "client_credentials",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow("Access token request validation failed");
    });
  });

  describe("DPoP header validation", () => {
    it("should throw error when DPoP header is missing", () => {
      const headers = new Headers();
      headers.set("OAuth-Client-Attestation", VALID_CLIENT_ATTESTATION_JWT);
      headers.set(
        "OAuth-Client-Attestation-PoP",
        VALID_CLIENT_ATTESTATION_POP_JWT,
      );

      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow("Request is missing required 'DPoP' header");
    });

    it("should throw error for invalid DPoP JWT format", () => {
      const headers = new Headers();
      headers.set("DPoP", "invalid-dpop-jwt");
      headers.set("OAuth-Client-Attestation", VALID_CLIENT_ATTESTATION_JWT);
      headers.set(
        "OAuth-Client-Attestation-PoP",
        VALID_CLIENT_ATTESTATION_POP_JWT,
      );

      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(
        "Request contains a 'DPoP' header, but the value is not a valid JWT format",
      );
    });

    it("should throw error for malformed DPoP JWT (missing parts)", () => {
      const headers = new Headers();
      headers.set("DPoP", "header.payload");
      headers.set("OAuth-Client-Attestation", VALID_CLIENT_ATTESTATION_JWT);
      headers.set(
        "OAuth-Client-Attestation-PoP",
        VALID_CLIENT_ATTESTATION_POP_JWT,
      );

      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(Oauth2Error);
    });
  });

  describe("Client Attestation header validation", () => {
    it("should throw error when OAuth-Client-Attestation header is missing", () => {
      const headers = new Headers();
      headers.set("DPoP", VALID_DPOP_JWT);
      headers.set(
        "OAuth-Client-Attestation-PoP",
        VALID_CLIENT_ATTESTATION_POP_JWT,
      );

      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(
        "Request contains client attestation headers, but the values are not in valid JWT format",
      );
    });

    it("should throw error when OAuth-Client-Attestation-PoP header is missing", () => {
      const headers = new Headers();
      headers.set("DPoP", VALID_DPOP_JWT);
      headers.set("OAuth-Client-Attestation", VALID_CLIENT_ATTESTATION_JWT);

      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(
        "Request contains client attestation headers, but the values are not in valid JWT format",
      );
    });

    it("should throw error for invalid OAuth-Client-Attestation JWT format", () => {
      const headers = new Headers();
      headers.set("DPoP", VALID_DPOP_JWT);
      headers.set("OAuth-Client-Attestation", "invalid-jwt");
      headers.set(
        "OAuth-Client-Attestation-PoP",
        VALID_CLIENT_ATTESTATION_POP_JWT,
      );

      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(
        "Request contains client attestation headers, but the values are not in valid JWT format",
      );
    });

    it("should throw error for invalid OAuth-Client-Attestation-PoP JWT format", () => {
      const headers = new Headers();
      headers.set("DPoP", VALID_DPOP_JWT);
      headers.set("OAuth-Client-Attestation", VALID_CLIENT_ATTESTATION_JWT);
      headers.set("OAuth-Client-Attestation-PoP", "invalid-jwt");

      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(
        "Request contains client attestation headers, but the values are not in valid JWT format",
      );
    });

    it("should throw error when both client attestation headers are missing", () => {
      const headers = new Headers();
      headers.set("DPoP", VALID_DPOP_JWT);

      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(Oauth2Error);
      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(headers),
        }),
      ).toThrow(
        "Request is missing required 'OAuth-Client-Attestation' header",
      );
    });
  });

  describe("PKCE code verifier", () => {
    it("should extract pkceCodeVerifier when present", () => {
      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        config: v1_4Config,
        request: createMockRequest(createValidHeaders()),
      });

      expect(result.pkceCodeVerifier).toBe("test-code-verifier");
    });

    it("should return undefined pkceCodeVerifier for refresh token grant", () => {
      const accessTokenRequest = {
        grant_type: "refresh_token",
        refresh_token: "test-refresh-token",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        config: v1_4Config,
        request: createMockRequest(createValidHeaders()),
      });

      expect(result.pkceCodeVerifier).toBeUndefined();
    });
  });

  describe("Strict schema validation", () => {
    it("should strip unknown fields from request", () => {
      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        custom_field: "custom-value",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        config: v1_4Config,
        request: createMockRequest(createValidHeaders()),
      });

      // The custom_field should be stripped from the validated request
      expect(result.accessTokenRequest).not.toHaveProperty("custom_field");
      expect(result.accessTokenRequest).toEqual({
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      });
    });
  });

  describe("Case-insensitive header handling", () => {
    it("should handle case-insensitive header names", () => {
      const headers = new Headers();
      headers.set("dpop", VALID_DPOP_JWT);
      headers.set("oauth-client-attestation", VALID_CLIENT_ATTESTATION_JWT);
      headers.set(
        "oauth-client-attestation-pop",
        VALID_CLIENT_ATTESTATION_POP_JWT,
      );

      const accessTokenRequest = {
        code: "test-auth-code",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      const result = parseAccessTokenRequest({
        accessTokenRequest,
        config: v1_4Config,
        request: createMockRequest(headers),
      });

      expect(result.dpop).toBeDefined();
      expect(result.clientAttestation).toBeDefined();
    });
  });

  describe("Edge cases", () => {
    it("should handle empty string values gracefully", () => {
      const accessTokenRequest = {
        code: "",
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow(Oauth2Error);
    });

    it("should handle null values in request", () => {
      const accessTokenRequest = {
        code: null,
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow(Oauth2Error);
    });

    it("should handle undefined values in request", () => {
      const accessTokenRequest = {
        code: undefined,
        code_verifier: "test-code-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://client.example.com/callback",
      };

      expect(() =>
        parseAccessTokenRequest({
          accessTokenRequest,
          config: v1_4Config,
          request: createMockRequest(createValidHeaders()),
        }),
      ).toThrow(Oauth2Error);
    });
  });
});
