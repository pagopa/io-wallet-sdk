/* eslint-disable max-lines-per-function */
import { beforeEach, describe, expect, it } from "vitest";

import type { CredentialOffer } from "../z-credential-offer";

import { CredentialOfferError } from "../../errors";
import { extractGrantDetails } from "../extract-grant-details";

describe("extractGrantDetails", () => {
  beforeEach(() => {
    // Clean up any side effects between tests
  });

  describe("successful extraction", () => {
    it("should extract authorization_code grant with only required fields", () => {
      const offer: CredentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            scope: "openid",
          },
        },
      };

      const result = extractGrantDetails(offer);

      expect(result.grantType).toBe("authorization_code");
      expect(result.authorizationCodeGrant.scope).toBe("openid");
      expect(result.authorizationCodeGrant.authorizationServer).toBeUndefined();
      expect(result.authorizationCodeGrant.issuerState).toBeUndefined();
    });

    it("should extract authorization_code grant with all fields", () => {
      const offer: CredentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            authorization_server: "https://auth.issuer.example.com",
            issuer_state: "eyJhbGciOiJSU0Et...zaEJ3w",
            scope: "openid profile",
          },
        },
      };

      const result = extractGrantDetails(offer);

      expect(result.grantType).toBe("authorization_code");
      expect(result.authorizationCodeGrant.scope).toBe("openid profile");
      expect(result.authorizationCodeGrant.authorizationServer).toBe(
        "https://auth.issuer.example.com",
      );
      expect(result.authorizationCodeGrant.issuerState).toBe(
        "eyJhbGciOiJSU0Et...zaEJ3w",
      );
    });

    it("should extract authorization_code grant with authorization_server only", () => {
      const offer: CredentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            authorization_server: "https://auth.issuer.example.com",
            scope: "openid",
          },
        },
      };

      const result = extractGrantDetails(offer);

      expect(result.grantType).toBe("authorization_code");
      expect(result.authorizationCodeGrant.scope).toBe("openid");
      expect(result.authorizationCodeGrant.authorizationServer).toBe(
        "https://auth.issuer.example.com",
      );
      expect(result.authorizationCodeGrant.issuerState).toBeUndefined();
    });

    it("should extract authorization_code grant with issuer_state only", () => {
      const offer: CredentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            issuer_state: "state-value-123",
            scope: "openid",
          },
        },
      };

      const result = extractGrantDetails(offer);

      expect(result.grantType).toBe("authorization_code");
      expect(result.authorizationCodeGrant.scope).toBe("openid");
      expect(result.authorizationCodeGrant.authorizationServer).toBeUndefined();
      expect(result.authorizationCodeGrant.issuerState).toBe("state-value-123");
    });
  });

  describe("error cases", () => {
    it("should throw CredentialOfferError when grants is missing", () => {
      const offer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        // grants is missing
      } as unknown as CredentialOffer;

      expect(() => extractGrantDetails(offer)).toThrow(CredentialOfferError);
      expect(() => extractGrantDetails(offer)).toThrow(
        "No grants found in credential offer",
      );
    });

    it("should throw CredentialOfferError when authorization_code grant is missing", () => {
      const offer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          // authorization_code is missing
        },
      } as unknown as CredentialOffer;

      expect(() => extractGrantDetails(offer)).toThrow(CredentialOfferError);
      expect(() => extractGrantDetails(offer)).toThrow(
        "authorization_code grant not found",
      );
    });

    it("should throw CredentialOfferError when grants is null", () => {
      const offer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: null,
      } as unknown as CredentialOffer;

      expect(() => extractGrantDetails(offer)).toThrow(CredentialOfferError);
      expect(() => extractGrantDetails(offer)).toThrow(
        "No grants found in credential offer",
      );
    });

    it("should throw CredentialOfferError when authorization_code is null", () => {
      const offer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: null,
        },
      } as unknown as CredentialOffer;

      expect(() => extractGrantDetails(offer)).toThrow(CredentialOfferError);
      expect(() => extractGrantDetails(offer)).toThrow(
        "authorization_code grant not found",
      );
    });
  });

  describe("edge cases", () => {
    it("should always return authorization_code as grantType for IT-Wallet v1.3", () => {
      const offer: CredentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            scope: "openid",
          },
        },
      };

      const result = extractGrantDetails(offer);

      // IT-Wallet v1.3 only supports authorization_code grant
      expect(result.grantType).toBe("authorization_code");
    });

    it("should handle complex scope values", () => {
      const offer: CredentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            scope: "openid profile email address phone offline_access",
          },
        },
      };

      const result = extractGrantDetails(offer);

      expect(result.authorizationCodeGrant.scope).toBe(
        "openid profile email address phone offline_access",
      );
    });

    it("should handle long issuer_state values", () => {
      const longIssuerState = "a".repeat(500);
      const offer: CredentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            issuer_state: longIssuerState,
            scope: "openid",
          },
        },
      };

      const result = extractGrantDetails(offer);

      expect(result.authorizationCodeGrant.issuerState).toBe(longIssuerState);
      expect(result.authorizationCodeGrant.issuerState).toHaveLength(500);
    });

    it("should handle multiple credential_configuration_ids without affecting grant extraction", () => {
      const offer: CredentialOffer = {
        credential_configuration_ids: [
          "UniversityDegree",
          "EmployeeID",
          "DriverLicense",
        ],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            scope: "openid",
          },
        },
      };

      const result = extractGrantDetails(offer);

      expect(result.grantType).toBe("authorization_code");
      expect(result.authorizationCodeGrant.scope).toBe("openid");
    });
  });

  describe("type correctness", () => {
    it("should return ExtractGrantDetailsResult with correct structure", () => {
      const offer: CredentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            authorization_server: "https://auth.issuer.example.com",
            issuer_state: "state-123",
            scope: "openid",
          },
        },
      };

      const result = extractGrantDetails(offer);

      // Check result structure
      expect(result).toHaveProperty("grantType");
      expect(result).toHaveProperty("authorizationCodeGrant");

      // Check authorizationCodeGrant structure
      expect(result.authorizationCodeGrant).toHaveProperty("scope");
      expect(result.authorizationCodeGrant).toHaveProperty(
        "authorizationServer",
      );
      expect(result.authorizationCodeGrant).toHaveProperty("issuerState");

      // Check types
      expect(typeof result.grantType).toBe("string");
      expect(typeof result.authorizationCodeGrant.scope).toBe("string");
      expect(typeof result.authorizationCodeGrant.authorizationServer).toBe(
        "string",
      );
      expect(typeof result.authorizationCodeGrant.issuerState).toBe("string");
    });
  });
});
