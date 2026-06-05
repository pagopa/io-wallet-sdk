/* eslint-disable max-lines-per-function */
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it } from "vitest";

import type {
  CredentialOfferV1_3,
  CredentialOfferV1_4,
} from "../z-credential-offer";

import { CredentialOfferError } from "../../errors";
import { extractGrantDetails } from "../extract-grant-details";

const v1_3Config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
});

const v1_4Config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_4,
});

describe("extractGrantDetails", () => {
  beforeEach(() => {
    // Clean up any side effects between tests
  });

  describe("successful extraction", () => {
    it("should extract authorization_code grant with only required fields", () => {
      const credentialOffer: CredentialOfferV1_3 = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            scope: "openid",
          },
        },
      };

      const result = extractGrantDetails({
        config: v1_3Config,
        credentialOffer,
      });

      expect(result.grantType).toBe("authorization_code");
      expect(result.authorizationCodeGrant.scope).toBe("openid");
      expect(result.authorizationCodeGrant.authorizationServer).toBeUndefined();
      expect(result.authorizationCodeGrant.issuerState).toBeUndefined();
    });

    it("should extract authorization_code grant with all fields", () => {
      const credentialOffer: CredentialOfferV1_3 = {
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

      const result = extractGrantDetails({
        config: v1_3Config,
        credentialOffer,
      });

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
      const credentialOffer: CredentialOfferV1_3 = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            authorization_server: "https://auth.issuer.example.com",
            scope: "openid",
          },
        },
      };

      const result = extractGrantDetails({
        config: v1_3Config,
        credentialOffer,
      });

      expect(result.grantType).toBe("authorization_code");
      expect(result.authorizationCodeGrant.scope).toBe("openid");
      expect(result.authorizationCodeGrant.authorizationServer).toBe(
        "https://auth.issuer.example.com",
      );
      expect(result.authorizationCodeGrant.issuerState).toBeUndefined();
    });

    it("should extract authorization_code grant with issuer_state only", () => {
      const credentialOffer: CredentialOfferV1_3 = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            issuer_state: "state-value-123",
            scope: "openid",
          },
        },
      };

      const result = extractGrantDetails({
        config: v1_3Config,
        credentialOffer,
      });

      expect(result.grantType).toBe("authorization_code");
      expect(result.authorizationCodeGrant.scope).toBe("openid");
      expect(result.authorizationCodeGrant.authorizationServer).toBeUndefined();
      expect(result.authorizationCodeGrant.issuerState).toBe("state-value-123");
    });
  });

  describe("error cases", () => {
    it("should throw CredentialOfferError when grants is missing", () => {
      const credentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        // grants is missing
      } as unknown as CredentialOfferV1_3;

      expect(() =>
        extractGrantDetails({ config: v1_3Config, credentialOffer }),
      ).toThrow(CredentialOfferError);
      expect(() =>
        extractGrantDetails({ config: v1_3Config, credentialOffer }),
      ).toThrow("No grants found in credential offer");
    });

    it("should throw CredentialOfferError when authorization_code grant is missing", () => {
      const credentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          // authorization_code is missing
        },
      } as unknown as CredentialOfferV1_3;

      expect(() =>
        extractGrantDetails({ config: v1_3Config, credentialOffer }),
      ).toThrow(CredentialOfferError);
      expect(() =>
        extractGrantDetails({ config: v1_3Config, credentialOffer }),
      ).toThrow("authorization_code grant not found");
    });

    it("should throw CredentialOfferError when grants is null", () => {
      const credentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: null,
      } as unknown as CredentialOfferV1_3;

      expect(() =>
        extractGrantDetails({ config: v1_3Config, credentialOffer }),
      ).toThrow(CredentialOfferError);
      expect(() =>
        extractGrantDetails({ config: v1_3Config, credentialOffer }),
      ).toThrow("No grants found in credential offer");
    });

    it("should throw CredentialOfferError when authorization_code is null", () => {
      const credentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: null,
        },
      } as unknown as CredentialOfferV1_3;

      expect(() =>
        extractGrantDetails({ config: v1_3Config, credentialOffer }),
      ).toThrow(CredentialOfferError);
      expect(() =>
        extractGrantDetails({ config: v1_3Config, credentialOffer }),
      ).toThrow("authorization_code grant not found");
    });
  });

  describe("edge cases", () => {
    it("should always return authorization_code as grantType for IT-Wallet", () => {
      const credentialOffer: CredentialOfferV1_3 = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            scope: "openid",
          },
        },
      };

      const result = extractGrantDetails({
        config: v1_3Config,
        credentialOffer,
      });

      // IT-Wallet only supports authorization_code grant
      expect(result.grantType).toBe("authorization_code");
    });

    it("should handle complex scope values", () => {
      const credentialOffer: CredentialOfferV1_3 = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            scope: "openid profile email address phone offline_access",
          },
        },
      };

      const result = extractGrantDetails({
        config: v1_3Config,
        credentialOffer,
      });

      expect(result.authorizationCodeGrant.scope).toBe(
        "openid profile email address phone offline_access",
      );
    });

    it("should handle long issuer_state values", () => {
      const longIssuerState = "a".repeat(500);
      const credentialOffer: CredentialOfferV1_3 = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            issuer_state: longIssuerState,
            scope: "openid",
          },
        },
      };

      const result = extractGrantDetails({
        config: v1_3Config,
        credentialOffer,
      });

      expect(result.authorizationCodeGrant.issuerState).toBe(longIssuerState);
      expect(result.authorizationCodeGrant.issuerState).toHaveLength(500);
    });

    it("should handle multiple credential_configuration_ids without affecting grant extraction", () => {
      const credentialOffer: CredentialOfferV1_3 = {
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

      const result = extractGrantDetails({
        config: v1_3Config,
        credentialOffer,
      });

      expect(result.grantType).toBe("authorization_code");
      expect(result.authorizationCodeGrant.scope).toBe("openid");
    });
  });

  describe("type correctness", () => {
    it("should return ExtractGrantDetailsResult with correct structure", () => {
      const credentialOffer: CredentialOfferV1_3 = {
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

      const result = extractGrantDetails({
        config: v1_3Config,
        credentialOffer,
      });

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

  describe("v1.4", () => {
    it("should extract grant details without scope for a v1.4 offer", () => {
      const credentialOffer: CredentialOfferV1_4 = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            authorization_server: "https://auth.issuer.example.com",
            issuer_state: "state-value-123",
          },
        },
      };

      const result = extractGrantDetails({
        config: v1_4Config,
        credentialOffer,
      });

      expect(result.grantType).toBe("authorization_code");
      expect(result.authorizationCodeGrant.authorizationServer).toBe(
        "https://auth.issuer.example.com",
      );
      expect(result.authorizationCodeGrant.issuerState).toBe("state-value-123");
      expect("scope" in result.authorizationCodeGrant).toBe(false);
    });

    it("should throw CredentialOfferError when authorization_code grant is missing for a v1.4 offer", () => {
      const credentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {},
      } as unknown as CredentialOfferV1_4;

      expect(() =>
        extractGrantDetails({ config: v1_4Config, credentialOffer }),
      ).toThrow("authorization_code grant not found");
    });
  });
});
