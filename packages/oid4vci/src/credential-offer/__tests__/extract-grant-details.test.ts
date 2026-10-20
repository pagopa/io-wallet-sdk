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
import {
  CREDENTIAL_OFFER_GRANTS,
  CredentialOfferAPTITUDE,
} from "../APTITUDE/z-credential-offer";
import { extractGrantDetails } from "../extract-grant-details";

const v1_3Config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
});

const v1_4Config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_4,
});

const aptitudeConfig = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.APTITUDE,
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

      expect(result.authorization_code.scope).toBe("openid");
      expect(result.authorization_code.authorizationServer).toBeUndefined();
      expect(result.authorization_code.issuerState).toBeUndefined();
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

      expect(result.authorization_code.scope).toBe("openid profile");
      expect(result.authorization_code.authorizationServer).toBe(
        "https://auth.issuer.example.com",
      );
      expect(result.authorization_code.issuerState).toBe(
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

      expect(result.authorization_code.scope).toBe("openid");
      expect(result.authorization_code.authorizationServer).toBe(
        "https://auth.issuer.example.com",
      );
      expect(result.authorization_code.issuerState).toBeUndefined();
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

      expect(result.authorization_code.scope).toBe("openid");
      expect(result.authorization_code.authorizationServer).toBeUndefined();
      expect(result.authorization_code.issuerState).toBe("state-value-123");
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
    it("should return authorization_code details under its grant type key", () => {
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

      expect(Object.keys(result)).toEqual([
        CREDENTIAL_OFFER_GRANTS.AUTHORIZATION_CODE,
      ]);
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

      expect(result.authorization_code.scope).toBe(
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

      expect(result.authorization_code.issuerState).toBe(longIssuerState);
      expect(result.authorization_code.issuerState).toHaveLength(500);
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

      expect(result.authorization_code.scope).toBe("openid");
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

      // Grant details are keyed by the OAuth grant type.
      expect(result).toHaveProperty(CREDENTIAL_OFFER_GRANTS.AUTHORIZATION_CODE);

      // Check authorization_code grant structure
      expect(result.authorization_code).toHaveProperty("scope");
      expect(result.authorization_code).toHaveProperty("authorizationServer");
      expect(result.authorization_code).toHaveProperty("issuerState");

      // Check types
      expect(typeof result.authorization_code.scope).toBe("string");
      expect(typeof result.authorization_code.authorizationServer).toBe(
        "string",
      );
      expect(typeof result.authorization_code.issuerState).toBe("string");
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

      expect(result.authorization_code.authorizationServer).toBe(
        "https://auth.issuer.example.com",
      );
      expect(result.authorization_code.issuerState).toBe("state-value-123");
      expect("scope" in result.authorization_code).toBe(false);
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

  describe("APTITUDE", () => {
    it("should extract grant details without scope for an APTITUDE offer", () => {
      const credentialOffer: CredentialOfferAPTITUDE = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            authorization_server: "https://auth.issuer.example.com",
            issuer_state: "state-value-123",
          },
        },
      };

      const grantDetails = extractGrantDetails({
        config: aptitudeConfig,
        credentialOffer,
      });

      expect(Object.keys(grantDetails)).toEqual([
        CREDENTIAL_OFFER_GRANTS.AUTHORIZATION_CODE,
      ]);
      expect(grantDetails.authorization_code?.authorizationServer).toBe(
        "https://auth.issuer.example.com",
      );
      expect(grantDetails.authorization_code?.issuerState).toBe(
        "state-value-123",
      );
    });

    it("should accept a credential offer with pre-authorized code grant for an APTITUDE offer", () => {
      const credentialOffer: CredentialOfferAPTITUDE = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": "pre-authorized-code-value",
          },
        },
      };

      const grantDetails = extractGrantDetails({
        config: aptitudeConfig,
        credentialOffer,
      });

      expect(Object.keys(grantDetails)).toEqual([
        CREDENTIAL_OFFER_GRANTS.PREAUTHORIZED_CODE,
      ]);
      expect(
        grantDetails[CREDENTIAL_OFFER_GRANTS.PREAUTHORIZED_CODE]
          ?.preAuthorizedCode,
      ).toBe("pre-authorized-code-value");
    });

    it("should accept a credential offer with pre-authorized code grant with transaction code empty object for an APTITUDE offer", () => {
      const credentialOffer: CredentialOfferAPTITUDE = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": "pre-authorized-code-value",
            tx_code: {},
          },
        },
      };

      const grantDetails = extractGrantDetails({
        config: aptitudeConfig,
        credentialOffer,
      });

      expect(
        grantDetails[CREDENTIAL_OFFER_GRANTS.PREAUTHORIZED_CODE]
          ?.preAuthorizedCode,
      ).toBe("pre-authorized-code-value");
      expect(
        grantDetails[CREDENTIAL_OFFER_GRANTS.PREAUTHORIZED_CODE]?.txCode,
      ).toEqual({
        description: undefined,
        inputMode: undefined,
        length: undefined,
      });
    });

    it("should accept a credential offer with multiple grant types from an APTITUDE offer", () => {
      const credentialOffer: CredentialOfferAPTITUDE = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            authorization_server: "https://auth.issuer.example.com",
            issuer_state: "state-value-123",
          },
          "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": "pre-authorized-code-value",
          },
        },
      };

      const grantDetails = extractGrantDetails({
        config: aptitudeConfig,
        credentialOffer,
      });

      expect(Object.keys(grantDetails)).toHaveLength(2);
      expect(
        grantDetails[CREDENTIAL_OFFER_GRANTS.PREAUTHORIZED_CODE]
          ?.preAuthorizedCode,
      ).toBe("pre-authorized-code-value");
      expect(grantDetails.authorization_code?.authorizationServer).toBe(
        "https://auth.issuer.example.com",
      );
      expect(grantDetails.authorization_code?.issuerState).toBe(
        "state-value-123",
      );
    });

    it("should throw CredentialOfferError when neither authorization_code nor pre authorized code grant is omitted for an APTITUDE offer", () => {
      const credentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {},
      } as unknown as CredentialOfferAPTITUDE;

      expect(() =>
        extractGrantDetails({ config: aptitudeConfig, credentialOffer }),
      ).toThrow(
        "either one of authorization_code or pre-authorized code grant is required",
      );
    });
  });
});
