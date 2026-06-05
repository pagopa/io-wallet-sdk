/* eslint-disable max-lines-per-function */
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  UnexpectedStatusCodeError,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  CredentialOfferV1_3,
  CredentialOfferV1_4,
} from "../z-credential-offer";

import { CredentialOfferError } from "../../errors";
import { resolveCredentialOffer } from "../resolve-credential-offer";

const mockFetch = vi.fn();

vi.mock("@pagopa/io-wallet-utils", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-utils")>();
  return {
    ...actual,
    createFetcher: () => mockFetch,
  };
});

describe("resolveCredentialOffer", () => {
  const validCredentialOffer: CredentialOfferV1_3 = {
    credential_configuration_ids: ["UniversityDegree"],
    credential_issuer: "https://issuer.example.com",
    grants: {
      authorization_code: {
        scope: "openid",
      },
    },
  };

  const baseOptions = {
    callbacks: {
      fetch: mockFetch,
    },
    config: new IoWalletSdkConfig({
      itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
    }),
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("by-value credential offers", () => {
    it("should resolve by-value offer with openid-credential-offer scheme", async () => {
      const encodedOffer = encodeURIComponent(
        JSON.stringify(validCredentialOffer),
      );
      const uri = `openid-credential-offer://?credential_offer=${encodedOffer}`;

      const result = await resolveCredentialOffer({
        credentialOffer: uri,
        ...baseOptions,
      });

      expect(result).toEqual(validCredentialOffer);
    });

    it("should resolve by-value offer with haip-vci scheme", async () => {
      const encodedOffer = encodeURIComponent(
        JSON.stringify(validCredentialOffer),
      );
      const uri = `haip-vci://?credential_offer=${encodedOffer}`;

      const result = await resolveCredentialOffer({
        credentialOffer: uri,
        ...baseOptions,
      });

      expect(result).toEqual(validCredentialOffer);
    });

    it("should resolve by-value offer with HTTPS Universal Link", async () => {
      const encodedOffer = encodeURIComponent(
        JSON.stringify(validCredentialOffer),
      );
      const uri = `https://wallet.example.com/credential-offer?credential_offer=${encodedOffer}`;

      const result = await resolveCredentialOffer({
        credentialOffer: uri,
        ...baseOptions,
      });

      expect(result).toEqual(validCredentialOffer);
    });
  });

  describe("by-reference credential offers", () => {
    it("should resolve by-reference offer with openid-credential-offer scheme", async () => {
      const uri =
        "openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/123";

      mockFetch.mockResolvedValue({
        json: vi.fn().mockResolvedValue(validCredentialOffer),
        ok: true,
        status: 200,
      });

      const result = await resolveCredentialOffer({
        credentialOffer: uri,
        ...baseOptions,
      });

      expect(result).toEqual(validCredentialOffer);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://issuer.example.com/offers/123",
        {
          headers: {
            Accept: "application/json",
          },
          method: "GET",
        },
      );
    });

    it("should resolve by-reference offer with haip-vci scheme", async () => {
      const uri =
        "haip-vci://?credential_offer_uri=https://issuer.example.com/offers/456";

      mockFetch.mockResolvedValue({
        json: vi.fn().mockResolvedValue(validCredentialOffer),
        ok: true,
        status: 200,
      });

      const result = await resolveCredentialOffer({
        credentialOffer: uri,
        ...baseOptions,
      });

      expect(result).toEqual(validCredentialOffer);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://issuer.example.com/offers/456",
        {
          headers: {
            Accept: "application/json",
          },
          method: "GET",
        },
      );
    });

    it("should resolve by-reference offer with HTTPS Universal Link", async () => {
      const uri =
        "https://wallet.example.com/credential-offer?credential_offer_uri=https://issuer.example.com/offers/789";

      mockFetch.mockResolvedValue({
        json: vi.fn().mockResolvedValue(validCredentialOffer),
        ok: true,
        status: 200,
      });

      const result = await resolveCredentialOffer({
        credentialOffer: uri,
        ...baseOptions,
      });

      expect(result).toEqual(validCredentialOffer);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://issuer.example.com/offers/789",
        {
          headers: {
            Accept: "application/json",
          },
          method: "GET",
        },
      );
    });

    it("should throw UnexpectedStatusCodeError when HTTP fetch fails", async () => {
      const offerUri = "https://issuer.example.com/offers/123";
      const uri = `openid-credential-offer://?credential_offer_uri=${offerUri}`;

      mockFetch.mockResolvedValue({
        headers: { get: vi.fn().mockReturnValue("text/plain") },
        ok: false,
        status: 404,
        text: vi.fn().mockResolvedValue("Not Found"),
        url: offerUri,
      });

      await expect(
        resolveCredentialOffer({
          credentialOffer: uri,
          ...baseOptions,
        }),
      ).rejects.toThrow(UnexpectedStatusCodeError);

      await expect(
        resolveCredentialOffer({
          credentialOffer: uri,
          ...baseOptions,
        }),
      ).rejects.toThrow(
        `message=Http request failed. Expected 200, got 404, url: ${offerUri} reason=Not Found statusCode=404`,
      );
    });

    it("should throw CredentialOfferError when fetch returns non-JSON", async () => {
      const uri =
        "openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/123";

      mockFetch.mockResolvedValue({
        json: vi.fn().mockRejectedValue(new Error("Invalid JSON")),
        ok: true,
        status: 200,
      });

      await expect(
        resolveCredentialOffer({
          credentialOffer: uri,
          ...baseOptions,
        }),
      ).rejects.toThrow(CredentialOfferError);
    });

    it("should throw CredentialOfferError when network error occurs", async () => {
      const uri =
        "openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/123";

      mockFetch.mockRejectedValue(new Error("Network error"));

      await expect(
        resolveCredentialOffer({
          credentialOffer: uri,
          ...baseOptions,
        }),
      ).rejects.toThrow(CredentialOfferError);
    });
  });

  describe("direct JSON strings", () => {
    it("should resolve direct JSON string", async () => {
      const jsonString = JSON.stringify(validCredentialOffer);

      const result = await resolveCredentialOffer({
        credentialOffer: jsonString,
        ...baseOptions,
      });

      expect(result).toEqual(validCredentialOffer);
    });

    it("should throw CredentialOfferError for invalid JSON string", async () => {
      const invalidJson = "{ invalid json }";

      await expect(
        resolveCredentialOffer({
          credentialOffer: invalidJson,
          ...baseOptions,
        }),
      ).rejects.toThrow(CredentialOfferError);
    });
  });

  describe("validation errors", () => {
    it("should throw CredentialOfferError when credential_issuer is missing", async () => {
      const invalidOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        grants: {
          authorization_code: {
            scope: "openid",
          },
        },
      };

      const encodedOffer = encodeURIComponent(JSON.stringify(invalidOffer));
      const uri = `openid-credential-offer://?credential_offer=${encodedOffer}`;

      await expect(
        resolveCredentialOffer({
          credentialOffer: uri,
          ...baseOptions,
        }),
      ).rejects.toThrow(CredentialOfferError);
    });

    it("should throw CredentialOfferError when credential_configuration_ids is missing", async () => {
      const invalidOffer = {
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            scope: "openid",
          },
        },
      };

      const encodedOffer = encodeURIComponent(JSON.stringify(invalidOffer));
      const uri = `openid-credential-offer://?credential_offer=${encodedOffer}`;

      await expect(
        resolveCredentialOffer({
          credentialOffer: uri,
          ...baseOptions,
        }),
      ).rejects.toThrow(CredentialOfferError);
    });

    it("should throw CredentialOfferError when grants is missing", async () => {
      const invalidOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
      };

      const encodedOffer = encodeURIComponent(JSON.stringify(invalidOffer));
      const uri = `openid-credential-offer://?credential_offer=${encodedOffer}`;

      await expect(
        resolveCredentialOffer({
          credentialOffer: uri,
          ...baseOptions,
        }),
      ).rejects.toThrow(CredentialOfferError);
    });

    it("should throw CredentialOfferError when authorization_code grant is missing", async () => {
      const invalidOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {},
      };

      const encodedOffer = encodeURIComponent(JSON.stringify(invalidOffer));
      const uri = `openid-credential-offer://?credential_offer=${encodedOffer}`;

      await expect(
        resolveCredentialOffer({
          credentialOffer: uri,
          ...baseOptions,
        }),
      ).rejects.toThrow(CredentialOfferError);
    });

    it("should throw CredentialOfferError when scope is missing in authorization_code", async () => {
      const invalidOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {},
        },
      };

      const encodedOffer = encodeURIComponent(JSON.stringify(invalidOffer));
      const uri = `openid-credential-offer://?credential_offer=${encodedOffer}`;

      await expect(
        resolveCredentialOffer({
          credentialOffer: uri,
          ...baseOptions,
        }),
      ).rejects.toThrow(CredentialOfferError);
    });
  });

  describe("edge cases", () => {
    it("should handle credential offer with all optional fields", async () => {
      const fullOffer: CredentialOfferV1_3 = {
        credential_configuration_ids: ["UniversityDegree", "EmployeeID"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            authorization_server: "https://auth.issuer.example.com",
            issuer_state: "eyJhbGciOiJSU0Et...zaEJ3w",
            scope: "openid profile",
          },
        },
      };

      const encodedOffer = encodeURIComponent(JSON.stringify(fullOffer));
      const uri = `openid-credential-offer://?credential_offer=${encodedOffer}`;

      const result = await resolveCredentialOffer({
        credentialOffer: uri,
        ...baseOptions,
      });

      expect(result).toEqual(fullOffer);
      expect(result.grants.authorization_code.authorization_server).toBe(
        "https://auth.issuer.example.com",
      );
      expect(result.grants.authorization_code.issuer_state).toBe(
        "eyJhbGciOiJSU0Et...zaEJ3w",
      );
    });

    it("should handle credential offer with multiple credential_configuration_ids", async () => {
      const multiConfigOffer: CredentialOfferV1_3 = {
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

      const jsonString = JSON.stringify(multiConfigOffer);

      const result = await resolveCredentialOffer({
        credentialOffer: jsonString,
        ...baseOptions,
      });

      expect(result.credential_configuration_ids).toHaveLength(3);
    });
  });

  describe("v1.4", () => {
    const v1_4Options = {
      callbacks: {
        fetch: mockFetch,
      },
      config: new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_4,
      }),
    };

    const validV1_4Offer: CredentialOfferV1_4 = {
      credential_configuration_ids: ["UniversityDegree"],
      credential_issuer: "https://issuer.example.com",
      grants: {
        authorization_code: {
          issuer_state: "eyJhbGciOiJSU0Et...zaEJ3w",
        },
      },
    };

    it("should resolve a v1.4 offer without scope", async () => {
      const jsonString = JSON.stringify(validV1_4Offer);

      const result = await resolveCredentialOffer({
        credentialOffer: jsonString,
        ...v1_4Options,
      });

      expect(result).toEqual(validV1_4Offer);
      expect(result.grants.authorization_code.issuer_state).toBe(
        "eyJhbGciOiJSU0Et...zaEJ3w",
      );
      expect("scope" in result.grants.authorization_code).toBe(false);
    });

    it("should drop a stray scope from a v1.4 offer", async () => {
      const offerWithScope = {
        ...validV1_4Offer,
        grants: {
          authorization_code: {
            issuer_state: "eyJhbGciOiJSU0Et...zaEJ3w",
            scope: "openid",
          },
        },
      };
      const jsonString = JSON.stringify(offerWithScope);

      const result = await resolveCredentialOffer({
        credentialOffer: jsonString,
        ...v1_4Options,
      });

      expect("scope" in result.grants.authorization_code).toBe(false);
    });

    it("should still require credential_issuer for a v1.4 offer", async () => {
      const invalidOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        grants: {
          authorization_code: {},
        },
      };
      const jsonString = JSON.stringify(invalidOffer);

      await expect(
        resolveCredentialOffer({
          credentialOffer: jsonString,
          ...v1_4Options,
        }),
      ).rejects.toThrow(CredentialOfferError);
    });
  });
});
