/* eslint-disable max-lines-per-function */
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { CredentialOffer } from "../z-credential-offer";

import { CredentialOfferError } from "../../errors";
import { resolveCredentialOffer } from "../resolve-credential-offer";

const mockFetch = vi.fn();

vi.mock("@openid4vc/utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@openid4vc/utils")>();
  return {
    ...actual,
    createFetcher: () => mockFetch,
  };
});

describe("resolveCredentialOffer", () => {
  const validCredentialOffer: CredentialOffer = {
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

    it("should throw CredentialOfferError when HTTP fetch fails", async () => {
      const uri =
        "openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/123";

      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      await expect(
        resolveCredentialOffer({
          credentialOffer: uri,
          ...baseOptions,
        }),
      ).rejects.toThrow(CredentialOfferError);

      await expect(
        resolveCredentialOffer({
          credentialOffer: uri,
          ...baseOptions,
        }),
      ).rejects.toThrow("HTTP 404 Not Found");
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
      const fullOffer: CredentialOffer = {
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
      const multiConfigOffer: CredentialOffer = {
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
});
