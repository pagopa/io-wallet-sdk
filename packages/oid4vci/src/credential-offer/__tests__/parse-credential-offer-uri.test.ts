import { beforeEach, describe, expect, it } from "vitest";

import { CredentialOfferError } from "../../errors";
import { parseCredentialOfferUri } from "../parse-credential-offer-uri";

describe("parseCredentialOfferUri", () => {
  beforeEach(() => {
    // Clean up any side effects between tests
  });

  describe("openid-credential-offer:// scheme", () => {
    it("should parse by-value credential offer with openid-credential-offer scheme", async () => {
      const uri =
        "openid-credential-offer://?credential_offer=%7B%22test%22%3A%22value%22%7D";

      const result = await parseCredentialOfferUri({ uri });

      expect(result.scheme).toBe("openid-credential-offer");
      expect(result.credential_offer).toBe('{"test":"value"}');
      expect(result.credential_offer_uri).toBeUndefined();
    });

    it("should parse by-reference credential offer with openid-credential-offer scheme", async () => {
      const uri =
        "openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/123";

      const result = await parseCredentialOfferUri({ uri });

      expect(result.scheme).toBe("openid-credential-offer");
      expect(result.credential_offer).toBeUndefined();
      expect(result.credential_offer_uri).toBe(
        "https://issuer.example.com/offers/123",
      );
    });
  });

  describe("haip-vci:// scheme", () => {
    it("should parse by-value credential offer with haip-vci scheme", async () => {
      const uri =
        "haip-vci://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example.com%22%7D";

      const result = await parseCredentialOfferUri({ uri });

      expect(result.scheme).toBe("haip-vci");
      expect(result.credential_offer).toBe(
        '{"credential_issuer":"https://issuer.example.com"}',
      );
      expect(result.credential_offer_uri).toBeUndefined();
    });

    it("should parse by-reference credential offer with haip-vci scheme", async () => {
      const uri =
        "haip-vci://?credential_offer_uri=https://issuer.example.com/offers/456";

      const result = await parseCredentialOfferUri({ uri });

      expect(result.scheme).toBe("haip-vci");
      expect(result.credential_offer).toBeUndefined();
      expect(result.credential_offer_uri).toBe(
        "https://issuer.example.com/offers/456",
      );
    });
  });

  describe("https:// scheme (Universal Links)", () => {
    it("should parse by-value credential offer with HTTPS Universal Link", async () => {
      const uri =
        "https://wallet.example.com/credential-offer?credential_offer=%7B%22test%22%3A%22data%22%7D";

      const result = await parseCredentialOfferUri({ uri });

      expect(result.scheme).toBe("https");
      expect(result.credential_offer).toBe('{"test":"data"}');
      expect(result.credential_offer_uri).toBeUndefined();
    });

    it("should parse by-reference credential offer with HTTPS Universal Link", async () => {
      const uri =
        "https://wallet.example.com/credential-offer?credential_offer_uri=https://issuer.example.com/offers/789";

      const result = await parseCredentialOfferUri({ uri });

      expect(result.scheme).toBe("https");
      expect(result.credential_offer).toBeUndefined();
      expect(result.credential_offer_uri).toBe(
        "https://issuer.example.com/offers/789",
      );
    });
  });

  describe("custom allowed schemes", () => {
    it("should accept URI when scheme is in allowedSchemes", async () => {
      const uri =
        "openid-credential-offer://?credential_offer=%7B%22test%22%3A%22value%22%7D";

      const result = await parseCredentialOfferUri({
        allowedSchemes: ["openid-credential-offer"],
        uri,
      });

      expect(result.scheme).toBe("openid-credential-offer");
    });

    it("should reject URI when scheme is not in allowedSchemes", async () => {
      const uri = "haip-vci://?credential_offer=%7B%22test%22%3A%22value%22%7D";

      await expect(
        parseCredentialOfferUri({
          allowedSchemes: ["openid-credential-offer"],
          uri,
        }),
      ).rejects.toThrow(CredentialOfferError);

      await expect(
        parseCredentialOfferUri({
          allowedSchemes: ["openid-credential-offer"],
          uri,
        }),
      ).rejects.toThrow(
        "Unsupported URL scheme: haip-vci. Allowed schemes: openid-credential-offer",
      );
    });
  });

  describe("error cases", () => {
    it("should throw CredentialOfferError for unsupported scheme", async () => {
      const uri = "http://example.com?credential_offer=%7B%7D";

      await expect(parseCredentialOfferUri({ uri })).rejects.toThrow(
        CredentialOfferError,
      );

      await expect(parseCredentialOfferUri({ uri })).rejects.toThrow(
        "Unsupported URL scheme: http",
      );
    });

    it("should throw CredentialOfferError when both credential_offer and credential_offer_uri are missing", async () => {
      const uri = "openid-credential-offer://?other_param=value";

      await expect(parseCredentialOfferUri({ uri })).rejects.toThrow(
        CredentialOfferError,
      );
    });

    it("should throw CredentialOfferError for malformed URI", async () => {
      const uri = "not-a-valid-uri";

      await expect(parseCredentialOfferUri({ uri })).rejects.toThrow(
        CredentialOfferError,
      );

      await expect(parseCredentialOfferUri({ uri })).rejects.toThrow(
        "Failed to parse credential offer URI",
      );
    });

    it("should throw CredentialOfferError for URI with invalid query string", async () => {
      const uri = "openid-credential-offer://?";

      await expect(parseCredentialOfferUri({ uri })).rejects.toThrow(
        CredentialOfferError,
      );
    });
  });

  describe("edge cases", () => {
    it("should handle URI with both credential_offer and credential_offer_uri (credential_offer takes precedence)", async () => {
      const uri =
        "openid-credential-offer://?credential_offer=%7B%22test%22%3A%22value%22%7D&credential_offer_uri=https://issuer.example.com/offers/123";

      const result = await parseCredentialOfferUri({ uri });

      expect(result.scheme).toBe("openid-credential-offer");
      expect(result.credential_offer).toBe('{"test":"value"}');
      expect(result.credential_offer_uri).toBe(
        "https://issuer.example.com/offers/123",
      );
    });

    it("should handle URI with additional query parameters", async () => {
      const uri =
        "openid-credential-offer://?credential_offer=%7B%22test%22%3A%22value%22%7D&extra=param&foo=bar";

      const result = await parseCredentialOfferUri({ uri });

      expect(result.scheme).toBe("openid-credential-offer");
      expect(result.credential_offer).toBe('{"test":"value"}');
    });

    it("should handle empty credential_offer parameter value", async () => {
      const uri = "openid-credential-offer://?credential_offer=";

      await expect(parseCredentialOfferUri({ uri })).rejects.toThrow(
        CredentialOfferError,
      );
    });
  });
});
