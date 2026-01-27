import { describe, expect, it } from "vitest";

import { ItWalletSpecsVersion } from "../config";
import {
  ItWalletSpecsVersionError,
  UnexpectedStatusCodeError,
} from "../errors";

describe("ItWalletSpecsVersionError", () => {
  describe("constructor", () => {
    it("should create error with correct message", () => {
      const error = new ItWalletSpecsVersionError(
        "createCredentialRequest",
        "2.0.0",
        [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
      );

      expect(error.message).toBe(
        'Feature "createCredentialRequest" does not support version 2.0.0.\n' +
          "Supported versions: V1_0, V1_3",
      );
    });

    it("should set error name", () => {
      const error = new ItWalletSpecsVersionError("testFeature", "1.0.0", [
        "1.0.2",
      ]);

      expect(error.name).toBe("ItWalletSpecsVersionError");
    });

    it("should set error code", () => {
      const error = new ItWalletSpecsVersionError("testFeature", "1.0.0", [
        "1.0.2",
      ]);

      expect(error.code).toBe("IT_WALLET_SPECS_VERSION_ERROR");
    });

    it("should store feature property", () => {
      const error = new ItWalletSpecsVersionError("myFeature", "1.0.0", [
        "1.0.2",
      ]);

      expect(error.feature).toBe("myFeature");
    });

    it("should store requestedVersion property", () => {
      const error = new ItWalletSpecsVersionError("myFeature", "2.5.0", [
        "1.0.2",
      ]);

      expect(error.requestedVersion).toBe("2.5.0");
    });

    it("should store supportedVersions property", () => {
      const supportedVersions = ["1.0.2", "1.3.3", "2.0.0"] as const;
      const error = new ItWalletSpecsVersionError(
        "myFeature",
        "3.0.0",
        supportedVersions,
      );

      expect(error.supportedVersions).toEqual(supportedVersions);
    });

    it("should be instance of Error", () => {
      const error = new ItWalletSpecsVersionError("testFeature", "1.0.0", [
        "1.0.2",
      ]);

      expect(error).toBeInstanceOf(Error);
    });

    it("should have proper stack trace", () => {
      const error = new ItWalletSpecsVersionError("testFeature", "1.0.0", [
        "1.0.2",
      ]);

      expect(error.stack).toBeDefined();
      expect(error.stack).toContain("ItWalletSpecsVersionError");
    });
  });

  describe("error message formatting", () => {
    it("should format message with single supported version", () => {
      const error = new ItWalletSpecsVersionError(
        "fetchCredentialResponse",
        "1.0.0",
        [ItWalletSpecsVersion.V1_3],
      );

      expect(error.message).toContain("Supported versions: V1_3");
    });

    it("should format message with multiple supported versions", () => {
      const error = new ItWalletSpecsVersionError(
        "fetchCredentialResponse",
        "1.0.0",
        [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3, "2.0.0"],
      );

      expect(error.message).toContain("Supported versions: V1_0, V1_3, 2.0.0");
    });

    it("should include feature name in message", () => {
      const error = new ItWalletSpecsVersionError("customFeature", "1.0.0", [
        "1.0.2",
      ]);

      expect(error.message).toContain('Feature "customFeature"');
    });

    it("should include requested version in message", () => {
      const error = new ItWalletSpecsVersionError("testFeature", "9.9.9", [
        "1.0.2",
      ]);

      expect(error.message).toContain("does not support version 9.9.9");
    });
  });

  describe("use cases", () => {
    it("should be catchable as Error", () => {
      expect(() => {
        throw new ItWalletSpecsVersionError("test", "1.0.0", ["1.0.2"]);
      }).toThrow(Error);
    });

    it("should be catchable as ItWalletSpecsVersionError", () => {
      expect(() => {
        throw new ItWalletSpecsVersionError("test", "1.0.0", ["1.0.2"]);
      }).toThrow(ItWalletSpecsVersionError);
    });

    it("should provide structured error info for error handling", () => {
      try {
        throw new ItWalletSpecsVersionError(
          "createCredentialRequest",
          "2.0.0",
          [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
        );
      } catch (error) {
        if (error instanceof ItWalletSpecsVersionError) {
          expect(error.feature).toBe("createCredentialRequest");
          expect(error.requestedVersion).toBe("2.0.0");
          expect(error.supportedVersions).toEqual([
            ItWalletSpecsVersion.V1_0,
            ItWalletSpecsVersion.V1_3,
          ]);
          expect(error.code).toBe("IT_WALLET_SPECS_VERSION_ERROR");
        } else {
          throw new Error("Expected ItWalletSpecsVersionError");
        }
      }
    });
  });
});

describe("UnexpectedStatusCodeError", () => {
  describe("constructor", () => {
    it("should create error with string reason", () => {
      const error = new UnexpectedStatusCodeError({
        message: "Request failed",
        reason: "Not found",
        statusCode: 404,
      });

      expect(error.reason).toBe("Not found");
      expect(error.statusCode).toBe(404);
    });

    it("should create error with object reason", () => {
      const reason = { description: "Token expired", error: "invalid_grant" };
      const error = new UnexpectedStatusCodeError({
        message: "OAuth error",
        reason,
        statusCode: 400,
      });

      expect(error.reason).toEqual(reason);
    });
  });
});
