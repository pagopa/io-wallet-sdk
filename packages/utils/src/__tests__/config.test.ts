import { describe, expect, it } from "vitest";

import { IoWalletSdkConfig, ItWalletSpecsVersion } from "../config";

describe("IoWalletSdkConfig", () => {
  describe("constructor", () => {
    it("should create config with v1.0.2", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 });
      expect(config.itWalletSpecsVersion).toBe(ItWalletSpecsVersion.V1_0);
    });

    it("should create config with v1.3.3", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 });
      expect(config.itWalletSpecsVersion).toBe(ItWalletSpecsVersion.V1_3);
    });
  });

  describe("isVersion", () => {
    it("should return true when version matches for v1.0.2", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 });
      expect(config.isVersion(ItWalletSpecsVersion.V1_0)).toBe(true);
    });

    it("should return false when version does not match for v1.0.2", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 });
      expect(config.isVersion(ItWalletSpecsVersion.V1_3)).toBe(false);
    });

    it("should return true when version matches for v1.3.3", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 });
      expect(config.isVersion(ItWalletSpecsVersion.V1_3)).toBe(true);
    });

    it("should return false when version does not match for v1.3.3", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 });
      expect(config.isVersion(ItWalletSpecsVersion.V1_0)).toBe(false);
    });

    it("should provide type narrowing (TypeScript compile-time check)", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 });

      if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
        // This should compile without errors due to type narrowing
        const version: typeof ItWalletSpecsVersion.V1_3 = config.itWalletSpecsVersion;
        expect(version).toBe(ItWalletSpecsVersion.V1_3);
      }
    });
  });

  describe("type safety", () => {
    it("should accept valid version strings", () => {
      const validVersions: ItWalletSpecsVersion[] = [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3];

      validVersions.forEach((version) => {
        expect(() => {
          new IoWalletSdkConfig({ itWalletSpecsVersion: version });
        }).not.toThrow();
      });
    });
  });
});
