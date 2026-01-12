import { describe, expect, it } from "vitest";

import { IoWalletSdkConfig, type ItWalletSpecsVersion } from "../config";

describe("IoWalletSdkConfig", () => {
  describe("constructor", () => {
    it("should create config with v1.0.2", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: "1.0.2" });
      expect(config.itWalletSpecsVersion).toBe("1.0.2");
    });

    it("should create config with v1.3.3", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: "1.3.3" });
      expect(config.itWalletSpecsVersion).toBe("1.3.3");
    });
  });

  describe("isVersion", () => {
    it("should return true when version matches for v1.0.2", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: "1.0.2" });
      expect(config.isVersion("1.0.2")).toBe(true);
    });

    it("should return false when version does not match for v1.0.2", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: "1.0.2" });
      expect(config.isVersion("1.3.3")).toBe(false);
    });

    it("should return true when version matches for v1.3.3", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: "1.3.3" });
      expect(config.isVersion("1.3.3")).toBe(true);
    });

    it("should return false when version does not match for v1.3.3", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: "1.3.3" });
      expect(config.isVersion("1.0.2")).toBe(false);
    });

    it("should provide type narrowing (TypeScript compile-time check)", () => {
      const config = new IoWalletSdkConfig({ itWalletSpecsVersion: "1.3.3" });

      if (config.isVersion("1.3.3")) {
        // This should compile without errors due to type narrowing
        const version: "1.3.3" = config.itWalletSpecsVersion;
        expect(version).toBe("1.3.3");
      }
    });
  });

  describe("type safety", () => {
    it("should accept valid version strings", () => {
      const validVersions: ItWalletSpecsVersion[] = ["1.0.2", "1.3.3"];

      validVersions.forEach((version) => {
        expect(() => {
          new IoWalletSdkConfig({ itWalletSpecsVersion: version });
        }).not.toThrow();
      });
    });
  });
});
