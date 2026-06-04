/* eslint-disable max-lines-per-function */
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it } from "vitest";

import type {
  ValidateCredentialOfferOptionsV1_3,
  ValidateCredentialOfferOptionsV1_4,
} from "../types";
import type {
  CredentialOfferV1_3,
  CredentialOfferV1_4,
} from "../z-credential-offer";

import { CredentialOfferError } from "../../errors";
import { validateCredentialOffer } from "../validate-credential-offer";

const v1_3Config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
});

const v1_4Config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_4,
});

describe("validateCredentialOffer", () => {
  const validCredentialOffer: CredentialOfferV1_3 = {
    credential_configuration_ids: ["UniversityDegree"],
    credential_issuer: "https://issuer.example.com",
    grants: {
      authorization_code: {
        scope: "openid",
      },
    },
  };

  beforeEach(() => {
    // Clean up any side effects between tests
  });

  describe("successful validation", () => {
    it("should validate a valid credential offer", async () => {
      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialOffer: validCredentialOffer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should validate credential offer with all optional fields", async () => {
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

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialOffer: fullOffer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should validate credential offer with multiple credential_configuration_ids", async () => {
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

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialOffer: multiConfigOffer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });
  });

  describe("credential_issuer validation", () => {
    it("should throw CredentialOfferError when credential_issuer is not HTTPS", async () => {
      const invalidOffer: CredentialOfferV1_3 = {
        ...validCredentialOffer,
        credential_issuer: "http://issuer.example.com",
      };

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialOffer: invalidOffer,
      };

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        CredentialOfferError,
      );

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        "credential_issuer must be an HTTPS URL",
      );
    });
  });

  describe("credential_configuration_ids validation", () => {
    it("should throw CredentialOfferError when credential_configuration_ids is empty", async () => {
      const invalidOffer: CredentialOfferV1_3 = {
        ...validCredentialOffer,
        credential_configuration_ids: [],
      };

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialOffer: invalidOffer,
      };

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        CredentialOfferError,
      );

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        "credential_configuration_ids must contain at least one identifier",
      );
    });
  });

  describe("grants validation", () => {
    it("should throw CredentialOfferError when grants is missing", async () => {
      const invalidOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
      } as unknown as CredentialOfferV1_3;

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialOffer: invalidOffer,
      };

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        CredentialOfferError,
      );

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        "grants is REQUIRED for IT-Wallet v1.3",
      );
    });

    it("should throw CredentialOfferError when authorization_code grant is missing", async () => {
      const invalidOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {},
      } as unknown as CredentialOfferV1_3;

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialOffer: invalidOffer,
      };

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        CredentialOfferError,
      );

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        "authorization_code grant is REQUIRED for IT-Wallet v1.3",
      );
    });
  });

  describe("scope validation", () => {
    it("should throw CredentialOfferError when scope is missing", async () => {
      const invalidOffer: CredentialOfferV1_3 = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            scope: "",
          },
        },
      };

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialOffer: invalidOffer,
      };

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        CredentialOfferError,
      );

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        "authorization_code.scope is REQUIRED",
      );
    });
  });

  describe("authorization_server conditional validation", () => {
    it("should validate when authorization_server is present with single auth server in metadata", async () => {
      const offer: CredentialOfferV1_3 = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            authorization_server: "https://auth.issuer.example.com",
            scope: "openid",
          },
        },
      };

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialIssuerMetadata: {
          authorization_servers: ["https://auth.issuer.example.com"],
        },
        credentialOffer: offer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should throw CredentialOfferError when authorization_server is missing with multiple auth servers", async () => {
      const offer: CredentialOfferV1_3 = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            scope: "openid",
            // authorization_server is missing
          },
        },
      };

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialIssuerMetadata: {
          authorization_servers: [
            "https://auth1.issuer.example.com",
            "https://auth2.issuer.example.com",
          ],
        },
        credentialOffer: offer,
      };

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        CredentialOfferError,
      );

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        "authorization_server is REQUIRED when Credential Issuer uses multiple Authorization Servers",
      );
    });

    it("should validate when authorization_server is present and matches one of multiple auth servers", async () => {
      const offer: CredentialOfferV1_3 = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            authorization_server: "https://auth2.issuer.example.com",
            scope: "openid",
          },
        },
      };

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialIssuerMetadata: {
          authorization_servers: [
            "https://auth1.issuer.example.com",
            "https://auth2.issuer.example.com",
          ],
        },
        credentialOffer: offer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should throw CredentialOfferError when authorization_server does not match metadata", async () => {
      const offer: CredentialOfferV1_3 = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            authorization_server: "https://unknown-auth.example.com",
            scope: "openid",
          },
        },
      };

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialIssuerMetadata: {
          authorization_servers: [
            "https://auth1.issuer.example.com",
            "https://auth2.issuer.example.com",
          ],
        },
        credentialOffer: offer,
      };

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        CredentialOfferError,
      );

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        "authorization_server 'https://unknown-auth.example.com' does not match Credential Issuer metadata",
      );
    });

    it("should validate when authorization_server is optional with single auth server", async () => {
      const offer: CredentialOfferV1_3 = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            scope: "openid",
            // authorization_server is optional when there's only one
          },
        },
      };

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialIssuerMetadata: {
          authorization_servers: ["https://auth.issuer.example.com"],
        },
        credentialOffer: offer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should validate when no credentialIssuerMetadata is provided", async () => {
      const offer: CredentialOfferV1_3 = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            authorization_server: "https://auth.issuer.example.com",
            scope: "openid",
          },
        },
      };

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialOffer: offer,
        // No credentialIssuerMetadata provided
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should validate when credentialIssuerMetadata has no authorization_servers", async () => {
      const offer: CredentialOfferV1_3 = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            scope: "openid",
          },
        },
      };

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialIssuerMetadata: {
          // No authorization_servers field
        },
        credentialOffer: offer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });
  });

  describe("edge cases", () => {
    it("should validate credential offer with issuer_state", async () => {
      const offer: CredentialOfferV1_3 = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            issuer_state: "eyJhbGciOiJSU0Et...zaEJ3w",
            scope: "openid",
          },
        },
      };

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialOffer: offer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should validate credential offer with complex scope", async () => {
      const offer: CredentialOfferV1_3 = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            scope: "openid profile email address phone",
          },
        },
      };

      const options: ValidateCredentialOfferOptionsV1_3 = {
        config: v1_3Config,
        credentialOffer: offer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });
  });

  describe("v1.4", () => {
    const validV1_4Offer: CredentialOfferV1_4 = {
      credential_configuration_ids: ["UniversityDegree"],
      credential_issuer: "https://issuer.example.com",
      grants: {
        authorization_code: {
          issuer_state: "eyJhbGciOiJSU0Et...zaEJ3w",
        },
      },
    };

    it("should validate a v1.4 offer that carries no scope", async () => {
      const options: ValidateCredentialOfferOptionsV1_4 = {
        config: v1_4Config,
        credentialOffer: validV1_4Offer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should validate a v1.4 offer with only the required fields", async () => {
      const options: ValidateCredentialOfferOptionsV1_4 = {
        config: v1_4Config,
        credentialOffer: {
          credential_configuration_ids: ["UniversityDegree"],
          credential_issuer: "https://issuer.example.com",
          grants: {
            authorization_code: {},
          },
        },
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should still enforce HTTPS credential_issuer for a v1.4 offer", async () => {
      const options: ValidateCredentialOfferOptionsV1_4 = {
        config: v1_4Config,
        credentialOffer: {
          ...validV1_4Offer,
          credential_issuer: "http://issuer.example.com",
        },
      };

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        "credential_issuer must be an HTTPS URL",
      );
    });

    it("should report the v1.4 version label when grants is missing", async () => {
      const options: ValidateCredentialOfferOptionsV1_4 = {
        config: v1_4Config,
        credentialOffer: {
          credential_configuration_ids: ["UniversityDegree"],
          credential_issuer: "https://issuer.example.com",
        } as unknown as CredentialOfferV1_4,
      };

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        "grants is REQUIRED for IT-Wallet v1.4",
      );
    });

    it("should still enforce the authorization_server match for a v1.4 offer", async () => {
      const options: ValidateCredentialOfferOptionsV1_4 = {
        config: v1_4Config,
        credentialIssuerMetadata: {
          authorization_servers: [
            "https://auth1.issuer.example.com",
            "https://auth2.issuer.example.com",
          ],
        },
        credentialOffer: {
          ...validV1_4Offer,
          grants: {
            authorization_code: {
              authorization_server: "https://unknown-auth.example.com",
            },
          },
        },
      };

      await expect(validateCredentialOffer(options)).rejects.toThrow(
        "authorization_server 'https://unknown-auth.example.com' does not match Credential Issuer metadata",
      );
    });
  });
});
