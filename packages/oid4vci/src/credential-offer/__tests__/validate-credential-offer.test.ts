/* eslint-disable max-lines-per-function */
import { beforeEach, describe, expect, it } from "vitest";

import type { ValidateCredentialOfferOptions } from "../types";
import type { CredentialOffer } from "../z-credential-offer";

import { CredentialOfferError } from "../../errors";
import { validateCredentialOffer } from "../validate-credential-offer";

describe("validateCredentialOffer", () => {
  const validCredentialOffer: CredentialOffer = {
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
      const options: ValidateCredentialOfferOptions = {
        credentialOffer: validCredentialOffer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should validate credential offer with all optional fields", async () => {
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

      const options: ValidateCredentialOfferOptions = {
        credentialOffer: fullOffer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should validate credential offer with multiple credential_configuration_ids", async () => {
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

      const options: ValidateCredentialOfferOptions = {
        credentialOffer: multiConfigOffer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });
  });

  describe("credential_issuer validation", () => {
    it("should throw CredentialOfferError when credential_issuer is not HTTPS", async () => {
      const invalidOffer: CredentialOffer = {
        ...validCredentialOffer,
        credential_issuer: "http://issuer.example.com",
      };

      const options: ValidateCredentialOfferOptions = {
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
      const invalidOffer: CredentialOffer = {
        ...validCredentialOffer,
        credential_configuration_ids: [],
      };

      const options: ValidateCredentialOfferOptions = {
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
      } as unknown as CredentialOffer;

      const options: ValidateCredentialOfferOptions = {
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
      } as unknown as CredentialOffer;

      const options: ValidateCredentialOfferOptions = {
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
      const invalidOffer: CredentialOffer = {
        credential_configuration_ids: ["UniversityDegree"],
        credential_issuer: "https://issuer.example.com",
        grants: {
          authorization_code: {
            scope: "",
          },
        },
      };

      const options: ValidateCredentialOfferOptions = {
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
      const offer: CredentialOffer = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            authorization_server: "https://auth.issuer.example.com",
            scope: "openid",
          },
        },
      };

      const options: ValidateCredentialOfferOptions = {
        credentialIssuerMetadata: {
          authorization_servers: ["https://auth.issuer.example.com"],
        },
        credentialOffer: offer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should throw CredentialOfferError when authorization_server is missing with multiple auth servers", async () => {
      const offer: CredentialOffer = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            scope: "openid",
            // authorization_server is missing
          },
        },
      };

      const options: ValidateCredentialOfferOptions = {
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
      const offer: CredentialOffer = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            authorization_server: "https://auth2.issuer.example.com",
            scope: "openid",
          },
        },
      };

      const options: ValidateCredentialOfferOptions = {
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
      const offer: CredentialOffer = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            authorization_server: "https://unknown-auth.example.com",
            scope: "openid",
          },
        },
      };

      const options: ValidateCredentialOfferOptions = {
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
      const offer: CredentialOffer = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            scope: "openid",
            // authorization_server is optional when there's only one
          },
        },
      };

      const options: ValidateCredentialOfferOptions = {
        credentialIssuerMetadata: {
          authorization_servers: ["https://auth.issuer.example.com"],
        },
        credentialOffer: offer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should validate when no credentialIssuerMetadata is provided", async () => {
      const offer: CredentialOffer = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            authorization_server: "https://auth.issuer.example.com",
            scope: "openid",
          },
        },
      };

      const options: ValidateCredentialOfferOptions = {
        credentialOffer: offer,
        // No credentialIssuerMetadata provided
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should validate when credentialIssuerMetadata has no authorization_servers", async () => {
      const offer: CredentialOffer = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            scope: "openid",
          },
        },
      };

      const options: ValidateCredentialOfferOptions = {
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
      const offer: CredentialOffer = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            issuer_state: "eyJhbGciOiJSU0Et...zaEJ3w",
            scope: "openid",
          },
        },
      };

      const options: ValidateCredentialOfferOptions = {
        credentialOffer: offer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });

    it("should validate credential offer with complex scope", async () => {
      const offer: CredentialOffer = {
        ...validCredentialOffer,
        grants: {
          authorization_code: {
            scope: "openid profile email address phone",
          },
        },
      };

      const options: ValidateCredentialOfferOptions = {
        credentialOffer: offer,
      };

      await expect(validateCredentialOffer(options)).resolves.toBeUndefined();
    });
  });
});
