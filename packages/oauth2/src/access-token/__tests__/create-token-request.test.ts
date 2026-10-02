import { describe, expect, it } from "vitest";

import { createTokenRequest } from "../create-token-request";
import {
  authorizationCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
} from "../z-grant-type";
import { zAccessTokenRequest } from "../z-token";

describe("createTokenRequest - authorization code", () => {
  it.each([undefined, authorizationCodeGrantIdentifier])(
    "creates an authorization-code request with grantType %s",
    async (grantType) => {
      const request = await createTokenRequest({
        authorizationCode: "issuer-authorization-code",
        grantType,
        pkceCodeVerifier: "pkce-verifier",
        redirectUri: "https://wallet.example.com/callback",
      });

      expect(request).toEqual({
        code: "issuer-authorization-code",
        code_verifier: "pkce-verifier",
        grant_type: "authorization_code",
        redirect_uri: "https://wallet.example.com/callback",
      });
      expect(zAccessTokenRequest.parse(request)).toEqual(request);
    },
  );

  it("preserves extension fields without allowing them to override the authorization grant", async () => {
    const additionalRequestPayload = {
      client_id: "wallet-client",
      code: "unexpected-code",
      code_verifier: "unexpected-verifier",
      grant_type: "refresh_token",
      redirect_uri: "https://unexpected.example.com",
    };

    const request = await createTokenRequest({
      additionalRequestPayload,
      authorizationCode: "issuer-code",
      pkceCodeVerifier: "pkce-verifier",
      redirectUri: "https://wallet.example.com/callback",
    });

    expect(request).toEqual({
      client_id: "wallet-client",
      code: "issuer-code",
      code_verifier: "pkce-verifier",
      grant_type: "authorization_code",
      redirect_uri: "https://wallet.example.com/callback",
    });
    expect(additionalRequestPayload.code).toBe("unexpected-code");
  });
});

describe("createTokenRequest - pre-authorized code", () => {
  it.each([undefined, "001234", "A+%&= code"])(
    "creates a pre-authorized request with transaction code and no PKCE",
    async (txCode) => {
      const request = await createTokenRequest({
        grantType: preAuthorizedCodeGrantIdentifier,
        preAuthorizedCode: "opaque%2F+&= code",
        txCode,
      });

      expect(request).toEqual({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": "opaque%2F+&= code",
        tx_code: txCode,
      });
      expect(request).not.toHaveProperty("code");
      expect(request).not.toHaveProperty("code_verifier");
      expect(request).not.toHaveProperty("redirect_uri");
      expect(zAccessTokenRequest.parse(request)).toEqual(request);
    },
  );

  it("preserves authorization details and protects the selected grant parameters", async () => {
    const authorizationDetails = [
      {
        credential_configuration_id: "EuropeanDisabilityCard",
        locations: ["https://issuer.example.com"],
        type: "openid_credential",
      },
    ];
    const additionalRequestPayload = {
      authorization_details: authorizationDetails,
      client_id: "wallet-client",
      grant_type: "authorization_code",
      "pre-authorized_code": "unexpected-code",
      tx_code: "unexpected-transaction-code",
    };

    const request = await createTokenRequest({
      additionalRequestPayload,
      grantType: preAuthorizedCodeGrantIdentifier,
      preAuthorizedCode: "issuer-code",
      txCode: "001234",
    });

    expect(request).toEqual({
      authorization_details: authorizationDetails,
      client_id: "wallet-client",
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": "issuer-code",
      tx_code: "001234",
    });
    expect(additionalRequestPayload.tx_code).toBe(
      "unexpected-transaction-code",
    );
  });
});
