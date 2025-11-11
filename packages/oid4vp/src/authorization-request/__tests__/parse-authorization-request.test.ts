import {
  CallbackContext,
  JwtSignerJwk,
  Oauth2JwtParseError,
} from "@openid4vc/oauth2";
import { ValidationError } from "@openid4vc/utils";
import { describe, expect, it } from "vitest";

import { ParseAuthorizeRequestError } from "../../errors";
import { parseAuthorizeRequest } from "../parse-authorization-request";
import { AuthorizationRequestObject } from "../z-request-object";
const jose = import("jose");

const publicKey = {
  crv: "P-256",
  kty: "EC",
  x: "40_OgyA0fjgLpbL1hkU12rJSJ27zPEm6FJET4cBO4UA",
  y: "bUGcZDIlShZrlUjx58mVZ-Hxu2IPddEq1QSEb8BjaQo",
};

const wrongPublicKey = {
  crv: "P-256",
  kty: "EC",
  x: "VJ23NtKusfLrtx1a2CMsieJJ8PiI_olk6RgLEN7xuEU",
  y: "NU5kLnG73gcamaSd4rilxgNRiz5WmO-EE0zCKe0hG8c",
};

const wrongPubKeySigner: JwtSignerJwk = {
  alg: "ES256",
  method: "jwk",
  publicJwk: wrongPublicKey,
};

const signer: JwtSignerJwk = {
  alg: "ES256",
  method: "jwk",
  publicJwk: publicKey,
};

const correctRequestObject: AuthorizationRequestObject = {
  client_id: "test-client-id",
  dcql_query: {},
  exp: new Date("2035-09-15").getTime(),
  iat: new Date("2025-09-15").getTime(),
  iss: "test-client-id",
  nonce: "test_nonce",
  request_uri: "uri://request.example.com",
  request_uri_method: "POST",
  response_mode: "direct_post.jwt",
  response_type: "vp_token",
  response_uri: "uri://response.example.com",
  scope: "test_presentation_scope",
  state: "test_state",
  wallet_nonce: "Test wallet nonce",
};
/**
 * JWT with correct header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
 */
const correctRequestObjectJwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MjA3MzQyNzIwMDAwMH0.isnK4zjF1SWw02fHoTxGji--1spFDmISJRUNnpaPhbBZbYxFxDrd69gfJHx1bNXP5pMRcE5-c-0dtbo3tZoXXw";

/**
 * The missingMandatoryFieldRequestObjectJwt is obtained by signing the missingMandatoryFieldRequestObject defined below
 * const {response_type : _ , ...missingMandatoryFieldRequestObject} = correctRequestObject
 * Header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
 */
const missingMandatoryFieldRequestObjectJwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MjA3MzQyNzIwMDAwMH0.rQWRpNGrtH1VhwMhXoHrDncK0ojb4r2BVjr8WI0ZFUjBYrXst0PETd9r4fFl08lCSDOA_iOKm3Oyjz5cy6scHg";

/**
 * The nonConformingRequestObjectJwt is obtained by signing this object
 * const nonConformingRequestObject = {
 *     ...correctRequestObject,
 *     response_type : 3,
 *     response_uri : 'this is not a uri',
 *     request_uri : undefined,
 *     response_mode : 'direct_post',
 *     dcql_query : [],
 * }
 * Header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
 */
const nonConformingRequestObjectJwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJyZXNwb25zZV90eXBlIjozLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsInJlc3BvbnNlX3VyaSI6InRoaXMgaXMgbm90IGEgdXJpIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoidGVzdF9ub25jZSIsIndhbGxldF9ub25jZSI6IlRlc3Qgd2FsbGV0IG5vbmNlIiwic2NvcGUiOiJ0ZXN0X3ByZXNlbnRhdGlvbl9zY29wZSIsInN0YXRlIjoidGVzdF9zdGF0ZSIsImRjcWxfcXVlcnkiOltdLCJpc3MiOiJ0ZXN0LWNsaWVudC1pZCIsImlhdCI6MTc1Nzg5NDQwMDAwMCwiZXhwIjoyMDczNDI3MjAwMDAwfQ.zZkKLkuGUl0iBZRuGTPBVtoXvQxwcgj5eH_K-B_wvcKkLYBsAGMILB-OE-sAGkIYAb12CEl0DcMbYCERKQ96ug";

const expiredRequestObject = {
  ...correctRequestObject,
  exp: new Date("2025-09-16").getTime(),
};
/**
 * Header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
 */
const expiredRequestObjectJwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MTc1Nzk4MDgwMDAwMH0.8H9UNt-LJZnhG2PfNNuf9IZ5ldmhME5Bqii2dEzE-mQqRWELCP8O7W5ZNpPNit55PUpsUemQYoOgqPCPHBgS3A";

/**
 * JWT with invalid header typ field: {"alg":"ES256","typ":"jwt"}
 */
const invalidHeaderTypJwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MjA3MzQyNzIwMDAwMH0.xbxwjLKeP4AJRqUwSq3e47i4QPmCs3aELuSWTH5Ad6bgu1OxG5Dlt1S6pqc9z95B_t98134H9KDowF_7NLRSGA";

const callbacks: Pick<CallbackContext, "verifyJwt"> = {
  verifyJwt: async (signer, { compact }) => {
    const { jwtVerify } = await jose;
    if (signer.method === "jwk") {
      try {
        await jwtVerify(compact, signer.publicJwk);
        return {
          signerJwk: signer.publicJwk,
          verified: true,
        };
      } catch {
        return {
          verified: false,
        };
      }
    }
    return {
      verified: false,
    };
  },
};

describe("parseAuthorizationRequest tests", () => {
  it("should parse and verify the request object correctly", async () => {
    const actualRequestObject = await parseAuthorizeRequest({
      callbacks,
      dpop: { signer },
      requestObjectJwt: correctRequestObjectJwt,
    });
    expect(actualRequestObject).toEqual(correctRequestObject);
  });

  it("should throw a ValidationError for missing mandatory fields", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          dpop: { signer },
          requestObjectJwt: missingMandatoryFieldRequestObjectJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should throw a ValidationError for non conforming structure", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          dpop: { signer },
          requestObjectJwt: nonConformingRequestObjectJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should parse and verify the request object correctly since expiration is not checked", async () => {
    const actualRequestObject = await parseAuthorizeRequest({
      callbacks,
      dpop: { signer },
      requestObjectJwt: expiredRequestObjectJwt,
    });
    expect(actualRequestObject).toEqual(expiredRequestObject);
  });

  it("should throw an Oauth2JwtParseError because of a malformed jwt", async () => {
    await expect(async () =>
      parseAuthorizeRequest({
        callbacks,
        dpop: { signer },
        requestObjectJwt: "this is not a JWT",
      }),
    ).rejects.toThrow(Oauth2JwtParseError);
  });

  it("should throw an ParseAuthroizeRequestError because of a malformed signature", async () => {
    await expect(async () => {
      const [head, payload] = correctRequestObjectJwt.split(".");
      await parseAuthorizeRequest({
        callbacks,
        dpop: { signer },
        requestObjectJwt: `${head}.${payload}.this_is_not_a_signature`,
      });
    }).rejects.toThrow(ParseAuthorizeRequestError);
  });

  it("should throw an ParseAuthorizeRequestError because of a missing signature", async () => {
    await expect(async () => {
      const [head, payload] = correctRequestObjectJwt.split(".");
      await parseAuthorizeRequest({
        callbacks,
        dpop: { signer },
        requestObjectJwt: `${head}.${payload}.`,
      });
    }).rejects.toThrow(ParseAuthorizeRequestError);
  });

  it("should throw an ParseAuthorizeRequestError because of a mismatching public key signer", async () => {
    await expect(async () => {
      await parseAuthorizeRequest({
        callbacks,
        dpop: { signer: wrongPubKeySigner },
        requestObjectJwt: correctRequestObjectJwt,
      });
    }).rejects.toThrow(ParseAuthorizeRequestError);
  });

  it("should throw a ValidationError for invalid header typ field", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          dpop: { signer },
          requestObjectJwt: invalidHeaderTypJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should throw a ValidationError for missing alg field in header", async () => {
    // JWT with missing alg field in header: {"typ":"oauth-authz-req+jwt"}
    const missingAlgJwt =
      "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0In0.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MjA3MzQyNzIwMDAwMH0.invalid_signature";

    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          dpop: { signer },
          requestObjectJwt: missingAlgJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should throw a ValidationError for empty trust_chain array", async () => {
    // JWT with empty trust_chain field: {"alg":"ES256","typ":"oauth-authz-req+jwt","trust_chain":[]}
    const jwtWithEmptyTrustChain =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJ0cnVzdF9jaGFpbiI6W119.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MjA3MzQyNzIwMDAwMH0.invalid_signature";

    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          dpop: { signer },
          requestObjectJwt: jwtWithEmptyTrustChain,
        }),
    ).rejects.toThrow(ValidationError);
  });
});
