import { CallbackContext, Oauth2JwtParseError } from "@openid4vc/oauth2";
import { ValidationError } from "@openid4vc/utils";
import { describe, expect, it } from "vitest";

import { ParseAuthorizeRequestError } from "../../errors";
import { parseAuthorizeRequest } from "../parse-authorization-request";
import { AuthorizationRequestObject } from "../z-request-object";
const jose = import("jose");

const publicKey = {
  alg: "ES256",
  crv: "P-256",
  kty: "EC",
  x: "KNNlYniur1Lqz71meugVtO8Up39X-arb-xw0cLsx1xc",
  y: "PwXAe1n1PqrfXRkN_gdF7_QJ7ec1Yo26gCNRbNUKrEQ",
};

const correctRequestObject: AuthorizationRequestObject = {
  client_id: "x509_hash:test-client-id",
  client_metadata: {
    jwks: {
      keys: [publicKey],
    },
    vp_formats_supported: {
      jwt_vp_json: {
        alg_values_supported: ["ES256"],
      },
    },
  },
  dcql_query: {},
  exp: new Date("2035-09-15").getTime(),
  iat: new Date("2025-09-15").getTime(),
  iss: "x509_hash:test-client-id",
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
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X2hhc2gjdGVzdC1jbGllbnQtaWQiLCJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsIngiOiJLTk5sWW5pdXIxTHF6NzFtZXVnVnRPOFVwMzlYLWFyYi14dzBjTHN4MXhjIiwieSI6IlB3WEFlMW4xUHFyZlhSa05fZ2RGN19RSjdlYzFZbzI2Z0NOUmJOVUtyRVEiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2In1dfSwidnBfZm9ybWF0c19zdXBwb3J0ZWQiOnsiand0X3ZwX2pzb24iOnsiYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXX19fSwicmVzcG9uc2VfdXJpIjoidXJpOi8vcmVzcG9uc2UuZXhhbXBsZS5jb20iLCJyZXF1ZXN0X3VyaSI6InVyaTovL3JlcXVlc3QuZXhhbXBsZS5jb20iLCJyZXF1ZXN0X3VyaV9tZXRob2QiOiJQT1NUIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsIm5vbmNlIjoidGVzdF9ub25jZSIsIndhbGxldF9ub25jZSI6IlRlc3Qgd2FsbGV0IG5vbmNlIiwic2NvcGUiOiJ0ZXN0X3ByZXNlbnRhdGlvbl9zY29wZSIsInN0YXRlIjoidGVzdF9zdGF0ZSIsImRjcWxfcXVlcnkiOnt9LCJpc3MiOiJ4NTA5X2hhc2gjdGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MjA3MzQyNzIwMDAwMH0.dgsesQ8MU4cdDF9XBjdXToOLyGZ42bhE_AaKE3Zf7sy87HVBzIb4Qn9l5unwWbeTATtXscFdRRjwdw7ZGA-BlQ";

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
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X2hhc2gjdGVzdC1jbGllbnQtaWQiLCJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsIngiOiJLTk5sWW5pdXIxTHF6NzFtZXVnVnRPOFVwMzlYLWFyYi14dzBjTHN4MXhjIiwieSI6IlB3WEFlMW4xUHFyZlhSa05fZ2RGN19RSjdlYzFZbzI2Z0NOUmJOVUtyRVEiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2In1dfSwidnBfZm9ybWF0c19zdXBwb3J0ZWQiOnsiand0X3ZwX2pzb24iOnsiYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXX19fSwicmVzcG9uc2VfdXJpIjoidXJpOi8vcmVzcG9uc2UuZXhhbXBsZS5jb20iLCJyZXF1ZXN0X3VyaSI6InVyaTovL3JlcXVlc3QuZXhhbXBsZS5jb20iLCJyZXF1ZXN0X3VyaV9tZXRob2QiOiJQT1NUIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsIm5vbmNlIjoidGVzdF9ub25jZSIsIndhbGxldF9ub25jZSI6IlRlc3Qgd2FsbGV0IG5vbmNlIiwic2NvcGUiOiJ0ZXN0X3ByZXNlbnRhdGlvbl9zY29wZSIsInN0YXRlIjoidGVzdF9zdGF0ZSIsImRjcWxfcXVlcnkiOnt9LCJpc3MiOiJ4NTA5X2hhc2gjdGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MTc1Nzk4MDgwMDAwMH0.aKGEjOQlOXNgKI3Uoexj6LpNuljLpCG4FhRB7ny1LCM6eZNgi0ynvOjw-t3smktAVQO9cEGpuSrKxcZhjLLltg";

/**
 * JWT signed with a different key (signature doesn't match the public key in the payload)
 */
const wrongSignedRequestObjectJwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X2hhc2gjdGVzdC1jbGllbnQtaWQiLCJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsIngiOiJLTk5sWW5pdXIxTHF6NzFtZXVnVnRPOFVwMzlYLWFyYi14dzBjTHN4MXhjIiwieSI6IlB3WEFlMW4xUHFyZlhSa05fZ2RGN19RSjdlYzFZbzI2Z0NOUmJOVUtyRVEiLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2In1dfSwidnBfZm9ybWF0c19zdXBwb3J0ZWQiOnsiand0X3ZwX2pzb24iOnsiYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXX19fSwicmVzcG9uc2VfdXJpIjoidXJpOi8vcmVzcG9uc2UuZXhhbXBsZS5jb20iLCJyZXF1ZXN0X3VyaSI6InVyaTovL3JlcXVlc3QuZXhhbXBsZS5jb20iLCJyZXF1ZXN0X3VyaV9tZXRob2QiOiJQT1NUIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsIm5vbmNlIjoidGVzdF9ub25jZSIsIndhbGxldF9ub25jZSI6IlRlc3Qgd2FsbGV0IG5vbmNlIiwic2NvcGUiOiJ0ZXN0X3ByZXNlbnRhdGlvbl9zY29wZSIsInN0YXRlIjoidGVzdF9zdGF0ZSIsImRjcWxfcXVlcnkiOnt9LCJpc3MiOiJ4NTA5X2hhc2gjdGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MjA3MzQyNzIwMDAwMH0.p8kt3WZ-vd-AgkZG7HkuqplxGfrFISq6Eb7kHlnqkID-q90HreduLenpM7fV2o8BH6Uzx1MS3Ueo_DroK5KgGA";

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
      requestObjectJwt: correctRequestObjectJwt,
    });
    expect(actualRequestObject).toEqual(correctRequestObject);
  });

  it("should throw a ValidationError for missing mandatory fields", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          requestObjectJwt: missingMandatoryFieldRequestObjectJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should throw a ValidationError for non conforming structure", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          requestObjectJwt: nonConformingRequestObjectJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should parse and verify the request object correctly since expiration is not checked", async () => {
    const actualRequestObject = await parseAuthorizeRequest({
      callbacks,
      requestObjectJwt: expiredRequestObjectJwt,
    });
    expect(actualRequestObject).toEqual(expiredRequestObject);
  });

  it("should throw an Oauth2JwtParseError because of a malformed jwt", async () => {
    await expect(async () =>
      parseAuthorizeRequest({
        callbacks,
        requestObjectJwt: "this is not a JWT",
      }),
    ).rejects.toThrow(Oauth2JwtParseError);
  });

  it("should throw an ParseAuthroizeRequestError because of a malformed signature", async () => {
    await expect(async () => {
      const [head, payload] = correctRequestObjectJwt.split(".");
      await parseAuthorizeRequest({
        callbacks,
        requestObjectJwt: `${head}.${payload}.this_is_not_a_signature`,
      });
    }).rejects.toThrow(ParseAuthorizeRequestError);
  });

  it("should throw an ParseAuthorizeRequestError because of a missing signature", async () => {
    await expect(async () => {
      const [head, payload] = correctRequestObjectJwt.split(".");
      await parseAuthorizeRequest({
        callbacks,
        requestObjectJwt: `${head}.${payload}.`,
      });
    }).rejects.toThrow(ParseAuthorizeRequestError);
  });

  it("should throw an ParseAuthorizeRequestError because of a mismatching public key signer", async () => {
    await expect(async () => {
      await parseAuthorizeRequest({
        callbacks,
        requestObjectJwt: wrongSignedRequestObjectJwt,
      });
    }).rejects.toThrow(ParseAuthorizeRequestError);
  });

  it("should throw a ValidationError for invalid header typ field", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
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
          requestObjectJwt: jwtWithEmptyTrustChain,
        }),
    ).rejects.toThrow(ValidationError);
  });
});
