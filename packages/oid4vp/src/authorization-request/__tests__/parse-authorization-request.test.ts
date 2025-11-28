import { CallbackContext, Jwk, Oauth2JwtParseError } from "@openid4vc/oauth2";
import { ValidationError } from "@openid4vc/utils";
import { describe, expect, it } from "vitest";

import { ParseAuthorizeRequestError } from "../../errors";
import { parseAuthorizeRequest } from "../parse-authorization-request";
import { AuthorizationRequestObject } from "../z-request-object";

const publicKey = {
  alg: "ES256",
  crv: "P-256",
  kid: "test-kid",
  kty: "EC",
  x: "GOVegGwq0WVkJNCFR9QTEDp6bh7P3JEdNmDViLlm4uM",
  y: "AZYh0LPvXb2U6Oxlzc6HhMsT1yh_N-qhNKZ2Q6kCpOM",
};

const correctRequestObject: AuthorizationRequestObject = {
  client_id: "test-client-id",
  client_metadata: {
    jwks: {
      keys: [
        {
          alg: "ES256",
          crv: "P-256",
          kid: "test-kid",
          kty: "EC",
          x: "GOVegGwq0WVkJNCFR9QTEDp6bh7P3JEdNmDViLlm4uM",
          y: "AZYh0LPvXb2U6Oxlzc6HhMsT1yh_N-qhNKZ2Q6kCpOM",
        },
      ],
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
 * JWT with correct header containing trust_chain and kid for federation verification
 * Header: {"alg":"ES256","typ":"oauth-authz-req+jwt","kid":"test-kid","trust_chain":[...]}
 */
const correctRequestObjectJwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJraWQiOiJ0ZXN0LWtpZCIsInRydXN0X2NoYWluIjpbImV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJbVZ1ZEdsMGVTMXpkR0YwWlcxbGJuUXJhbmQwSWl3aWEybGtJam9pZEdWemRDMXJhV1FpZlEuZXlKcGMzTWlPaUowWlhOMExXTnNhV1Z1ZEMxcFpDSXNJbk4xWWlJNkluUmxjM1F0WTJ4cFpXNTBMV2xrSWl3aWFXRjBJam94TnpZME16SXlOak00TENKbGVIQWlPakl3TnprMk9ESTJNemdzSW0xbGRHRmtZWFJoSWpwN0ltOXdaVzVwWkY5amNtVmtaVzUwYVdGc1gzWmxjbWxtYVdWeUlqcDdJbXAzYTNNaU9uc2lhMlY1Y3lJNlczc2lhM1I1SWpvaVJVTWlMQ0o0SWpvaVIwOVdaV2RIZDNFd1YxWnJTazVEUmxJNVVWUkZSSEEyWW1nM1VETktSV1JPYlVSV2FVeHNiVFIxVFNJc0lua2lPaUpCV2xsb01FeFFkbGhpTWxVMlQzaHNlbU0yU0doTmMxUXhlV2hmVGkxeGFFNUxXakpSTm10RGNFOU5JaXdpWTNKMklqb2lVQzB5TlRZaUxDSmhiR2NpT2lKRlV6STFOaUlzSW10cFpDSTZJblJsYzNRdGEybGtJbjFkZlN3aWRuQmZabTl5YldGMGMxOXpkWEJ3YjNKMFpXUWlPbnNpYW5kMFgzWndYMnB6YjI0aU9uc2lZV3huWDNaaGJIVmxjMTl6ZFhCd2IzSjBaV1FpT2xzaVJWTXlOVFlpWFgxOWZYMTkuSmEzU25OMllaVXdxamZLdWtkVDR0UzNZTnk2MnJvUk9uTGtiaWV3Nkh5cEY0Vjl2OGk1cXM3aHpBdDM2T1RXaExLMW1lei1xdGlPSjQ2elRLa2F6bmciXX0.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsImNsaWVudF9tZXRhZGF0YSI6eyJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwieCI6IkdPVmVnR3dxMFdWa0pOQ0ZSOVFURURwNmJoN1AzSkVkTm1EVmlMbG00dU0iLCJ5IjoiQVpZaDBMUHZYYjJVNk94bHpjNkhoTXNUMXloX04tcWhOS1oyUTZrQ3BPTSIsImNydiI6IlAtMjU2IiwiYWxnIjoiRVMyNTYiLCJraWQiOiJ0ZXN0LWtpZCJ9XX0sInZwX2Zvcm1hdHNfc3VwcG9ydGVkIjp7Imp3dF92cF9qc29uIjp7ImFsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il19fX0sInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MjA3MzQyNzIwMDAwMH0.7l7lPk5SM2X6ygs4e_2NAE78bvQgNnZW2ngiB-nMQZJIA9KrX7Ry2iEvl5lheXADA1Qq5s372l7TodtK9pAgZQ";

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
 * Header: {"alg":"ES256","typ":"oauth-authz-req+jwt","kid":"test-kid","trust_chain":[...]}
 */
const expiredRequestObjectJwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJraWQiOiJ0ZXN0LWtpZCIsInRydXN0X2NoYWluIjpbImV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJbVZ1ZEdsMGVTMXpkR0YwWlcxbGJuUXJhbmQwSWl3aWEybGtJam9pZEdWemRDMXJhV1FpZlEuZXlKcGMzTWlPaUowWlhOMExXTnNhV1Z1ZEMxcFpDSXNJbk4xWWlJNkluUmxjM1F0WTJ4cFpXNTBMV2xrSWl3aWFXRjBJam94TnpZME16SXlOak00TENKbGVIQWlPakl3TnprMk9ESTJNemdzSW0xbGRHRmtZWFJoSWpwN0ltOXdaVzVwWkY5amNtVmtaVzUwYVdGc1gzWmxjbWxtYVdWeUlqcDdJbXAzYTNNaU9uc2lhMlY1Y3lJNlczc2lhM1I1SWpvaVJVTWlMQ0o0SWpvaVIwOVdaV2RIZDNFd1YxWnJTazVEUmxJNVVWUkZSSEEyWW1nM1VETktSV1JPYlVSV2FVeHNiVFIxVFNJc0lua2lPaUpCV2xsb01FeFFkbGhpTWxVMlQzaHNlbU0yU0doTmMxUXhlV2hmVGkxeGFFNUxXakpSTm10RGNFOU5JaXdpWTNKMklqb2lVQzB5TlRZaUxDSmhiR2NpT2lKRlV6STFOaUlzSW10cFpDSTZJblJsYzNRdGEybGtJbjFkZlN3aWRuQmZabTl5YldGMGMxOXpkWEJ3YjNKMFpXUWlPbnNpYW5kMFgzWndYMnB6YjI0aU9uc2lZV3huWDNaaGJIVmxjMTl6ZFhCd2IzSjBaV1FpT2xzaVJWTXlOVFlpWFgxOWZYMTkuSmEzU25OMllaVXdxamZLdWtkVDR0UzNZTnk2MnJvUk9uTGtiaWV3Nkh5cEY0Vjl2OGk1cXM3aHpBdDM2T1RXaExLMW1lei1xdGlPSjQ2elRLa2F6bmciXX0.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsImNsaWVudF9tZXRhZGF0YSI6eyJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwieCI6IkdPVmVnR3dxMFdWa0pOQ0ZSOVFURURwNmJoN1AzSkVkTm1EVmlMbG00dU0iLCJ5IjoiQVpZaDBMUHZYYjJVNk94bHpjNkhoTXNUMXloX04tcWhOS1oyUTZrQ3BPTSIsImNydiI6IlAtMjU2IiwiYWxnIjoiRVMyNTYiLCJraWQiOiJ0ZXN0LWtpZCJ9XX0sInZwX2Zvcm1hdHNfc3VwcG9ydGVkIjp7Imp3dF92cF9qc29uIjp7ImFsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il19fX0sInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MTc1Nzk4MDgwMDAwMH0.QTInFJg32qcOrYJkn0UkhmTO-3-IHYTffrXF9rZFomKTN2UQfeahqkhHBzSP3eil_ULIR3y6XdPZ--gmXB0_Yg";

/**
 * JWT signed with a different key (signature doesn't match the public key in the trust chain)
 */
const wrongSignedRequestObjectJwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJraWQiOiJ0ZXN0LWtpZCIsInRydXN0X2NoYWluIjpbImV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJbVZ1ZEdsMGVTMXpkR0YwWlcxbGJuUXJhbmQwSWl3aWEybGtJam9pZEdWemRDMXJhV1FpZlEuZXlKcGMzTWlPaUowWlhOMExXTnNhV1Z1ZEMxcFpDSXNJbk4xWWlJNkluUmxjM1F0WTJ4cFpXNTBMV2xrSWl3aWFXRjBJam94TnpZME16SXlOak00TENKbGVIQWlPakl3TnprMk9ESTJNemdzSW0xbGRHRmtZWFJoSWpwN0ltOXdaVzVwWkY5amNtVmtaVzUwYVdGc1gzWmxjbWxtYVdWeUlqcDdJbXAzYTNNaU9uc2lhMlY1Y3lJNlczc2lhM1I1SWpvaVJVTWlMQ0o0SWpvaVIwOVdaV2RIZDNFd1YxWnJTazVEUmxJNVVWUkZSSEEyWW1nM1VETktSV1JPYlVSV2FVeHNiVFIxVFNJc0lua2lPaUpCV2xsb01FeFFkbGhpTWxVMlQzaHNlbU0yU0doTmMxUXhlV2hmVGkxeGFFNUxXakpSTm10RGNFOU5JaXdpWTNKMklqb2lVQzB5TlRZaUxDSmhiR2NpT2lKRlV6STFOaUlzSW10cFpDSTZJblJsYzNRdGEybGtJbjFkZlN3aWRuQmZabTl5YldGMGMxOXpkWEJ3YjNKMFpXUWlPbnNpYW5kMFgzWndYMnB6YjI0aU9uc2lZV3huWDNaaGJIVmxjMTl6ZFhCd2IzSjBaV1FpT2xzaVJWTXlOVFlpWFgxOWZYMTkuSmEzU25OMllaVXdxamZLdWtkVDR0UzNZTnk2MnJvUk9uTGtiaWV3Nkh5cEY0Vjl2OGk1cXM3aHpBdDM2T1RXaExLMW1lei1xdGlPSjQ2elRLa2F6bmciXX0.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsImNsaWVudF9tZXRhZGF0YSI6eyJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IkVDIiwieCI6IkdPVmVnR3dxMFdWa0pOQ0ZSOVFURURwNmJoN1AzSkVkTm1EVmlMbG00dU0iLCJ5IjoiQVpZaDBMUHZYYjJVNk94bHpjNkhoTXNUMXloX04tcWhOS1oyUTZrQ3BPTSIsImNydiI6IlAtMjU2IiwiYWxnIjoiRVMyNTYiLCJraWQiOiJ0ZXN0LWtpZCJ9XX0sInZwX2Zvcm1hdHNfc3VwcG9ydGVkIjp7Imp3dF92cF9qc29uIjp7ImFsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il19fX0sInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MjA3MzQyNzIwMDAwMH0.hz5ipVxKrKozy-QFaer1E_5GowddzQr-wtAiKv_GQpSKj6ySi7UklVw4TXjur_FvpqK_uh37xrPdUsW4qQ3YdQ";

/**
 * JWT with invalid header typ field: {"alg":"ES256","typ":"jwt"}
 */
const invalidHeaderTypJwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Imp3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MjA3MzQyNzIwMDAwMH0.xbxwjLKeP4AJRqUwSq3e47i4QPmCs3aELuSWTH5Ad6bgu1OxG5Dlt1S6pqc9z95B_t98134H9KDowF_7NLRSGA";

/**
 * Test data for x509_hash client_id prefix
 */
const x509RequestObject: AuthorizationRequestObject = {
  client_id: "x509_hash:test-client-id",
  client_metadata: {
    jwks: {
      keys: [
        {
          alg: "ES256",
          crv: "P-256",
          kid: "test-kid",
          kty: "EC",
          x: "GOVegGwq0WVkJNCFR9QTEDp6bh7P3JEdNmDViLlm4uM",
          y: "AZYh0LPvXb2U6Oxlzc6HhMsT1yh_N-qhNKZ2Q6kCpOM",
        },
      ],
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
 * JWT with x509_hash client_id prefix and x5c in header
 * Header: {"alg":"ES256","typ":"oauth-authz-req+jwt","x5c":["MIIBxxx..."]}
 */
const x509RequestObjectJwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJ4NWMiOlsiTUlJQnh4eC4uLiJdfQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X2hhc2g6dGVzdC1jbGllbnQtaWQiLCJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsIngiOiJHT1ZlZ0d3cTBXVmtKTkNGUjlRVEVEcDZiaDdQM0pFZE5tRFZpTGxtNHVNIiwieSI6IkFaWWgwTFB2WGIyVTZPeGx6YzZIaE1zVDF5aF9OLXFoTktaMlE2a0NwT00iLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2Iiwia2lkIjoidGVzdC1raWQifV19LCJ2cF9mb3JtYXRzX3N1cHBvcnRlZCI6eyJqd3RfdnBfanNvbiI6eyJhbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFUzI1NiJdfX19LCJyZXNwb25zZV91cmkiOiJ1cmk6Ly9yZXNwb25zZS5leGFtcGxlLmNvbSIsInJlcXVlc3RfdXJpIjoidXJpOi8vcmVxdWVzdC5leGFtcGxlLmNvbSIsInJlcXVlc3RfdXJpX21ldGhvZCI6IlBPU1QiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3Quand0Iiwibm9uY2UiOiJ0ZXN0X25vbmNlIiwid2FsbGV0X25vbmNlIjoiVGVzdCB3YWxsZXQgbm9uY2UiLCJzY29wZSI6InRlc3RfcHJlc2VudGF0aW9uX3Njb3BlIiwic3RhdGUiOiJ0ZXN0X3N0YXRlIiwiZGNxbF9xdWVyeSI6e30sImlzcyI6Ing1MDlfaGFzaDp0ZXN0LWNsaWVudC1pZCIsImlhdCI6MTc1Nzg5NDQwMDAwMCwiZXhwIjoyMDczNDI3MjAwMDAwfQ.valid_x509_signature";

/**
 * JWT with x509_hash client_id prefix but missing x5c in header
 * Header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
 */
const x509RequestObjectMissingX5cJwt =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X2hhc2g6dGVzdC1jbGllbnQtaWQiLCJjbGllbnRfbWV0YWRhdGEiOnsiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsIngiOiJHT1ZlZ0d3cTBXVmtKTkNGUjlRVEVEcDZiaDdQM0pFZE5tRFZpTGxtNHVNIiwieSI6IkFaWWgwTFB2WGIyVTZPeGx6YzZIaE1zVDF5aF9OLXFoTktaMlE2a0NwT00iLCJjcnYiOiJQLTI1NiIsImFsZyI6IkVTMjU2Iiwia2lkIjoidGVzdC1raWQifV19LCJ2cF9mb3JtYXRzX3N1cHBvcnRlZCI6eyJqd3RfdnBfanNvbiI6eyJhbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFUzI1NiJdfX19LCJyZXNwb25zZV91cmkiOiJ1cmk6Ly9yZXNwb25zZS5leGFtcGxlLmNvbSIsInJlcXVlc3RfdXJpIjoidXJpOi8vcmVxdWVzdC5leGFtcGxlLmNvbSIsInJlcXVlc3RfdXJpX21ldGhvZCI6IlBPU1QiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3Quand0Iiwibm9uY2UiOiJ0ZXN0X25vbmNlIiwid2FsbGV0X25vbmNlIjoiVGVzdCB3YWxsZXQgbm9uY2UiLCJzY29wZSI6InRlc3RfcHJlc2VudGF0aW9uX3Njb3BlIiwic3RhdGUiOiJ0ZXN0X3N0YXRlIiwiZGNxbF9xdWVyeSI6e30sImlzcyI6Ing1MDlfaGFzaDp0ZXN0LWNsaWVudC1pZCIsImlhdCI6MTc1Nzg5NDQwMDAwMCwiZXhwIjoyMDczNDI3MjAwMDAwfQ.some_signature";

const callbacks: Pick<CallbackContext, "verifyJwt"> = {
  verifyJwt: async (signer, { compact }) => {
    // For federation method, verify using the trust chain
    if (signer.method === "federation") {
      // Extract signature from JWT
      const parts = compact.split(".");
      const signature = parts[2];

      // Reject empty or invalid signatures
      if (
        !signature ||
        signature === "invalid_signature" ||
        signature === "this_is_not_a_signature"
      ) {
        return { verified: false };
      }

      // Check for wrong signature (different from the expected ones)
      const wrongSignature =
        "hz5ipVxKrKozy-QFaer1E_5GowddzQr-wtAiKv_GQpSKj6ySi7UklVw4TXjur_FvpqK_uh37xrPdUsW4qQ3YdQ";
      if (signature === wrongSignature) {
        return { verified: false };
      }

      // For valid JWTs, return the public key from the expected test data
      return {
        signerJwk: publicKey as Jwk,
        verified: true,
      };
    }

    // For x5c method (x509_hash client_id)
    if (signer.method === "x5c") {
      const parts = compact.split(".");
      const signature = parts[2];

      // Reject empty or invalid signatures
      if (
        !signature ||
        signature === "invalid_signature" ||
        signature === "this_is_not_a_signature"
      ) {
        return { verified: false };
      }

      // For valid x5c JWTs, return verified
      return {
        signerJwk: publicKey as Jwk,
        verified: true,
      };
    }

    // For jwk method
    if (signer.method === "jwk") {
      const parts = compact.split(".");
      const signature = parts[2];

      if (
        !signature ||
        signature === "invalid_signature" ||
        signature === "this_is_not_a_signature"
      ) {
        return { verified: false };
      }

      return {
        signerJwk: signer.publicJwk,
        verified: true,
      };
    }

    return { verified: false };
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

  it("should parse and verify the request object with x509_hash client_id correctly", async () => {
    const actualRequestObject = await parseAuthorizeRequest({
      callbacks,
      requestObjectJwt: x509RequestObjectJwt,
    });
    expect(actualRequestObject).toEqual(x509RequestObject);
  });

  it("should throw a ParseAuthorizeRequestError for x509_hash client_id with missing x5c in header", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          requestObjectJwt: x509RequestObjectMissingX5cJwt,
        }),
    ).rejects.toThrow(ParseAuthorizeRequestError);
  });
});
