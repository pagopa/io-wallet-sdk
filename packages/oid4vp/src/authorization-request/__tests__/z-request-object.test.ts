import { describe, expect, it } from "vitest";

import {
  zOpenid4vpAuthorizationRequestHeaderV1_0,
  zOpenid4vpAuthorizationRequestHeaderV1_3,
  zOpenid4vpAuthorizationRequestPayload,
} from "../z-authorization-request";

const basePayload = {
  client_id: "https://verifier.example.com",
  dcql_query: { credentials: [] },
  nonce: "n-0S6_WzA2Mj",
  response_mode: "direct_post.jwt" as const,
  response_type: "vp_token" as const,
  response_uri: "https://verifier.example.com/response",
  state: "abc123",
};

describe("zOpenid4vpAuthorizationRequestPayload", () => {
  it("should parse successfully when iss is present", () => {
    const result = zOpenid4vpAuthorizationRequestPayload.safeParse({
      ...basePayload,
      iss: "https://verifier.example.com",
    });
    expect(result.success).toBe(true);
  });

  it("should fail when iss is not a string", () => {
    const result = zOpenid4vpAuthorizationRequestPayload.safeParse({
      ...basePayload,
      iss: 123,
    });
    expect(result.success).toBe(false);
  });

  it("should fail when dcql_query is missing", () => {
    const result = zOpenid4vpAuthorizationRequestPayload.safeParse({
      client_id: basePayload.client_id,
      iss: "https://verifier.example.com",
      nonce: basePayload.nonce,
      response_mode: basePayload.response_mode,
      response_type: basePayload.response_type,
      response_uri: basePayload.response_uri,
      state: basePayload.state,
    });
    expect(result.success).toBe(false);
  });

  it("should fail when response_uri is missing", () => {
    const result = zOpenid4vpAuthorizationRequestPayload.safeParse({
      client_id: basePayload.client_id,
      dcql_query: basePayload.dcql_query,
      iss: "https://verifier.example.com",
      nonce: basePayload.nonce,
      response_mode: basePayload.response_mode,
      response_type: basePayload.response_type,
      state: basePayload.state,
    });
    expect(result.success).toBe(false);
  });
});

describe("zOpenid4vpAuthorizationRequestHeader", () => {
  it("should accept V1_3 headers with x5c", () => {
    const result = zOpenid4vpAuthorizationRequestHeaderV1_3.safeParse({
      alg: "ES256",
      kid: "kid-123",
      typ: "oauth-authz-req+jwt",
      x5c: ["leaf-certificate"],
    });

    expect(result.success).toBe(true);
  });

  it("should accept V1_3 headers without x5c", () => {
    const result = zOpenid4vpAuthorizationRequestHeaderV1_3.safeParse({
      alg: "ES256",
      kid: "kid-123",
      typ: "oauth-authz-req+jwt",
    });

    expect(result.success).toBe(true);
  });

  it("should reject V1_3 headers with an empty x5c chain", () => {
    const result = zOpenid4vpAuthorizationRequestHeaderV1_3.safeParse({
      alg: "ES256",
      kid: "kid-123",
      typ: "oauth-authz-req+jwt",
      x5c: [],
    });

    expect(result.success).toBe(false);
  });

  it("should keep trust_chain mandatory for V1_0 headers", () => {
    const result = zOpenid4vpAuthorizationRequestHeaderV1_0.safeParse({
      alg: "ES256",
      kid: "kid-123",
      typ: "oauth-authz-req+jwt",
    });

    expect(result.success).toBe(false);
  });
});
