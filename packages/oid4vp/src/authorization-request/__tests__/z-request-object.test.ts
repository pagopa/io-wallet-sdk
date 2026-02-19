import { describe, expect, it } from "vitest";

import { zOpenid4vpAuthorizationRequestPayload } from "../z-request-object";

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

  it("should fail when iss is missing", () => {
    const result = zOpenid4vpAuthorizationRequestPayload.safeParse(basePayload);
    expect(result.success).toBe(false);
  });

  it("should fail when iss is not a string", () => {
    const result = zOpenid4vpAuthorizationRequestPayload.safeParse({
      ...basePayload,
      iss: 123,
    });
    expect(result.success).toBe(false);
  });
});
