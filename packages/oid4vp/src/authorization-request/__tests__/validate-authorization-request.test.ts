import { describe, expect, it } from "vitest";

import { InvalidRequestUriMethodError, Oid4vpError } from "../../errors";
import { validateAuthorizationRequestParams } from "../validate-authorization-request";

describe("validateAuthorizationRequestParams", () => {
  it("should throw error when both request and request_uri are present", () => {
    expect(() =>
      validateAuthorizationRequestParams({
        request: "eyJhbGc...",
        request_uri: "https://example.com/request",
        client_id: "test-client",
      }),
    ).toThrow(Oid4vpError);
    expect(() =>
      validateAuthorizationRequestParams({
        request: "eyJhbGc...",
        request_uri: "https://example.com/request",
        client_id: "test-client",
      }),
    ).toThrow("request and request_uri cannot both be present");
  });

  it("should throw error when neither request nor request_uri is present", () => {
    expect(() =>
      validateAuthorizationRequestParams({
        client_id: "test-client",
      }),
    ).toThrow(Oid4vpError);
    expect(() =>
      validateAuthorizationRequestParams({
        client_id: "test-client",
      }),
    ).toThrow("Either request or request_uri parameter must be present");
  });

  it("should throw InvalidRequestUriMethodError for invalid request_uri_method", () => {
    expect(() =>
      validateAuthorizationRequestParams({
        request_uri: "https://example.com/request",
        request_uri_method: "PUT" as any,
        client_id: "test-client",
      }),
    ).toThrow(InvalidRequestUriMethodError);
    expect(() =>
      validateAuthorizationRequestParams({
        request_uri: "https://example.com/request",
        request_uri_method: "DELETE" as any,
        client_id: "test-client",
      }),
    ).toThrow("Must be 'get' or 'post'");
  });

  it("should throw error when request_uri_method used without request_uri", () => {
    expect(() =>
      validateAuthorizationRequestParams({
        request: "eyJhbGc...",
        request_uri_method: "post",
        client_id: "test-client",
      }),
    ).toThrow(Oid4vpError);
    expect(() =>
      validateAuthorizationRequestParams({
        request: "eyJhbGc...",
        request_uri_method: "post",
        client_id: "test-client",
      }),
    ).toThrow(
      "request_uri_method can only be used with request_uri parameter",
    );
  });

  it("should validate successfully with request parameter", () => {
    const params = {
      request: "eyJhbGc...",
      client_id: "test-client",
    };
    const result = validateAuthorizationRequestParams(params);
    expect(result.request).toBe("eyJhbGc...");
    expect(result.request_uri).toBeUndefined();
  });

  it("should validate successfully with request_uri parameter", () => {
    const params = {
      request_uri: "https://example.com/request",
      client_id: "test-client",
      request_uri_method: "post" as const,
    };
    const result = validateAuthorizationRequestParams(params);
    expect(result.request_uri).toBe("https://example.com/request");
    expect(result.request_uri_method).toBe("post");
    expect(result.request).toBeUndefined();
  });

  it("should normalize request_uri_method case insensitively", () => {
    const params1 = {
      request_uri: "https://example.com/request",
      request_uri_method: "GET" as any,
      client_id: "test-client",
    };
    expect(() => validateAuthorizationRequestParams(params1)).not.toThrow();

    const params2 = {
      request_uri: "https://example.com/request",
      request_uri_method: "Post" as any,
      client_id: "test-client",
    };
    expect(() => validateAuthorizationRequestParams(params2)).not.toThrow();
  });
});
