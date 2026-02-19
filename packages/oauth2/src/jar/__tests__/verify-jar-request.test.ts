/* eslint-disable max-lines-per-function */
import { CallbackContext, JwtSigner } from "@openid4vc/oauth2";
import { encodeToBase64Url } from "@pagopa/io-wallet-utils";
import { describe, expect, it, vi } from "vitest";

import { Jwk } from "../../common/jwk/z-jwk";
import { Oauth2Error } from "../../errors";
import {
  VerifyJarRequestOptions,
  verifyJarRequest,
} from "../verify-jar-request";

describe("verifyJarRequest", () => {
  const mockJwk: Jwk = {
    crv: "P-256",
    kty: "EC",
    x: "test-x",
    y: "test-y",
  };

  const mockCallbacks: Pick<CallbackContext, "verifyJwt"> = {
    verifyJwt: vi.fn(async () => ({
      signerJwk: mockJwk,
      verified: true,
    })),
  };

  const mockJwtSigner = {
    alg: "ES256",
    publicJwk: mockJwk,
  } as JwtSigner;

  const createMockJwt = (
    header: Record<string, unknown>,
    payload: Record<string, unknown>,
  ) =>
    [
      encodeToBase64Url(JSON.stringify(header)),
      encodeToBase64Url(JSON.stringify(payload)),
      "signature",
    ].join(".");

  const createMockJarJwt = (payload: Record<string, unknown>) =>
    createMockJwt({ alg: "ES256", typ: "oauth-authz-req+jwt" }, payload);

  const basePayload = {
    client_id: "client-123",
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    iss: "client-123",
    response_type: "code",
    scope: "openid",
  };

  const createOptions = (
    authorizationRequestJwt: string,
    now?: Date,
  ): VerifyJarRequestOptions => ({
    authorizationRequestJwt,
    callbacks: mockCallbacks,
    jarRequestParams: {
      client_id: "client-123",
    },
    jwtSigner: mockJwtSigner,
    now,
  });

  describe("successful validation", () => {
    it("should successfully verify a valid JAR request", async () => {
      const jarJwt = createMockJarJwt(basePayload);

      const result = await verifyJarRequest(createOptions(jarJwt));

      expect(result.authorizationRequestPayload).toBeDefined();
      expect(result.authorizationRequestPayload.client_id).toBe("client-123");
      expect(result.jwt).toBeDefined();
      expect(result.signer).toBeDefined();
    });

    it("should accept iat within 5 minutes in the past", async () => {
      const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 5 * 60;
      const jarJwt = createMockJarJwt({
        ...basePayload,
        iat: fiveMinutesAgo,
      });

      await expect(
        verifyJarRequest(createOptions(jarJwt)),
      ).resolves.toBeDefined();
    });

    it("should accept iat within clock skew tolerance in the future", async () => {
      const now = new Date();
      const nowSeconds = Math.floor(now.getTime() / 1000);
      const futureIat = nowSeconds + 30; // 30 seconds in the future

      const jarJwt = createMockJarJwt({
        ...basePayload,
        iat: futureIat,
      });

      await expect(
        verifyJarRequest(createOptions(jarJwt, now)),
      ).resolves.toBeDefined();
    });
  });

  describe("exp claim validation", () => {
    it("should throw error when exp claim is missing", async () => {
      const payloadWithoutExp = { ...basePayload };
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { exp, ...withoutExp } = payloadWithoutExp;
      const jarJwt = createMockJarJwt(withoutExp);

      await expect(verifyJarRequest(createOptions(jarJwt))).rejects.toThrow(
        new Oauth2Error("exp claim in request JWT is missing"),
      );
    });

    it("should throw error when exp claim is expired", async () => {
      const expiredTime = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
      const jarJwt = createMockJarJwt({
        ...basePayload,
        exp: expiredTime,
      });

      // The verifyJwt callback validates exp before our custom validation
      await expect(verifyJarRequest(createOptions(jarJwt))).rejects.toThrow(
        /jwt 'exp' is in the past|exp claim in request JWT is expired/,
      );
    });

    it("should accept exp exactly equal to current time", async () => {
      const now = new Date();
      const nowSeconds = Math.floor(now.getTime() / 1000);

      const jarJwt = createMockJarJwt({
        ...basePayload,
        exp: nowSeconds,
      });

      // Per JWT standards, exp is valid when equal to current time (expires after, not at)
      await expect(
        verifyJarRequest(createOptions(jarJwt, now)),
      ).resolves.toBeDefined();
    });

    it("should accept exp one second in the future", async () => {
      const now = new Date();
      const nowSeconds = Math.floor(now.getTime() / 1000);
      const futureExp = nowSeconds + 1;

      const jarJwt = createMockJarJwt({
        ...basePayload,
        exp: futureExp,
      });

      await expect(
        verifyJarRequest(createOptions(jarJwt, now)),
      ).resolves.toBeDefined();
    });
  });

  describe("iat claim validation", () => {
    it("should throw error when iat claim is missing", async () => {
      const payloadWithoutIat = { ...basePayload };
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { iat, ...withoutIat } = payloadWithoutIat;
      const jarJwt = createMockJarJwt(withoutIat);

      await expect(verifyJarRequest(createOptions(jarJwt))).rejects.toThrow(
        new Oauth2Error("iat claim in request JWT is missing"),
      );
    });

    it("should throw error when iat is more than 5 minutes old", async () => {
      const now = new Date();
      const nowSeconds = Math.floor(now.getTime() / 1000);
      const oldIat = nowSeconds - (5 * 60 + 1); // 5 minutes and 1 second ago

      const jarJwt = createMockJarJwt({
        ...basePayload,
        iat: oldIat,
      });

      await expect(
        verifyJarRequest(createOptions(jarJwt, now)),
      ).rejects.toThrow(
        new Oauth2Error(
          "iat claim in request JWT is too old (must be within 5 minutes)",
        ),
      );
    });

    it("should throw error when iat is more than clock skew tolerance in the future", async () => {
      const now = new Date();
      const nowSeconds = Math.floor(now.getTime() / 1000);
      const futureIat = nowSeconds + 61; // 61 seconds in the future (tolerance is 60)

      const jarJwt = createMockJarJwt({
        ...basePayload,
        iat: futureIat,
      });

      await expect(
        verifyJarRequest(createOptions(jarJwt, now)),
      ).rejects.toThrow(
        new Oauth2Error("iat claim in request JWT is too far in the future"),
      );
    });

    it("should accept iat exactly 5 minutes old", async () => {
      const now = new Date();
      const nowSeconds = Math.floor(now.getTime() / 1000);
      const fiveMinutesAgo = nowSeconds - 5 * 60;

      const jarJwt = createMockJarJwt({
        ...basePayload,
        iat: fiveMinutesAgo,
      });

      await expect(
        verifyJarRequest(createOptions(jarJwt, now)),
      ).resolves.toBeDefined();
    });

    it("should accept iat exactly at clock skew tolerance", async () => {
      const now = new Date();
      const nowSeconds = Math.floor(now.getTime() / 1000);
      const futureIat = nowSeconds + 60; // Exactly 60 seconds in the future

      const jarJwt = createMockJarJwt({
        ...basePayload,
        iat: futureIat,
      });

      await expect(
        verifyJarRequest(createOptions(jarJwt, now)),
      ).resolves.toBeDefined();
    });
  });

  describe("iss claim validation", () => {
    it("should throw error when iss does not match client_id", async () => {
      const jarJwt = createMockJarJwt({
        ...basePayload,
        iss: "different-client",
      });

      await expect(verifyJarRequest(createOptions(jarJwt))).rejects.toThrow(
        new Oauth2Error("iss claim in request JWT does not match client_id"),
      );
    });

    it("should accept when iss matches client_id", async () => {
      const jarJwt = createMockJarJwt({
        ...basePayload,
        iss: "client-123",
      });

      await expect(
        verifyJarRequest(createOptions(jarJwt)),
      ).resolves.toBeDefined();
    });
  });

  describe("client_id validation", () => {
    it("should throw error when client_id in JAR does not match request", async () => {
      const jarJwt = createMockJarJwt({
        ...basePayload,
        client_id: "different-client",
        iss: "different-client",
      });

      await expect(verifyJarRequest(createOptions(jarJwt))).rejects.toThrow(
        new Oauth2Error(
          "client_id does not match the request object client_id.",
        ),
      );
    });

    it("should throw error when client_id is missing in JAR payload", async () => {
      const payloadWithoutClientId = { ...basePayload };
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { client_id, ...withoutClientId } = payloadWithoutClientId;
      const jarJwt = createMockJarJwt(withoutClientId);

      // Zod schema validation catches this before our custom check
      await expect(verifyJarRequest(createOptions(jarJwt))).rejects.toThrow(
        /client_id/,
      );
    });
  });

  describe("JWT format validation", () => {
    it("should throw error when request object is not a valid JWT", async () => {
      const invalidJwt = "invalid.jwt";

      await expect(verifyJarRequest(createOptions(invalidJwt))).rejects.toThrow(
        new Oauth2Error("JAR request object is not a valid JWT."),
      );
    });

    it("should throw error when request object is encrypted (JWE)", async () => {
      // JWE has 5 parts: header.encrypted_key.iv.ciphertext.tag
      const jweToken =
        "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.encrypted_key.iv.ciphertext.tag";

      await expect(verifyJarRequest(createOptions(jweToken))).rejects.toThrow(
        new Oauth2Error("Encrypted JWE request objects are not supported."),
      );
    });

    it("should throw error when JWT has incorrect typ header", async () => {
      const jarJwt = createMockJwt(
        { alg: "ES256", typ: "invalid-typ" },
        basePayload,
      );

      await expect(verifyJarRequest(createOptions(jarJwt))).rejects.toThrow(
        new Oauth2Error(
          'Invalid Jar Request Object typ header. Expected "oauth-authz-req+jwt" or "jwt", received "invalid-typ".',
        ),
      );
    });

    it("should accept JWT with typ 'jwt'", async () => {
      const jarJwt = createMockJwt({ alg: "ES256", typ: "jwt" }, basePayload);

      await expect(
        verifyJarRequest(createOptions(jarJwt)),
      ).resolves.toBeDefined();
    });

    it("should accept JWT with typ 'oauth-authz-req+jwt'", async () => {
      const jarJwt = createMockJwt(
        { alg: "ES256", typ: "oauth-authz-req+jwt" },
        basePayload,
      );

      await expect(
        verifyJarRequest(createOptions(jarJwt)),
      ).resolves.toBeDefined();
    });
  });

  describe("combined validation scenarios", () => {
    it("should validate all claims together and fail on first error", async () => {
      const jarJwt = createMockJarJwt({
        ...basePayload,
        exp: undefined, // Missing exp
        iat: undefined, // Missing iat
        iss: "wrong-issuer", // Wrong iss
      });

      // The validation checks iss before exp in the code flow
      await expect(verifyJarRequest(createOptions(jarJwt))).rejects.toThrow(
        /iss claim in request JWT does not match client_id|exp claim in request JWT is missing/,
      );
    });

    it("should pass all validations with valid claims", async () => {
      const now = new Date();
      const nowSeconds = Math.floor(now.getTime() / 1000);

      const jarJwt = createMockJarJwt({
        client_id: "client-123",
        exp: nowSeconds + 3600, // 1 hour from now
        iat: nowSeconds - 60, // 1 minute ago
        iss: "client-123",
        response_type: "code",
        scope: "openid",
      });

      const result = await verifyJarRequest(createOptions(jarJwt, now));

      expect(result.authorizationRequestPayload.client_id).toBe("client-123");
      expect(result.authorizationRequestPayload.iss).toBe("client-123");
      expect(result.jwt.payload.exp).toBe(nowSeconds + 3600);
      expect(result.jwt.payload.iat).toBe(nowSeconds - 60);
    });
  });
});
