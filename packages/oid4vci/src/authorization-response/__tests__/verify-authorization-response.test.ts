import { JwtSignerJwk, VerifyJwtCallback } from "@openid4vc/oauth2";
import { Base64 } from "js-base64";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Oid4vciError } from "../../errors";
import {
  VerifyAuthorizationResponseFormPostJWTOptions,
  VerifyAuthorizationResponseOptions,
  verifyAuthorizationResponse,
  verifyAuthorizationResponseFormPostJWT,
} from "../verify-authorization-response";
import { AuthorizationResponse } from "../z-access-code";

const TEST_ISSUER = "test_issuer";
const WRONG_ISSUER = "wrong_issuer";
const TEST_STATE = "test_state";
const WRONG_STATE = "wrong_state";
const TEST_ACCESS_CODE = "test_code";

const TEST_AUTHORIZATION_RESPONSE = {
  code: TEST_ACCESS_CODE,
  iss: TEST_ISSUER,
  state: TEST_STATE,
} satisfies AuthorizationResponse;

function payloadToJwt(payload: Record<string, unknown>, signature: boolean) {
  const header = { alg: "ES256" };

  const headerEncoded = Base64.encode(JSON.stringify(header), true);
  const payloadEncoded = Base64.encode(JSON.stringify(payload), true);

  return `${headerEncoded}.${payloadEncoded}${signature ? ".SIGNATURE" : ""}`;
}

describe("verifyAuthorizationResponse tests", () => {
  const baseOptions: VerifyAuthorizationResponseOptions = {
    authorizationResponse: TEST_AUTHORIZATION_RESPONSE,
    iss: TEST_ISSUER,
    state: TEST_STATE,
  };

  it("should match the provided iss and state fields successfully", async () => {
    const response = await verifyAuthorizationResponse(baseOptions);

    expect(response).toBe(baseOptions.authorizationResponse);
  });

  it("should throw an Oid4vciError in case the passed iss does not match", async () => {
    await expect(
      verifyAuthorizationResponse({
        ...baseOptions,
        authorizationResponse: {
          ...TEST_AUTHORIZATION_RESPONSE,
          iss: WRONG_ISSUER,
        },
      }),
    ).rejects.toThrowError(Oid4vciError);
  });

  it("should throw an Oid4vciError in case the passed state does not match", async () => {
    await expect(
      verifyAuthorizationResponse({
        ...baseOptions,
        authorizationResponse: {
          ...TEST_AUTHORIZATION_RESPONSE,
          state: WRONG_STATE,
        },
      }),
    ).rejects.toThrowError(Oid4vciError);
  });
});

describe("verifyAuthorizationResponseFormPostJWT tests", () => {
  const mockVerifyJwt = vi.fn();
  const baseOptions: VerifyAuthorizationResponseFormPostJWTOptions = {
    authorizationResponseCompact: payloadToJwt(
      {
        code: TEST_ACCESS_CODE,
        iss: TEST_ISSUER,
        state: TEST_STATE,
      },
      true,
    ),
    authorizationResponseDecoded: {
      header: {
        alg: "ES256",
      },
      payload: {
        code: TEST_ACCESS_CODE,
        iss: TEST_ISSUER,
        state: TEST_STATE,
      },
      signature: "SIGNATURE",
    },
    callbacks: {
      verifyJwt: mockVerifyJwt,
    },
    iss: TEST_ISSUER,
    signer: {
      alg: "ES256",
      method: "jwk",
      publicJwk: {
        kty: "EC",
      },
    },
    state: TEST_STATE,
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should verify the jwt signature and compare the fields successfully", async () => {
    const mockVerification: Awaited<ReturnType<VerifyJwtCallback>> = {
      signerJwk: {
        kty: "EC",
      },
      verified: true,
    };
    mockVerifyJwt.mockResolvedValue(mockVerification);

    const result = await verifyAuthorizationResponseFormPostJWT(baseOptions);

    expect(mockVerifyJwt.mock.settledResults[0]?.value.signerJwk).toEqual(
      (baseOptions.signer as JwtSignerJwk).publicJwk,
    );

    expect(result).toEqual({
      code: TEST_ACCESS_CODE,
      iss: TEST_ISSUER,
      state: TEST_STATE,
    });
  });

  it("should throw an Oid4vciError in case signature verification fails", async () => {
    const mockVerification: Awaited<ReturnType<VerifyJwtCallback>> = {
      verified: false,
    };
    mockVerifyJwt.mockResolvedValue(mockVerification);

    const promisedResult = verifyAuthorizationResponseFormPostJWT(baseOptions);

    await expect(promisedResult).rejects.toThrow(Oid4vciError);
    await expect(promisedResult).rejects.toThrow(
      /Error verifying JWT signature/,
    );
  });

  it("should throw an Oid4vciError in case signature verification throws", async () => {
    mockVerifyJwt.mockRejectedValue(new Error("SPY ERROR"));

    const promisedResult = verifyAuthorizationResponseFormPostJWT(baseOptions);

    await expect(promisedResult).rejects.toThrow(Oid4vciError);
    await expect(promisedResult).rejects.toThrow(/SPY ERROR/);
  });

  it("should throw an Oid4vciError in case the iss fields don't match", async () => {
    const mockVerification: Awaited<ReturnType<VerifyJwtCallback>> = {
      signerJwk: {
        kty: "EC",
      },
      verified: true,
    };
    mockVerifyJwt.mockResolvedValue(mockVerification);

    const modifiedOptions: VerifyAuthorizationResponseFormPostJWTOptions = {
      ...baseOptions,
      iss: WRONG_ISSUER,
    };

    const promisedResult =
      verifyAuthorizationResponseFormPostJWT(modifiedOptions);

    await expect(promisedResult).rejects.toThrow(Oid4vciError);
    await expect(promisedResult).rejects.toThrow(/iss/);
  });

  it("should throw an Oid4vciError in case the state fields don't match", async () => {
    const mockVerification: Awaited<ReturnType<VerifyJwtCallback>> = {
      signerJwk: {
        kty: "EC",
      },
      verified: true,
    };
    mockVerifyJwt.mockResolvedValue(mockVerification);

    const modifiedOptions: VerifyAuthorizationResponseFormPostJWTOptions = {
      ...baseOptions,
      state: WRONG_STATE,
    };

    const promisedResult =
      verifyAuthorizationResponseFormPostJWT(modifiedOptions);

    await expect(promisedResult).rejects.toThrow(Oid4vciError);
    await expect(promisedResult).rejects.toThrow(/state/);
  });
});
