import { CallbackContext, Oauth2JwtParseError } from "@openid4vc/oauth2";
import { Jwk } from "@pagopa/io-wallet-oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { describe, expect, it } from "vitest";

import { ParseAuthorizeRequestError } from "../../errors";
import { parseAuthorizeRequest } from "../parse-authorization-request";
import { Openid4vpAuthorizationRequestPayload } from "../z-authorization-request";

const publicKey = {
  alg: "ES256",
  crv: "P-256",
  kid: "test-kid",
  kty: "EC",
  x: "GOVegGwq0WVkJNCFR9QTEDp6bh7P3JEdNmDViLlm4uM",
  y: "AZYh0LPvXb2U6Oxlzc6HhMsT1yh_N-qhNKZ2Q6kCpOM",
};

const configV1_0 = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
});

const configV1_3 = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
});

const encodeJwtPart = (value: unknown): string =>
  Buffer.from(JSON.stringify(value), "utf8")
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");

const createJwt = (options: {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
}) =>
  `${encodeJwtPart(options.header)}.${encodeJwtPart(options.payload)}.${options.signature}`;

const validFederationHeader = {
  alg: "ES256",
  kid: "test-kid",
  trust_chain: ["entity-statement-jwt"],
  typ: "oauth-authz-req+jwt",
};

const validX5cHeader = {
  alg: "ES256",
  kid: "test-kid",
  typ: "oauth-authz-req+jwt",
  x5c: ["MIIBxxx..."],
};

const wrongSignature =
  "hz5ipVxKrKozy-QFaer1E_5GowddzQr-wtAiKv_GQpSKj6ySi7UklVw4TXjur_FvpqK_uh37xrPdUsW4qQ3YdQ";

const correctRequestObject: Openid4vpAuthorizationRequestPayload = {
  client_id: "test-client-id",
  client_metadata: {
    application_type: "web",
    client_id: "https://relying-party.example.org",
    client_name: "Example Relying Party",
    encrypted_response_enc_values_supported: ["A256GCM"],
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
    logo_uri: "https://relying-party.example.org/public/compact-logo.svg",
    request_uris: ["https://relying-party.example.org/request_uri"],
    response_uris: ["https://relying-party.example.org/response_uri"],
    vp_formats_supported: {
      "dc+sd-jwt": {
        "kb-jwt_alg_values": ["ES256"],
        "sd-jwt_alg_values": ["ES256"],
      },
    },
  },
  dcql_query: {},
  exp: new Date("2035-09-15").getTime(),
  iat: new Date("2025-09-15").getTime(),
  iss: "test-client-id",
  nonce: "test_nonce",
  request_uri: "https://request.example.com",
  request_uri_method: "POST",
  response_mode: "direct_post.jwt",
  response_type: "vp_token",
  response_uri: "https://response.example.com",
  scope: "test_presentation_scope",
  state: "test_state",
  wallet_nonce: "Test wallet nonce",
};

const expiredRequestObject = {
  ...correctRequestObject,
  exp: new Date("2025-09-16").getTime(),
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const { response_type: _, ...missingMandatoryFieldRequestObject } =
  correctRequestObject;

const nonConformingRequestObject = {
  ...correctRequestObject,
  dcql_query: [],
  request_uri: undefined,
  response_mode: "direct_post",
  response_type: 3,
  response_uri: "this is not a uri",
};

const x509RequestObject: Openid4vpAuthorizationRequestPayload = {
  ...correctRequestObject,
  client_id: "x509_hash:test-client-id",
  iss: "x509_hash:test-client-id",
};

const correctRequestObjectJwt = createJwt({
  header: validFederationHeader,
  payload: correctRequestObject,
  signature: "valid_signature",
});

const missingMandatoryFieldRequestObjectJwt = createJwt({
  header: validFederationHeader,
  payload: missingMandatoryFieldRequestObject,
  signature: "valid_signature",
});

const nonConformingRequestObjectJwt = createJwt({
  header: validFederationHeader,
  payload: nonConformingRequestObject,
  signature: "valid_signature",
});

const expiredRequestObjectJwt = createJwt({
  header: validFederationHeader,
  payload: expiredRequestObject,
  signature: "valid_signature",
});

const wrongSignedRequestObjectJwt = createJwt({
  header: validFederationHeader,
  payload: correctRequestObject,
  signature: wrongSignature,
});

const invalidHeaderTypJwt = createJwt({
  header: { ...validFederationHeader, typ: "jwt" },
  payload: correctRequestObject,
  signature: "valid_signature",
});

const x509RequestObjectJwt = createJwt({
  header: validX5cHeader,
  payload: x509RequestObject,
  signature: "valid_x509_signature",
});

// V1_3 header for openid_federation / no-prefix without trust_chain (delegation scenario)
const v1_3FederationHeaderNoTrustChain = {
  alg: "ES256",
  kid: "test-kid",
  typ: "oauth-authz-req+jwt",
  x5c: ["MIIBxxx..."],
};

const v1_3FederationNoTrustChainJwt = createJwt({
  header: v1_3FederationHeaderNoTrustChain,
  payload: correctRequestObject,
  signature: "valid_signature",
});

const v1_3FederationClientIdNoTrustChainJwt = createJwt({
  header: v1_3FederationHeaderNoTrustChain,
  payload: {
    ...correctRequestObject,
    client_id: "openid_federation:test-client-id",
    iss: "openid_federation:test-client-id",
  },
  signature: "valid_signature",
});

const x509RequestObjectMissingX5cJwt = createJwt({
  header: {
    alg: "ES256",
    kid: "test-kid",
    typ: "oauth-authz-req+jwt",
  },
  payload: x509RequestObject,
  signature: "some_signature",
});

const requestObjectWithTransactionDataJwt = createJwt({
  header: validFederationHeader,
  payload: {
    ...correctRequestObject,
    transaction_data: ["ZXhhbXBsZV90cmFuc2FjdGlvbl9kYXRh"],
  },
  signature: "valid_transaction_data_signature",
});

const callbacks: Pick<CallbackContext, "verifyJwt"> = {
  verifyJwt: async (signer, { compact }) => {
    const parts = compact.split(".");
    const signature = parts[2];

    if (signer.method === "federation") {
      if (
        !signature ||
        signature === "invalid_signature" ||
        signature === "this_is_not_a_signature" ||
        signature === wrongSignature
      ) {
        return { verified: false };
      }

      return {
        signerJwk: publicKey as Jwk,
        verified: true,
      };
    }

    if (signer.method === "x5c") {
      if (
        !Array.isArray(signer.x5c) ||
        signer.x5c.length === 0 ||
        !signature ||
        signature === "invalid_signature" ||
        signature === "this_is_not_a_signature"
      ) {
        return { verified: false };
      }

      return {
        signerJwk: publicKey as Jwk,
        verified: true,
      };
    }

    if (signer.method === "jwk") {
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
      config: configV1_0,
      requestObjectJwt: correctRequestObjectJwt,
    });
    expect(actualRequestObject.payload).toEqual(correctRequestObject);
    expect(actualRequestObject.header.typ).toBe("oauth-authz-req+jwt");
    expect(actualRequestObject.header.alg).toBeDefined();
    expect(actualRequestObject.header.trust_chain).toBeDefined();
    expect(actualRequestObject.header.kid).toBeDefined();
  });

  it("should throw a ValidationError for missing mandatory fields", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          config: configV1_0,
          requestObjectJwt: missingMandatoryFieldRequestObjectJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should throw a ValidationError for non conforming structure", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          config: configV1_0,
          requestObjectJwt: nonConformingRequestObjectJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should parse and verify the request object correctly since expiration is not checked", async () => {
    const actualRequestObject = await parseAuthorizeRequest({
      callbacks,
      config: configV1_0,
      requestObjectJwt: expiredRequestObjectJwt,
    });
    expect(actualRequestObject.payload).toEqual(expiredRequestObject);
    expect(actualRequestObject.header.typ).toBe("oauth-authz-req+jwt");
    expect(actualRequestObject.header.alg).toBeDefined();
    expect(actualRequestObject.header.trust_chain).toBeDefined();
    expect(actualRequestObject.header.kid).toBeDefined();
  });

  it("should throw an Oauth2JwtParseError because of a malformed jwt", async () => {
    await expect(async () =>
      parseAuthorizeRequest({
        callbacks,
        config: configV1_0,
        requestObjectJwt: "this is not a JWT",
      }),
    ).rejects.toThrow(Oauth2JwtParseError);
  });

  it("should throw an ParseAuthroizeRequestError because of a malformed signature", async () => {
    await expect(async () => {
      const [head, payload] = correctRequestObjectJwt.split(".");
      await parseAuthorizeRequest({
        callbacks,
        config: configV1_0,
        requestObjectJwt: `${head}.${payload}.this_is_not_a_signature`,
      });
    }).rejects.toThrow(ParseAuthorizeRequestError);
  });

  it("should throw an ParseAuthorizeRequestError because of a missing signature", async () => {
    await expect(async () => {
      const [head, payload] = correctRequestObjectJwt.split(".");
      await parseAuthorizeRequest({
        callbacks,
        config: configV1_0,
        requestObjectJwt: `${head}.${payload}.`,
      });
    }).rejects.toThrow(ParseAuthorizeRequestError);
  });

  it("should throw an ParseAuthorizeRequestError because of a mismatching public key signer", async () => {
    await expect(async () => {
      await parseAuthorizeRequest({
        callbacks,
        config: configV1_0,
        requestObjectJwt: wrongSignedRequestObjectJwt,
      });
    }).rejects.toThrow(ParseAuthorizeRequestError);
  });

  it("should throw a ValidationError for invalid header typ field", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          config: configV1_0,
          requestObjectJwt: invalidHeaderTypJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should throw a ValidationError for missing alg field in header", async () => {
    const missingAlgJwt = createJwt({
      header: {
        kid: "test-kid",
        trust_chain: ["entity-statement-jwt"],
        typ: "oauth-authz-req+jwt",
      },
      payload: correctRequestObject,
      signature: "invalid_signature",
    });

    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          config: configV1_0,
          requestObjectJwt: missingAlgJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should throw a ValidationError for empty trust_chain array", async () => {
    const jwtWithEmptyTrustChain = createJwt({
      header: {
        alg: "ES256",
        kid: "test-kid",
        trust_chain: [],
        typ: "oauth-authz-req+jwt",
      },
      payload: correctRequestObject,
      signature: "invalid_signature",
    });

    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          config: configV1_0,
          requestObjectJwt: jwtWithEmptyTrustChain,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should parse and verify the request object with x509_hash client_id correctly", async () => {
    const actualRequestObject = await parseAuthorizeRequest({
      callbacks,
      config: configV1_3,
      requestObjectJwt: x509RequestObjectJwt,
    });
    expect(actualRequestObject.payload).toEqual(x509RequestObject);
    expect(actualRequestObject.header.x5c).toBeDefined();
  });

  it("should throw a ValidationError for x509_hash client_id with missing x5c in header", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          callbacks,
          config: configV1_3,
          requestObjectJwt: x509RequestObjectMissingX5cJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should parse V1_3 request with no-prefix client_id and no trust_chain, delegating to verifyJwt", async () => {
    const result = await parseAuthorizeRequest({
      callbacks,
      config: configV1_3,
      requestObjectJwt: v1_3FederationNoTrustChainJwt,
    });
    expect(result.payload).toEqual(correctRequestObject);
    expect(result.header.trust_chain).toBeUndefined();
  });

  it("should parse V1_3 request with openid_federation client_id and no trust_chain, delegating to verifyJwt", async () => {
    const result = await parseAuthorizeRequest({
      callbacks,
      config: configV1_3,
      requestObjectJwt: v1_3FederationClientIdNoTrustChainJwt,
    });
    expect(result.header.trust_chain).toBeUndefined();
  });
});

describe("parseAuthorizeRequest - transaction_data support", () => {
  it("should parse request object with transaction_data field", async () => {
    const result = await parseAuthorizeRequest({
      config: configV1_0,
      requestObjectJwt: requestObjectWithTransactionDataJwt,
    });

    expect(result.payload.transaction_data).toBeDefined();
    expect(result.payload.transaction_data).toEqual([
      "ZXhhbXBsZV90cmFuc2FjdGlvbl9kYXRh",
    ]);
  });
});

describe("parseAuthorizeRequest - optional verification", () => {
  it("should parse request object without verification when callbacks is undefined", async () => {
    const result = await parseAuthorizeRequest({
      config: configV1_0,
      requestObjectJwt: correctRequestObjectJwt,
    });

    expect(result.payload).toEqual(correctRequestObject);
    expect(result.header).toBeDefined();
    expect(result.header.alg).toBe("ES256");
    expect(result.header.trust_chain).toBeDefined();
  });

  it("should parse x509_hash request without verification when callbacks is not provided", async () => {
    const result = await parseAuthorizeRequest({
      config: configV1_3,
      requestObjectJwt: x509RequestObjectJwt,
    });

    expect(result.payload).toEqual(x509RequestObject);
    expect(result.header.x5c).toBeDefined();
  });

  it("should accept wrongly signed JWT when verification is disabled", async () => {
    const result = await parseAuthorizeRequest({
      config: configV1_0,
      requestObjectJwt: wrongSignedRequestObjectJwt,
    });

    expect(result.payload).toEqual(correctRequestObject);
    expect(result.header).toBeDefined();
  });

  it("should still validate JWT structure even without verification", async () => {
    const malformedJwt = "not.a.valid.jwt.structure";

    await expect(
      async () =>
        await parseAuthorizeRequest({
          config: configV1_0,
          requestObjectJwt: malformedJwt,
        }),
    ).rejects.toThrow(Oauth2JwtParseError);
  });

  it("should still validate payload schema even without verification", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          config: configV1_0,
          requestObjectJwt: missingMandatoryFieldRequestObjectJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });

  it("should still validate header schema even without verification", async () => {
    await expect(
      async () =>
        await parseAuthorizeRequest({
          config: configV1_0,
          requestObjectJwt: invalidHeaderTypJwt,
        }),
    ).rejects.toThrow(ValidationError);
  });
});
