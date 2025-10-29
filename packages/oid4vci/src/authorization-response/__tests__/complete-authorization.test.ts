import {
  UnexpectedStatusCodeError,
  ValidationError,
} from "@pagopa/io-wallet-utils";
import { Base64 } from "js-base64";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Oid4vciError } from "../../errors";
import {
  CompleteAuthorizationOptions,
  SendAuthorizationResponseAndExtractCodeOptions,
  completeAuthorization,
  sendAuthorizationResponseAndExtractCode,
} from "../complete-authorization";

const mockFetch = vi.fn();

vi.mock("@openid4vc/utils", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@openid4vc/utils")>();
  return {
    ...actual,
    createFetcher: () => mockFetch,
  };
});

const TEST_RESPONSE_URI = "https://test.response.uri";
const TEST_ISSUER = "test_issuer";
const TEST_STATE = "test_state";
const TEST_CODE = "test_code";

const MOCK_REDIRECT_URI = "https://redirect-uri.org";
const MOCK_RESPONSE_URI = "https://response-uri.org";
const MOCK_JARM = "MOCK_JARM";

function payloadToJwt(payload: Record<string, unknown>, signature: boolean) {
  const header = { alg: "ES256" };

  const headerEncoded = Base64.encode(JSON.stringify(header), true);
  const payloadEncoded = Base64.encode(JSON.stringify(payload), true);

  return `${headerEncoded}.${payloadEncoded}${signature ? ".SIGNATURE" : ""}`;
}

function buildResponseFormPostJWT(
  payload: Record<string, unknown>,
  signature: boolean,
) {
  return `<input name="response" value="${payloadToJwt(payload, signature)}"/>`;
}

describe("completeAuthorization tests", () => {
  const baseOptions: CompleteAuthorizationOptions = {
    callbacks: {
      fetch: mockFetch,
    },
    iss: TEST_ISSUER,
    response_uri: TEST_RESPONSE_URI,
    state: TEST_STATE,
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should successfully fetch and parse the authorization result", async () => {
    const mockedResponseJwt = payloadToJwt(
      {
        code: TEST_CODE,
        iss: TEST_ISSUER,
        state: TEST_STATE,
      },
      true,
    );
    const mockedResponseForm = buildResponseFormPostJWT(
      {
        code: TEST_CODE,
        iss: TEST_ISSUER,
        state: TEST_STATE,
      },
      true,
    );
    const mockResponse = {
      status: 200,
      text: vi.fn().mockResolvedValue(mockedResponseForm),
    };
    mockFetch.mockResolvedValue(mockResponse);

    const result = await completeAuthorization(baseOptions);

    expect(mockFetch).toHaveBeenCalledWith(TEST_RESPONSE_URI);

    expect(result).toEqual({
      decodedJwt: {
        header: {
          alg: "ES256",
        },
        payload: {
          code: TEST_CODE,
          iss: TEST_ISSUER,
          state: TEST_STATE,
        },
      },
      jwt: mockedResponseJwt,
    });
  });

  it("should throw UnexpectedStatusCodeError in case of an unexpected status code", async () => {
    const mockResponse = {
      headers: new Headers(),
      status: 401,
      text: vi.fn().mockResolvedValue(
        buildResponseFormPostJWT(
          {
            code: TEST_CODE,
            iss: TEST_ISSUER,
            state: TEST_STATE,
          },
          true,
        ),
      ),
      url: "example.com",
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(completeAuthorization(baseOptions)).rejects.toThrowError(
      UnexpectedStatusCodeError,
    );
  });

  it("should throw an OidvciError in case of a malformed HTML response", async () => {
    const mockResponse = {
      status: 200,
      text: vi.fn().mockResolvedValue("<div></div>"),
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(completeAuthorization(baseOptions)).rejects.toThrowError(
      /Oauth2Error/,
    );
  });

  it("should throw a Oid4vciError in case the JWT in the form is malformed", async () => {
    const mockResponse = {
      status: 200,
      text: vi
        .fn()
        .mockResolvedValue(
          buildResponseFormPostJWT({ iss: TEST_ISSUER }, false),
        ),
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(completeAuthorization(baseOptions)).rejects.toThrowError(
      Oid4vciError,
    );
  });

  it("should throw a ValidationError in case the JWT response does not contain the iss claim", async () => {
    const mockResponse = {
      status: 200,
      text: vi
        .fn()
        .mockResolvedValue(
          buildResponseFormPostJWT(
            { code: TEST_CODE, state: TEST_STATE },
            true,
          ),
        ),
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(completeAuthorization(baseOptions)).rejects.toThrowError(
      ValidationError,
    );
  });

  it("should throw a ValidationError in case the JWT response does not contain the state claim", async () => {
    const mockResponse = {
      status: 200,
      text: vi
        .fn()
        .mockResolvedValue(
          buildResponseFormPostJWT({ code: TEST_CODE, iss: TEST_ISSUER }, true),
        ),
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(completeAuthorization(baseOptions)).rejects.toThrowError(
      ValidationError,
    );
  });

  it("should throw a ValidationError in case the JWT response does not contain the code claim", async () => {
    const mockResponse = {
      status: 200,
      text: vi
        .fn()
        .mockResolvedValue(
          buildResponseFormPostJWT(
            { iss: TEST_ISSUER, state: TEST_STATE },
            true,
          ),
        ),
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(completeAuthorization(baseOptions)).rejects.toThrowError(
      ValidationError,
    );
  });

  it("should throw an Oid4vciError in case the passed iss does not match", async () => {
    const mockResponse = {
      status: 200,
      text: vi
        .fn()
        .mockResolvedValue(
          buildResponseFormPostJWT(
            { code: TEST_CODE, iss: "WRONG_ISSUER", state: TEST_STATE },
            true,
          ),
        ),
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(completeAuthorization(baseOptions)).rejects.toThrowError(
      Oid4vciError,
    );
  });

  it("should throw an Oid4vciError in case the passed state does not match", async () => {
    const mockResponse = {
      status: 200,
      text: vi
        .fn()
        .mockResolvedValue(
          buildResponseFormPostJWT(
            { code: TEST_CODE, iss: TEST_ISSUER, state: "WRONG_STATE" },
            true,
          ),
        ),
    };
    mockFetch.mockResolvedValue(mockResponse);

    await expect(completeAuthorization(baseOptions)).rejects.toThrowError(
      Oid4vciError,
    );
  });
});

describe("sendAuthorizationResponseAndExtractCode tests", () => {
  const baseOptions: SendAuthorizationResponseAndExtractCodeOptions = {
    authorizationResponseJarm: MOCK_JARM,
    callbacks: {
      fetch: mockFetch,
    },
    iss: TEST_ISSUER,
    presentationResponseUri: MOCK_RESPONSE_URI,
    state: TEST_STATE,
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should send the authorization response and obtain the code successfully", async () => {
    const firstMockResponse = {
      json: vi.fn().mockResolvedValue({
        redirect_uri: MOCK_REDIRECT_URI,
      }),
      status: 200,
    };
    mockFetch.mockResolvedValueOnce(firstMockResponse);
    const secondMockResponse = {
      status: 200,
      text: vi
        .fn()
        .mockResolvedValue(
          buildResponseFormPostJWT(
            { code: TEST_CODE, iss: TEST_ISSUER, state: TEST_STATE },
            true,
          ),
        ),
    };
    mockFetch.mockResolvedValueOnce(secondMockResponse);

    const result = await sendAuthorizationResponseAndExtractCode(baseOptions);

    expect(result).toEqual({
      decodedJwt: {
        header: {
          alg: "ES256",
        },
        payload: {
          code: TEST_CODE,
          iss: TEST_ISSUER,
          state: TEST_STATE,
        },
      },
      jwt: payloadToJwt(
        { code: TEST_CODE, iss: TEST_ISSUER, state: TEST_STATE },
        true,
      ),
    });
  });

  it("should wrap FetchAuthorizationResponseError in an Oid4vciError", async () => {
    const firstMockResponse = {
      json: vi.fn().mockRejectedValue("MOCK JSON PARSE ERROR"),
      status: 200,
    };
    mockFetch.mockResolvedValueOnce(firstMockResponse);

    const promisedResult = sendAuthorizationResponseAndExtractCode(baseOptions);
    await expect(promisedResult).rejects.toThrow(Oid4vciError);
    await expect(promisedResult).rejects.toThrow(/MOCK JSON PARSE ERROR/);
  });
});
