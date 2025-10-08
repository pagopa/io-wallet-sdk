import { JwtSigner } from "@openid4vc/oauth2";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createTokenDPoP } from "../createTokenDPoP";

const MOCKED_RANDOM = "random_string";

const callbacks = {
  generateRandom: async () => MOCKED_RANDOM,
  signJwt: vi.fn(),
};

// eslint-disable-next-line max-lines-per-function
describe("Test createTokenDPoP", () => {
  beforeEach(() => {
    callbacks.signJwt.mockClear();
  });

  it("should call signJwt with the default values", async () => {
    const header = {
      alg: "ES256",
    };
    const payload = {
      htm: "POST" as const,
      htu: "test://uri.htu",
    };

    await createTokenDPoP({
      callbacks,
      header,
      payload,
      signer: {} as JwtSigner,
    });

    expect(callbacks.signJwt).toHaveBeenCalledWith(
      {},
      {
        header: {
          ...header,
          typ: "dpop+jwt",
        },
        payload: {
          ...payload,
          jti: MOCKED_RANDOM,
        },
      },
    );
  });

  it("should pass all extra records of header and payload through", async () => {
    const header = {
      alg: "ES256",
      extra: "This is an extra record",
      extraObject: {
        title: "This is an extra object's title",
      },
    };
    const payload = {
      extra: "This is an extra record",
      extraObject: {
        label: "Label of an extra object",
      },
      htm: "POST" as const,
      htu: "test://uri.htu",
    };

    await createTokenDPoP({
      callbacks,
      header,
      payload,
      signer: {} as JwtSigner,
    });

    expect(callbacks.signJwt).toHaveBeenCalledWith(
      {},
      {
        header: {
          ...header,
          typ: "dpop+jwt",
        },
        payload: {
          ...payload,
          jti: MOCKED_RANDOM,
        },
      },
    );
  });

  it("should overwrite the typ field in the header", async () => {
    const header = {
      alg: "ES256",
      typ: "I will be overwritten",
    };
    const payload = {
      htm: "POST" as const,
      htu: "test://uri.htu",
    };

    await createTokenDPoP({
      callbacks,
      header,
      payload,
      signer: {} as JwtSigner,
    });

    expect(callbacks.signJwt).toHaveBeenCalledWith(
      {},
      {
        header: {
          ...header,
          typ: "dpop+jwt",
        },
        payload: {
          ...payload,
          jti: MOCKED_RANDOM,
        },
      },
    );
  });

  it("should use the default passed jti", async () => {
    const header = {
      alg: "ES256",
    };
    const payload = {
      htm: "POST" as const,
      htu: "test://uri.htu",
      jti: "I will not be overwritten",
    };

    await createTokenDPoP({
      callbacks,
      header,
      payload,
      signer: {} as JwtSigner,
    });

    expect(callbacks.signJwt).toHaveBeenCalledWith(
      {},
      {
        header: {
          ...header,
          typ: "dpop+jwt",
        },
        payload: {
          ...payload,
        },
      },
    );
  });

  it("should keep the alg and extra values in the header but overwrite the typ field", async () => {
    const header = {
      alg: "ES256",
      extra: "This is an extra record",
      extraObject: {
        title: "This is an extra object's title",
      },
      typ: "I will be overwritten",
    };
    const payload = {
      extra: "This is an extra record",
      extraObject: {
        label: "Label of an extra object",
      },
      htm: "POST" as const,
      htu: "test://uri.htu",
    };

    await createTokenDPoP({
      callbacks,
      header,
      payload,
      signer: {} as JwtSigner,
    });

    expect(callbacks.signJwt).toHaveBeenCalledWith(
      {},
      {
        header: {
          ...header,
          typ: "dpop+jwt",
        },
        payload: {
          ...payload,
          jti: MOCKED_RANDOM,
        },
      },
    );
  });

  it("should keep the extra values in the payload and not overwrite the jti field", async () => {
    const header = { alg: "ES256" };
    const payload = {
      extra: "This is an extra record",
      extraObject: {
        title: "This is an extra object's title",
      },
      htm: "POST" as const,
      htu: "test://uri.htu",
      jti: "I will not be overwritten",
    };

    await createTokenDPoP({
      callbacks,
      header,
      payload,
      signer: {} as JwtSigner,
    });

    expect(callbacks.signJwt).toHaveBeenCalledWith(
      {},
      {
        header: {
          ...header,
          typ: "dpop+jwt",
        },
        payload: {
          ...payload,
        },
      },
    );
  });
});
