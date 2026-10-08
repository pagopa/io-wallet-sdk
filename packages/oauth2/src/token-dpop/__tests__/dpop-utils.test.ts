import { describe, expect, it, vi } from "vitest";

import { fetchWithDpopNonceRetry, getRequiredDpopNonce } from "../dpop-utils";

const response = (
  status: number,
  headers: Record<string, string>,
  body?: unknown,
) => new Response(body ? JSON.stringify(body) : null, { headers, status });

describe("getRequiredDpopNonce", () => {
  it("should return the nonce of an authorization server use_dpop_nonce error", async () => {
    const nonce = await getRequiredDpopNonce(
      response(400, { "DPoP-Nonce": "n1" }, { error: "use_dpop_nonce" }),
    );
    expect(nonce).toBe("n1");
  });

  it("should return the nonce of a resource server use_dpop_nonce error", async () => {
    const nonce = await getRequiredDpopNonce(
      response(401, {
        "DPoP-Nonce": "n2",
        "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
      }),
    );
    expect(nonce).toBe("n2");
  });

  it("should ignore other errors and successful responses", async () => {
    await expect(
      getRequiredDpopNonce(
        response(400, { "DPoP-Nonce": "n" }, { error: "invalid_grant" }),
      ),
    ).resolves.toBeUndefined();
    await expect(
      getRequiredDpopNonce(response(200, { "DPoP-Nonce": "n" }, {})),
    ).resolves.toBeUndefined();
    await expect(
      getRequiredDpopNonce(response(400, {}, { error: "use_dpop_nonce" })),
    ).resolves.toBeUndefined();
  });
});

describe("fetchWithDpopNonceRetry", () => {
  it("should send a string proof once without retrying", async () => {
    const send = vi
      .fn()
      .mockResolvedValue(
        response(400, { "DPoP-Nonce": "n1" }, { error: "use_dpop_nonce" }),
      );

    await fetchWithDpopNonceRetry({ dPoP: "proof", sendRequest: send });

    expect(send).toHaveBeenCalledTimes(1);
    expect(send).toHaveBeenCalledWith("proof");
  });

  it("should not retry a successful request", async () => {
    const send = vi.fn().mockResolvedValue(response(200, {}, {}));
    const dPoP = vi.fn().mockResolvedValue("proof");

    await fetchWithDpopNonceRetry({ dPoP, sendRequest: send });

    expect(send).toHaveBeenCalledTimes(1);
    expect(dPoP).toHaveBeenCalledWith();
  });

  it("should retry once with the required nonce", async () => {
    const send = vi
      .fn()
      .mockResolvedValueOnce(
        response(400, { "DPoP-Nonce": "n1" }, { error: "use_dpop_nonce" }),
      )
      .mockResolvedValueOnce(
        response(400, { "DPoP-Nonce": "n2" }, { error: "use_dpop_nonce" }),
      );
    const dPoP = vi.fn(async (nonce?: string) => `proof-${nonce}`);

    const result = await fetchWithDpopNonceRetry({ dPoP, sendRequest: send });

    expect(send).toHaveBeenCalledTimes(2);
    expect(send).toHaveBeenLastCalledWith("proof-n1");
    expect(result.status).toBe(400);
  });
});
