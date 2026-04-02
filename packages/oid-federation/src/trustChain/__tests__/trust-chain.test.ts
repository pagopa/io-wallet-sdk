import { describe, expect, it, vi } from "vitest";

import {
  FetchAndValidateTrustChainOptions,
  ValidateTrustChainOptions,
  VerifyJwtWithJwkCallback,
  fetchAndValidateTrustChain,
  validateTrustChain,
} from "../trust-chain";

// ---------- helpers ----------

function encodeBase64Url(data: string): string {
  return Buffer.from(data).toString("base64url");
}

function makeJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): string {
  return `${encodeBase64Url(JSON.stringify(header))}.${encodeBase64Url(JSON.stringify(payload))}.fakesignature`;
}

const LEAF_KID = "leaf-key";
const ANCHOR_KID = "anchor-key";
const INTERMEDIATE_KID = "intermediate-key";
const BAD_INTERMEDIATE_KID = "bad-intermediate-key";
const BAD_ANCHOR_KID = "bad-anchor-key";
const LEAF_URL = "https://leaf.example.com";
const ANCHOR_URL = "https://anchor.example.com";
const INTERMEDIATE_URL = "https://intermediate.example.com";
const BAD_INTERMEDIATE_URL = "https://bad.intermediate.example.com";
const BAD_ANCHOR_URL = "https://bad.anchor.example.com";
const FETCH_ENDPOINT = `${ANCHOR_URL}/fetch`;
const INTERMEDIATE_FETCH_ENDPOINT = `${INTERMEDIATE_URL}/fetch`;

const INTERMEDIATE_KEY = {
  crv: "P-256",
  kid: INTERMEDIATE_KID,
  kty: "EC",
  x: "ix",
  y: "iy",
};

const BAD_INTERMEDIATE_KEY = {
  crv: "P-256",
  kid: BAD_INTERMEDIATE_KID,
  kty: "EC",
  x: "ix",
  y: "iy",
};

const LEAF_KEY = { crv: "P-256", kid: LEAF_KID, kty: "EC", x: "x", y: "y" };
const ANCHOR_KEY = {
  crv: "P-256",
  kid: ANCHOR_KID,
  kty: "EC",
  x: "ax",
  y: "ay",
};

const BAD_ANCHOR_KEY = {
  crv: "P-256",
  kid: BAD_ANCHOR_KID,
  kty: "EC",
  x: "sax",
  y: "say",
};

const now = Math.floor(Date.now() / 1000);
const future = now + 3600;
const past = now - 3600;

function makeLeafEC(exp = future) {
  return makeJwt(
    { alg: "ES256", kid: LEAF_KID, typ: "entity-statement+jwt" },
    {
      authority_hints: [ANCHOR_URL],
      exp,
      iat: now,
      iss: LEAF_URL,
      jwks: { keys: [LEAF_KEY] },
      sub: LEAF_URL,
    },
  );
}

function makeAnchorEC(exp = future) {
  return makeJwt(
    { alg: "ES256", kid: ANCHOR_KID, typ: "entity-statement+jwt" },
    {
      exp,
      iat: now,
      iss: ANCHOR_URL,
      jwks: { keys: [ANCHOR_KEY] },
      metadata: {
        federation_entity: {
          federation_fetch_endpoint: FETCH_ENDPOINT,
        },
      },
      sub: ANCHOR_URL,
    },
  );
}

function makeSubStmt(exp = future) {
  return makeJwt(
    { alg: "ES256", kid: ANCHOR_KID, typ: "entity-statement+jwt" },
    {
      exp,
      iat: now,
      iss: ANCHOR_URL,
      jwks: { keys: [LEAF_KEY] },
      sub: LEAF_URL,
    },
  );
}

const noopVerifyJwt: VerifyJwtWithJwkCallback = vi.fn(async () => ({
  signerJwk: { kty: "EC" },
  verified: true as const,
}));

const noopFetch = vi.fn(async () => new Response("not found", { status: 404 }));

// ---------- validateTrustChain — valid chains and signature verification ----------

describe("validateTrustChain - valid chains and signature verification", () => {
  it("accepts a valid 3-element chain", async () => {
    const chain = [makeLeafEC(), makeSubStmt(), makeAnchorEC()];
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await expect(validateTrustChain(chain, options)).resolves.toBeUndefined();
  });

  it("accepts a single-element chain (leaf is the anchor)", async () => {
    const singleEC = makeJwt(
      { alg: "ES256", kid: ANCHOR_KID, typ: "entity-statement+jwt" },
      {
        exp: future,
        iat: now,
        iss: ANCHOR_URL,
        jwks: { keys: [ANCHOR_KEY] },
        sub: ANCHOR_URL,
      },
    );
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await expect(
      validateTrustChain([singleEC], options),
    ).resolves.toBeUndefined();
  });

  it("skips authority_hints check when subject has no authority_hints", async () => {
    const leafNoHints = makeJwt(
      { alg: "ES256", kid: LEAF_KID, typ: "entity-statement+jwt" },
      {
        exp: future,
        iat: now,
        iss: LEAF_URL,
        jwks: { keys: [LEAF_KEY] },
        sub: LEAF_URL,
      },
    );
    const chain = [leafNoHints, makeSubStmt(), makeAnchorEC()];
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await expect(validateTrustChain(chain, options)).resolves.toBeUndefined();
  });

  it("verifyJwt is called for leaf and anchor self-signatures", async () => {
    const verifyJwt: VerifyJwtWithJwkCallback = vi.fn(async () => ({
      signerJwk: { kty: "EC" },
      verified: true as const,
    }));
    const leafJwt = makeLeafEC();
    const anchorJwt = makeAnchorEC();
    const chain = [leafJwt, makeSubStmt(), anchorJwt];
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await validateTrustChain(chain, options);
    const calls = vi.mocked(verifyJwt).mock.calls;
    const compacts = calls.map((c) => c[1].compact);
    expect(compacts).toContain(leafJwt);
    expect(compacts).toContain(anchorJwt);
  });

  it("verifies last sub-stmt using anchor keys", async () => {
    const verifyJwt: VerifyJwtWithJwkCallback = vi.fn(async () => ({
      signerJwk: { kty: "EC" },
      verified: true as const,
    }));
    const subJwt = makeSubStmt();
    const anchorJwt = makeAnchorEC();
    const chain = [makeLeafEC(), subJwt, anchorJwt];
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await validateTrustChain(chain, options);
    const calls = vi.mocked(verifyJwt).mock.calls;
    const subCall = calls.find((c) => c[1].compact === subJwt);
    expect(subCall).toBeDefined();
    if (!subCall?.[0]) throw new Error("Test expected sub call to be defined");
    expect(subCall[0].publicJwk.kid).toBe(ANCHOR_KID);
  });
});

// ---------- validateTrustChain — error cases ----------

describe("validateTrustChain - error cases", () => {
  it("throws on empty chain", async () => {
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt: noopVerifyJwt },
    };
    await expect(validateTrustChain([], options)).rejects.toThrow(
      "empty trust chain",
    );
  });

  it("throws when an element has expired", async () => {
    const chain = [makeLeafEC(past), makeSubStmt(), makeAnchorEC()];
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt: noopVerifyJwt },
    };
    await expect(validateTrustChain(chain, options)).rejects.toThrow(
      "has expired",
    );
  });

  it("throws when an element has iat in the future (§3.2 point 7)", async () => {
    const leafFutureIat = makeJwt(
      { alg: "ES256", kid: LEAF_KID, typ: "entity-statement+jwt" },
      {
        authority_hints: [ANCHOR_URL],
        exp: future,
        iat: now + 120,
        iss: LEAF_URL,
        jwks: { keys: [LEAF_KEY] },
        sub: LEAF_URL,
      },
    );
    const chain = [leafFutureIat, makeSubStmt(), makeAnchorEC()];
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt: noopVerifyJwt },
    };
    await expect(validateTrustChain(chain, options)).rejects.toThrow(
      "has iat in the future",
    );
  });

  it("throws when leaf subject does not match first sub-stmt subject", async () => {
    const mismatchedSubStmt = makeJwt(
      { alg: "ES256", kid: ANCHOR_KID, typ: "entity-statement+jwt" },
      {
        exp: future,
        iat: now,
        iss: ANCHOR_URL,
        jwks: { keys: [LEAF_KEY] },
        sub: "https://other.example.com",
      },
    );
    const chain = [makeLeafEC(), mismatchedSubStmt, makeAnchorEC()];
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt: noopVerifyJwt },
    };
    await expect(validateTrustChain(chain, options)).rejects.toThrow(
      "leaf EC subject does not match first subordinate statement subject",
    );
  });

  it("throws when a structural link is broken", async () => {
    const brokenSubStmt = makeJwt(
      { alg: "ES256", kid: ANCHOR_KID, typ: "entity-statement+jwt" },
      {
        exp: future,
        iat: now,
        iss: "https://wrong-issuer.example.com",
        jwks: { keys: [LEAF_KEY] },
        sub: LEAF_URL,
      },
    );
    const chain = [makeLeafEC(), brokenSubStmt, makeAnchorEC()];
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt: noopVerifyJwt },
    };
    await expect(validateTrustChain(chain, options)).rejects.toThrow(
      "trust chain link broken",
    );
  });

  it("throws when root is not a trusted anchor", async () => {
    const chain = [makeLeafEC(), makeSubStmt(), makeAnchorEC()];
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: ["https://other-anchor.example.com"],
    };
    await expect(validateTrustChain(chain, options)).rejects.toThrow(
      "is not a trusted anchor",
    );
  });
});

describe("validateTrustChain - authority hints, signatures, and EC checks", () => {
  it("throws when sub-stmt issuer is not in subject authority_hints (§3.2 point 6)", async () => {
    const leafWithStrictHints = makeJwt(
      { alg: "ES256", kid: LEAF_KID, typ: "entity-statement+jwt" },
      {
        authority_hints: ["https://different-anchor.example.com"],
        exp: future,
        iat: now,
        iss: LEAF_URL,
        jwks: { keys: [LEAF_KEY] },
        sub: LEAF_URL,
      },
    );
    // sub-stmt is issued by ANCHOR_URL, but leaf only lists a different anchor
    const chain = [leafWithStrictHints, makeSubStmt(), makeAnchorEC()];
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await expect(validateTrustChain(chain, options)).rejects.toThrow(
      "is not listed in authority_hints",
    );
  });

  it("throws when signature verification fails", async () => {
    const verifyJwt: VerifyJwtWithJwkCallback = vi.fn(async () => ({
      verified: false as const,
    }));
    const chain = [makeLeafEC(), makeSubStmt(), makeAnchorEC()];
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await expect(validateTrustChain(chain, options)).rejects.toThrow();
  });

  it("throws when leaf EC has mismatched iss and sub", async () => {
    const mismatchedLeaf = makeJwt(
      { alg: "ES256", kid: LEAF_KID, typ: "entity-statement+jwt" },
      {
        authority_hints: [ANCHOR_URL],
        exp: future,
        iat: now,
        iss: LEAF_URL,
        jwks: { keys: [LEAF_KEY] },
        sub: "https://other.example.com",
      },
    );
    const chain = [mismatchedLeaf, makeSubStmt(), makeAnchorEC()];
    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: noopFetch, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await expect(validateTrustChain(chain, options)).rejects.toThrow(
      "does not match sub",
    );
  });

  it("throws when a fetched intermediate EC is expired (with fetch callback)", async () => {
    const expiredIntermediateEC = makeJwt(
      { alg: "ES256", kid: INTERMEDIATE_KID, typ: "entity-statement+jwt" },
      {
        exp: past,
        iat: now,
        iss: INTERMEDIATE_URL,
        jwks: { keys: [INTERMEDIATE_KEY] },
        sub: INTERMEDIATE_URL,
      },
    );
    const subStmtLeaf = makeJwt(
      { alg: "ES256", kid: INTERMEDIATE_KID, typ: "entity-statement+jwt" },
      {
        exp: future,
        iat: now,
        iss: INTERMEDIATE_URL,
        jwks: { keys: [LEAF_KEY] },
        sub: LEAF_URL,
      },
    );
    const subStmtIntermediate = makeJwt(
      { alg: "ES256", kid: ANCHOR_KID, typ: "entity-statement+jwt" },
      {
        exp: future,
        iat: now,
        iss: ANCHOR_URL,
        jwks: { keys: [INTERMEDIATE_KEY] },
        sub: INTERMEDIATE_URL,
      },
    );
    const leafWithIntermediateHint = makeJwt(
      { alg: "ES256", kid: LEAF_KID, typ: "entity-statement+jwt" },
      {
        authority_hints: [INTERMEDIATE_URL],
        exp: future,
        iat: now,
        iss: LEAF_URL,
        jwks: { keys: [LEAF_KEY] },
        sub: LEAF_URL,
      },
    );
    const chain = [
      leafWithIntermediateHint,
      subStmtLeaf,
      subStmtIntermediate,
      makeAnchorEC(),
    ];

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (
        input.toString() === `${INTERMEDIATE_URL}/.well-known/openid-federation`
      )
        return new Response(expiredIntermediateEC, { status: 200 });
      return new Response("not found", { status: 404 });
    });

    const options: ValidateTrustChainOptions = {
      callbacks: { fetch: fetchMock, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };

    await expect(validateTrustChain(chain, options)).rejects.toThrow(
      "has expired",
    );
  });
});

// ---------- fetchAndValidateTrustChain — valid chains ----------

describe("fetchAndValidateTrustChain - valid chains", () => {
  it("fetches and validates a leaf → anchor chain", async () => {
    const leafJwt = makeLeafEC();
    const anchorJwt = makeAnchorEC();
    const subStmtJwt = makeSubStmt();

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url === `${LEAF_URL}/.well-known/openid-federation`)
        return new Response(leafJwt, { status: 200 });
      if (url === `${ANCHOR_URL}/.well-known/openid-federation`)
        return new Response(anchorJwt, { status: 200 });
      if (url.startsWith(FETCH_ENDPOINT))
        return new Response(subStmtJwt, { status: 200 });
      return new Response("not found", { status: 404 });
    });

    const options: FetchAndValidateTrustChainOptions = {
      callbacks: { fetch: fetchMock, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };

    const result = await fetchAndValidateTrustChain(LEAF_URL, options);
    expect(result).toEqual([leafJwt, subStmtJwt, anchorJwt]);
  });

  it("fetches and validates a single element (trust anchor only) chain", async () => {
    const anchorJwt = makeAnchorEC();

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url === `${ANCHOR_URL}/.well-known/openid-federation`)
        return new Response(anchorJwt, { status: 200 });
      return new Response("not found", { status: 404 });
    });

    const options: FetchAndValidateTrustChainOptions = {
      callbacks: { fetch: fetchMock, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };

    const result = await fetchAndValidateTrustChain(ANCHOR_URL, options);
    expect(result).toEqual([anchorJwt]);
  });

  it("accepts only the second trust anchor in the chain retrieval process", async () => {
    const leafJwt = makeJwt(
      { alg: "ES256", kid: LEAF_KID, typ: "entity-statement+jwt" },
      {
        authority_hints: [BAD_INTERMEDIATE_URL, INTERMEDIATE_URL],
        exp: future,
        iat: now,
        iss: LEAF_URL,
        jwks: { keys: [LEAF_KEY] },
        sub: LEAF_URL,
      },
    );
    const intermediateJwt = makeJwt(
      { alg: "ES256", kid: INTERMEDIATE_KID, typ: "entity-statement+jwt" },
      {
        authority_hints: [ANCHOR_URL],
        exp: future,
        iat: now,
        iss: INTERMEDIATE_URL,
        jwks: { keys: [INTERMEDIATE_KEY] },
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: INTERMEDIATE_FETCH_ENDPOINT,
          },
        },
        sub: INTERMEDIATE_URL,
      },
    );
    const badIntermediateJwt = makeJwt(
      { alg: "ES256", kid: INTERMEDIATE_KID, typ: "entity-statement+jwt" },
      {
        authority_hints: [BAD_ANCHOR_URL],
        exp: future,
        iat: now,
        iss: BAD_INTERMEDIATE_URL,
        jwks: { keys: [BAD_INTERMEDIATE_KEY] },
        sub: BAD_INTERMEDIATE_URL,
      },
    );
    const anchorJwt = makeAnchorEC();
    const anchorIntermediateSubstJwt = makeJwt(
      { alg: "ES256", kid: ANCHOR_KID, typ: "entity-statement+jwt" },
      {
        exp: future,
        iat: now,
        iss: ANCHOR_URL,
        jwks: { keys: [INTERMEDIATE_KEY] },
        sub: INTERMEDIATE_URL,
      },
    );
    const intermediateLeafSubstJwt = makeJwt(
      { alg: "ES256", kid: INTERMEDIATE_KID, typ: "entity-statement+jwt" },
      {
        exp: future,
        iat: now,
        iss: INTERMEDIATE_URL,
        jwks: { keys: [LEAF_KEY] },
        sub: LEAF_URL,
      },
    );
    const anchorUntrusted = makeJwt(
      { alg: "ES256", kid: BAD_ANCHOR_KID, typ: "entity-statement+jwt" },
      {
        exp: future,
        iat: now,
        iss: BAD_ANCHOR_URL,
        jwks: { keys: [BAD_ANCHOR_KEY] },
        sub: BAD_ANCHOR_URL,
      },
    );

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url === `${LEAF_URL}/.well-known/openid-federation`)
        return new Response(leafJwt, { status: 200 });
      if (url === `${INTERMEDIATE_URL}/.well-known/openid-federation`)
        return new Response(intermediateJwt, { status: 200 });
      if (url === `${ANCHOR_URL}/.well-known/openid-federation`)
        return new Response(anchorJwt, { status: 200 });
      if (url === `${BAD_INTERMEDIATE_URL}/.well-known/openid-federation`)
        return new Response(badIntermediateJwt, { status: 200 });
      if (url === `${BAD_ANCHOR_URL}/.well-known/openid-federation`)
        return new Response(anchorUntrusted, { status: 200 });
      if (url.startsWith(FETCH_ENDPOINT))
        return new Response(anchorIntermediateSubstJwt, { status: 200 });
      if (url.startsWith(INTERMEDIATE_FETCH_ENDPOINT))
        return new Response(intermediateLeafSubstJwt, { status: 200 });
      return new Response("not found", { status: 404 });
    });

    const options: FetchAndValidateTrustChainOptions = {
      callbacks: { fetch: fetchMock, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };

    const result = await fetchAndValidateTrustChain(LEAF_URL, options);
    expect(result).toEqual([
      leafJwt,
      intermediateLeafSubstJwt,
      anchorIntermediateSubstJwt,
      anchorJwt,
    ]);

    const calledUrls = vi.mocked(fetchMock).mock.calls.map((c) => c[0]);
    expect(calledUrls).toMatchObject([
      `${LEAF_URL}/.well-known/openid-federation`,
      `${BAD_INTERMEDIATE_URL}/.well-known/openid-federation`,
      `${BAD_ANCHOR_URL}/.well-known/openid-federation`,
      `${INTERMEDIATE_URL}/.well-known/openid-federation`,
      `${ANCHOR_URL}/.well-known/openid-federation`,
      expect.stringMatching(INTERMEDIATE_FETCH_ENDPOINT),
      expect.stringMatching(FETCH_ENDPOINT),
    ]);
  });
});

// ---------- fetchAndValidateTrustChain — error cases ----------

describe("fetchAndValidateTrustChain - error cases", () => {
  it("throws when no authority_hints point to a known anchor", async () => {
    const leafJwt = makeJwt(
      { alg: "ES256", kid: LEAF_KID, typ: "entity-statement+jwt" },
      {
        authority_hints: ["https://unknown-anchor.example.com"],
        exp: future,
        iat: now,
        iss: LEAF_URL,
        jwks: { keys: [LEAF_KEY] },
        sub: LEAF_URL,
      },
    );
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url === `${LEAF_URL}/.well-known/openid-federation`)
        return new Response(leafJwt, { status: 200 });
      return new Response("not found", { status: 404 });
    });
    const options: FetchAndValidateTrustChainOptions = {
      callbacks: { fetch: fetchMock, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await expect(
      fetchAndValidateTrustChain(LEAF_URL, options),
    ).rejects.toThrow();
  });

  it("throws when fetch returns a non-200 status", async () => {
    const fetchMock = vi.fn(async () => new Response("error", { status: 500 }));
    const options: FetchAndValidateTrustChainOptions = {
      callbacks: { fetch: fetchMock, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await expect(
      fetchAndValidateTrustChain(LEAF_URL, options),
    ).rejects.toThrow();
  });

  it("throws when an EC self-signature verification fails (buildTrustChain)", async () => {
    const leafJwt = makeLeafEC();
    const anchorJwt = makeAnchorEC();
    const subStmtJwt = makeSubStmt();
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url === `${LEAF_URL}/.well-known/openid-federation`)
        return new Response(leafJwt, { status: 200 });
      if (url === `${ANCHOR_URL}/.well-known/openid-federation`)
        return new Response(anchorJwt, { status: 200 });
      if (url.startsWith(FETCH_ENDPOINT))
        return new Response(subStmtJwt, { status: 200 });
      return new Response("not found", { status: 404 });
    });
    const failingVerifyJwt: VerifyJwtWithJwkCallback = vi.fn(async () => ({
      verified: false as const,
    }));
    const options: FetchAndValidateTrustChainOptions = {
      callbacks: { fetch: fetchMock, verifyJwt: failingVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await expect(fetchAndValidateTrustChain(LEAF_URL, options)).rejects.toThrow(
      "Jwt verification failed",
    );
  });

  it("throws when superior entity has no federation_fetch_endpoint (buildTrustChain)", async () => {
    const leafJwt = makeLeafEC();
    const anchorWithoutFetchEndpoint = makeJwt(
      { alg: "ES256", kid: ANCHOR_KID, typ: "entity-statement+jwt" },
      {
        exp: future,
        iat: now,
        iss: ANCHOR_URL,
        jwks: { keys: [ANCHOR_KEY] },
        sub: ANCHOR_URL,
      },
    );
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url === `${LEAF_URL}/.well-known/openid-federation`)
        return new Response(leafJwt, { status: 200 });
      if (url === `${ANCHOR_URL}/.well-known/openid-federation`)
        return new Response(anchorWithoutFetchEndpoint, { status: 200 });
      return new Response("not found", { status: 404 });
    });
    const options: FetchAndValidateTrustChainOptions = {
      callbacks: { fetch: fetchMock, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await expect(fetchAndValidateTrustChain(LEAF_URL, options)).rejects.toThrow(
      "federation_fetch_endpoint",
    );
  });
});

describe("fetchAndValidateTrustChain - expiry and EC validation errors", () => {
  it("throws when a fetched intermediate EC is expired (buildTrustChain)", async () => {
    const leafJwt = makeJwt(
      { alg: "ES256", kid: LEAF_KID, typ: "entity-statement+jwt" },
      {
        authority_hints: [INTERMEDIATE_URL],
        exp: future,
        iat: now,
        iss: LEAF_URL,
        jwks: { keys: [LEAF_KEY] },
        sub: LEAF_URL,
      },
    );
    const expiredIntermediateJwt = makeJwt(
      { alg: "ES256", kid: INTERMEDIATE_KID, typ: "entity-statement+jwt" },
      {
        authority_hints: [ANCHOR_URL],
        exp: past,
        iat: now,
        iss: INTERMEDIATE_URL,
        jwks: { keys: [INTERMEDIATE_KEY] },
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: INTERMEDIATE_FETCH_ENDPOINT,
          },
        },
        sub: INTERMEDIATE_URL,
      },
    );
    const anchorJwt = makeAnchorEC();

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url === `${LEAF_URL}/.well-known/openid-federation`)
        return new Response(leafJwt, { status: 200 });
      if (url === `${INTERMEDIATE_URL}/.well-known/openid-federation`)
        return new Response(expiredIntermediateJwt, { status: 200 });
      if (url === `${ANCHOR_URL}/.well-known/openid-federation`)
        return new Response(anchorJwt, { status: 200 });
      return new Response("not found", { status: 404 });
    });

    const options: FetchAndValidateTrustChainOptions = {
      callbacks: { fetch: fetchMock, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };

    await expect(fetchAndValidateTrustChain(LEAF_URL, options)).rejects.toThrow(
      "has expired",
    );
  });

  it("throws when a fetched EC has mismatched iss and sub (buildTrustChain)", async () => {
    const mismatchedAnchorJwt = makeJwt(
      { alg: "ES256", kid: ANCHOR_KID, typ: "entity-statement+jwt" },
      {
        exp: future,
        iat: now,
        iss: ANCHOR_URL,
        jwks: { keys: [ANCHOR_KEY] },
        metadata: {
          federation_entity: { federation_fetch_endpoint: FETCH_ENDPOINT },
        },
        sub: "https://other.example.com",
      },
    );

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url === `${LEAF_URL}/.well-known/openid-federation`)
        return new Response(makeLeafEC(), { status: 200 });
      if (url === `${ANCHOR_URL}/.well-known/openid-federation`)
        return new Response(mismatchedAnchorJwt, { status: 200 });
      return new Response("not found", { status: 404 });
    });

    const options: FetchAndValidateTrustChainOptions = {
      callbacks: { fetch: fetchMock, verifyJwt: noopVerifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };

    await expect(fetchAndValidateTrustChain(LEAF_URL, options)).rejects.toThrow(
      "does not match sub",
    );
  });

  it("throws when subordinate statement signature verification fails (buildTrustChain)", async () => {
    const leafJwt = makeLeafEC();
    const anchorJwt = makeAnchorEC();
    const subStmtJwt = makeSubStmt();
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url === `${LEAF_URL}/.well-known/openid-federation`)
        return new Response(leafJwt, { status: 200 });
      if (url === `${ANCHOR_URL}/.well-known/openid-federation`)
        return new Response(anchorJwt, { status: 200 });
      if (url.startsWith(FETCH_ENDPOINT))
        return new Response(subStmtJwt, { status: 200 });
      return new Response("not found", { status: 404 });
    });
    const verifyJwt: VerifyJwtWithJwkCallback = vi.fn(async (_signer, jwt) => {
      if (jwt.compact === subStmtJwt) return { verified: false as const };
      return { signerJwk: { kty: "EC" }, verified: true as const };
    });
    const options: FetchAndValidateTrustChainOptions = {
      callbacks: { fetch: fetchMock, verifyJwt },
      trustAnchorUrls: [ANCHOR_URL],
    };
    await expect(fetchAndValidateTrustChain(LEAF_URL, options)).rejects.toThrow(
      "Error verifying signature",
    );
  });
});

// ---------- 1-intermediate chain, middle EC key mismatch (shared fixtures) ----------

describe("1-intermediate chain with middle intermediate EC key mismatch", () => {
  const INTER1_URL = "https://intermediate1.example.com";
  const INTER1_KID = "intermediate1-key";
  const BAD_INTER1_KID = "bad-intermediate2-key";
  const INTER1_FETCH_ENDPOINT = `${INTER1_URL}/fetch`;

  const INTER1_KEY = {
    crv: "P-256",
    kid: INTER1_KID,
    kty: "EC",
    x: "i1x",
    y: "i1y",
  };
  const BAD_INTER1_KEY = {
    crv: "P-256",
    kid: BAD_INTER1_KID,
    kty: "EC",
    x: "bi2x",
    y: "bi2y",
  };

  // Chain: [leafEC, subStmt(leaf←inter1), subStmt(inter1←anchor), anchorEC]
  const leafJwt = makeJwt(
    { alg: "ES256", kid: LEAF_KID, typ: "entity-statement+jwt" },
    {
      authority_hints: [INTER1_URL],
      exp: future,
      iat: now,
      iss: LEAF_URL,
      jwks: { keys: [LEAF_KEY] },
      sub: LEAF_URL,
    },
  );
  const subStmtLeafByInter1 = makeJwt(
    { alg: "ES256", kid: INTER1_KID, typ: "entity-statement+jwt" },
    {
      exp: future,
      iat: now,
      iss: INTER1_URL,
      jwks: { keys: [LEAF_KEY] },
      sub: LEAF_URL,
    },
  );
  const subStmtInter1ByAnchor = makeJwt(
    { alg: "ES256", kid: ANCHOR_KID, typ: "entity-statement+jwt" },
    {
      exp: future,
      iat: now,
      iss: ANCHOR_URL,
      jwks: { keys: [INTER1_KEY] },
      sub: INTER1_URL,
    },
  );
  const anchorJwt = makeAnchorEC();
  const chain6 = [
    leafJwt,
    subStmtLeafByInter1,
    subStmtInter1ByAnchor,
    anchorJwt,
  ];

  // inter1EC is correct — its jwks match what the chain declares for inter1
  const badInter1EC = makeJwt(
    { alg: "ES256", kid: BAD_INTER1_KID, typ: "entity-statement+jwt" },
    {
      authority_hints: [ANCHOR_URL],
      exp: future,
      iat: now,
      iss: INTER1_URL,
      jwks: { keys: [BAD_INTER1_KEY] },
      metadata: {
        federation_entity: { federation_fetch_endpoint: INTER1_FETCH_ENDPOINT },
      },
      sub: INTER1_URL,
    },
  );

  describe("validateTrustChain", () => {
    it("throws when the middle intermediate's EC declares different keys than its subordinate statement", async () => {
      const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
        const url = input.toString();
        if (url === `${INTER1_URL}/.well-known/openid-federation`)
          return new Response(badInter1EC, { status: 200 });
        return new Response("not found", { status: 404 });
      });

      const options: ValidateTrustChainOptions = {
        callbacks: { fetch: fetchMock, verifyJwt: noopVerifyJwt },
        trustAnchorUrls: [ANCHOR_URL],
      };

      await expect(validateTrustChain(chain6, options)).rejects.toThrow(
        "not found in EC's declared keys",
      );
    });
  });

  describe("fetchAndValidateTrustChain", () => {
    it("throws when the middle intermediate's EC declares different keys than its subordinate statement", async () => {
      const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
        const url = input.toString();
        if (url === `${LEAF_URL}/.well-known/openid-federation`)
          return new Response(leafJwt, { status: 200 });
        if (url === `${INTER1_URL}/.well-known/openid-federation`)
          return new Response(badInter1EC, { status: 200 });
        if (url === `${ANCHOR_URL}/.well-known/openid-federation`)
          return new Response(anchorJwt, { status: 200 });
        if (url.startsWith(INTER1_FETCH_ENDPOINT))
          return new Response(subStmtLeafByInter1, { status: 200 });
        if (url.startsWith(FETCH_ENDPOINT))
          return new Response(subStmtInter1ByAnchor, { status: 200 });
        return new Response("not found", { status: 404 });
      });

      const options: FetchAndValidateTrustChainOptions = {
        callbacks: { fetch: fetchMock, verifyJwt: noopVerifyJwt },
        trustAnchorUrls: [ANCHOR_URL],
      };

      await expect(
        fetchAndValidateTrustChain(LEAF_URL, options),
      ).rejects.toThrow("not found in EC's declared keys");
    });
  });
});
