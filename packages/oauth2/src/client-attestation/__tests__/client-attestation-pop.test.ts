import { encodeToBase64Url } from "@openid4vc/utils";
import { describe, expect, it, vi } from "vitest";

import { Oauth2Error } from "../../errors";
import {
  createClientAttestationPopJwt,
  verifyClientAttestationPopJwt,
} from "../client-attestation-pop";

describe("client-attestation-pop", () => {
  const mockJwk = { crv: "P-256", kty: "EC", x: "...", y: "..." };
  const mockHeader = { alg: "ES256", typ: "oauth-client-attestation-pop+jwt" };
  const mockPayload = {
    cnf: { jwk: mockJwk },
    sub: "client-id",
  };
  const mockClientAttestation = [
    encodeToBase64Url(JSON.stringify(mockHeader)),
    encodeToBase64Url(JSON.stringify(mockPayload)),
    "signature",
  ].join(".");

  const mockSignJwt = vi.fn(async (_signer, { header, payload }) => ({
    jwt: [
      encodeToBase64Url(JSON.stringify(header)),
      encodeToBase64Url(JSON.stringify(payload)),
      "signature",
    ].join("."),
    signerJwk: mockJwk,
  }));
  const mockGenerateRandom = vi.fn(async (len) => new Uint8Array(len));
  const mockVerifyJwt = vi.fn(async () => ({
    signerJwk: mockJwk,
    verified: true,
  }));

  it("should create a client attestation pop jwt", async () => {
    const jwt = await createClientAttestationPopJwt({
      authorizationServer: "https://auth.example",
      callbacks: { generateRandom: mockGenerateRandom, signJwt: mockSignJwt },
      clientAttestation: mockClientAttestation,
      issuedAt: new Date(1700000000000),
    });
    expect(typeof jwt).toBe("string");
    expect(jwt.split(".").length).toBe(3);
  });

  it("should throw if client attestation does not contain cnf.jwk", async () => {
    const badAttestation = [
      encodeToBase64Url(JSON.stringify(mockHeader)),
      encodeToBase64Url(JSON.stringify({ sub: "client-id" })),
      "signature",
    ].join(".");
    await expect(
      createClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: { generateRandom: mockGenerateRandom, signJwt: mockSignJwt },
        clientAttestation: badAttestation,
      }),
    ).rejects.toThrow(/cnf\.jwk/);
  });

  it("should throw if client attestation does not contain sub", async () => {
    const badAttestation = [
      encodeToBase64Url(JSON.stringify(mockHeader)),
      encodeToBase64Url(JSON.stringify({ cnf: { jwk: mockJwk } })),
      "signature",
    ].join(".");
    await expect(
      createClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: { generateRandom: mockGenerateRandom, signJwt: mockSignJwt },
        clientAttestation: badAttestation,
      }),
    ).rejects.toThrow(/sub/);
  });

  it("should throw if clientAttestation is malformed", async () => {
    const badAttestation = [
      encodeToBase64Url(JSON.stringify(mockHeader)),
      "asdf",
      "signature",
    ].join(".");
    await expect(
      createClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: { generateRandom: mockGenerateRandom, signJwt: mockSignJwt },
        clientAttestation: badAttestation,
      }),
    ).rejects.toThrow(Oauth2Error);
  });

  it("should verify a valid client attestation pop jwt", async () => {
    const jwt = [
      encodeToBase64Url(JSON.stringify(mockHeader)),
      encodeToBase64Url(
        JSON.stringify({ aud: "https://auth.example", sub: "client-id" }),
      ),
      "signature",
    ].join(".");
    const result = await verifyClientAttestationPopJwt({
      authorizationServer: "https://auth.example",
      callbacks: { verifyJwt: mockVerifyJwt },
      clientAttestationPopJwt: jwt,
      clientAttestationPublicJwk: mockJwk,
    });
    expect(result.header.alg).toBe("ES256");
    expect(result.payload.aud).toBe("https://auth.example");
    expect(result.signer).toBeDefined();
  });

  it("should throw if aud does not match", async () => {
    const jwt = [
      encodeToBase64Url(JSON.stringify(mockHeader)),
      encodeToBase64Url(JSON.stringify({ aud: "wrong", sub: "client-id" })),
      "signature",
    ].join(".");
    await expect(
      verifyClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: { verifyJwt: mockVerifyJwt },
        clientAttestationPopJwt: jwt,
        clientAttestationPublicJwk: mockJwk,
      }),
    ).rejects.toThrow(/aud/);
  });

  it("should throw if jwt is malformed", async () => {
    const jwt = [
      encodeToBase64Url(JSON.stringify(mockHeader)),
      "asdf",
      "signature",
    ].join(".");
    await expect(
      verifyClientAttestationPopJwt({
        authorizationServer: "https://auth.example",
        callbacks: { verifyJwt: mockVerifyJwt },
        clientAttestationPopJwt: jwt,
        clientAttestationPublicJwk: mockJwk,
      }),
    ).rejects.toThrow(Oauth2Error);
  });
});
