import { Base64 } from "js-base64";
import { describe, expect, it, vi } from "vitest";

import { createItWalletEntityConfiguration } from "../createItWalletEntityConfiguration";

describe("createItWalletEntityConfiguration", () => {
  const mockHeader = {
    alg: "ES256",
    kid: "test-kid",
    typ: "entity-statement+jwt" as const,
  };

  const mockClaims = {
    exp: 1754321794,
    iat: 1754321794,
    iss: "https://wallet.example.com",
    jwks: {
      keys: [
        {
          crv: "P-256",
          kid: "test-kid",
          kty: "EC" as const,
          x: "...",
          y: "...",
        },
      ],
    },
    metadata: {
      federation_entity: {
        contacts: ["info@pagopa.it"],
        federation_resolve_endpoint: `https://wallet.example.com/resolve`,
        homepage_uri: "https://io.italia.it",
        logo_uri: "https://io.italia.it/assets/img/io-it-logo-blue.svg",
        organization_name: "PagoPa S.p.A.",
        policy_uri: "https://io.italia.it/privacy-policy",
        tos_uri: "https://io.italia.it/privacy-policy",
      },
      wallet_provider: {
        jwks: {
          keys: [
            {
              crv: "P-256",
              kid: "test-kid",
              kty: "EC" as const,
              x: "...",
              y: "...",
            },
          ],
        },
      },
    },
    sub: "https://wallet.example.com",
  };

  const mockSignJwtCallback = vi.fn(async ({ jwk, toBeSigned }) => {
    const signatureString = `signed-${toBeSigned}-${jwk.kid}`;
    return new TextEncoder().encode(signatureString);
  });

  it("should create a signed entity configuration JWT successfully", async () => {
    const result = await createItWalletEntityConfiguration({
      claims: mockClaims,
      header: mockHeader,
      signJwtCallback: mockSignJwtCallback,
    });

    // 1. Check that the result is a string in JWT format (three parts separated by dots).
    expect(typeof result).toBe("string");
    const parts = result.split(".");
    expect(parts).toHaveLength(3);

    const [headerB64, payloadB64, signatureB64] = parts;

    // 2. Decode the header and payload and check their contents.
    const decodedHeader = JSON.parse(Base64.decode(headerB64));
    const decodedPayload = JSON.parse(Base64.decode(payloadB64));

    expect(decodedHeader).toEqual(mockHeader);
    expect(decodedPayload).toEqual(mockClaims);

    // 3. Check that our signing callback was called.
    // We can't know the exact `toBeSigned` string without duplicating the library's logic,
    // but we can confirm the callback was called once.
    expect(mockSignJwtCallback).toHaveBeenCalledOnce();
    const callbackArgs = mockSignJwtCallback.mock.calls[0][0];
    expect(callbackArgs.jwk.kid).toBe("test-kid");

    // 4. Check that the signature in the final JWT matches what our callback produced.
    const expectedSignature = new TextDecoder().decode(
      await mockSignJwtCallback.mock.results[0].value,
    );
    // The actual signature in the JWT is also Base64Url encoded
    const decodedSignature = new TextDecoder().decode(
      Uint8Array.from(Base64.decode(signatureB64), (c) => c.charCodeAt(0)),
    );
    expect(decodedSignature).toBe(expectedSignature);
  });

  it("should throw an error if header validation fails", async () => {
    const invalidHeader = { ...mockHeader, kid: undefined }; // Invalid header

    await expect(
      createItWalletEntityConfiguration({
        claims: mockClaims,
        header: invalidHeader,
        signJwtCallback: mockSignJwtCallback,
      }),
    ).rejects.toThrow("invalid header claims provided");
  });

  it("should throw an error if claims validation fails", async () => {
    const invalidClaims = { ...mockClaims, iss: undefined }; // Invalid claims

    await expect(
      createItWalletEntityConfiguration({
        claims: invalidClaims,
        header: mockHeader,
        signJwtCallback: mockSignJwtCallback,
      }),
    ).rejects.toThrow("invalid payload claims provided");
  });
});
