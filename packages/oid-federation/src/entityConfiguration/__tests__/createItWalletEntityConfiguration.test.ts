import { describe, it, expect, vi } from "vitest";
import { createItWalletEntityConfiguration } from "../createItWalletEntityConfiguration";

describe("createItWalletEntityConfiguration", () => {
  const mockHeader = {
    alg: "ES256",
    kid: "test-kid",
    typ: "entity-statement+jwt" as const,
  };

  const mockClaims = {
    iss: "https://wallet.example.com",
    sub: "https://wallet.example.com",
    exp: 1754321794,
    iat: 1754321794,
    jwks: {
      keys: [
        {
          kty: "EC" as const,
          crv: "P-256",
          x: "...",
          y: "...",
          kid: "test-kid",
        },
      ],
    },
    metadata: {
      federation_entity: {
        contacts: ["info@pagopa.it"],
        tos_uri: "https://io.italia.it/privacy-policy",
        federation_resolve_endpoint: `https://wallet.example.com/resolve`,
        homepage_uri: "https://io.italia.it",
        logo_uri: "https://io.italia.it/assets/img/io-it-logo-blue.svg",
        organization_name: "PagoPa S.p.A.",
        policy_uri: "https://io.italia.it/privacy-policy",
      },
      wallet_provider: {
        jwks: {
          keys: [
            {
              kty: "EC" as const,
              crv: "P-256",
              x: "...",
              y: "...",
              kid: "test-kid",
            },
          ],
        },
      },
    },
  };

  const mockSignJwtCallback = vi.fn(async ({ toBeSigned, jwk }) => {
    const signatureString = `signed-${toBeSigned}-${jwk.kid}`;
    return new TextEncoder().encode(signatureString);
  });

  // Helper to decode Base64Url
  const decodeBase64Url = (str: string) => {
    // Replace URL-safe characters with standard Base64 characters
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    // Pad with '=' if necessary
    while (base64.length % 4) {
      base64 += "=";
    }
    return atob(base64);
  };

  it("should create a signed entity configuration JWT successfully", async () => {
    const result = await createItWalletEntityConfiguration({
      header: mockHeader,
      claims: mockClaims,
      signJwtCallback: mockSignJwtCallback,
    });

    // 1. Check that the result is a string in JWT format (three parts separated by dots).
    expect(typeof result).toBe("string");
    const parts = result.split(".");
    expect(parts).toHaveLength(3);

    const [headerB64, payloadB64, signatureB64] = parts;

    // 2. Decode the header and payload and check their contents.
    const decodedHeader = JSON.parse(decodeBase64Url(headerB64));
    const decodedPayload = JSON.parse(decodeBase64Url(payloadB64));

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
      Uint8Array.from(decodeBase64Url(signatureB64), (c) => c.charCodeAt(0)),
    );
    expect(decodedSignature).toBe(expectedSignature);
  });

  it("should throw an error if header validation fails", async () => {
    const invalidHeader = { ...mockHeader, kid: undefined }; // Invalid header

    await expect(
      createItWalletEntityConfiguration({
        header: invalidHeader,
        claims: mockClaims,
        signJwtCallback: mockSignJwtCallback,
      }),
    ).rejects.toThrow("invalid header claims provided");
  });

  it("should throw an error if claims validation fails", async () => {
    const invalidClaims = { ...mockClaims, iss: undefined }; // Invalid claims

    await expect(
      createItWalletEntityConfiguration({
        header: mockHeader,
        claims: invalidClaims,
        signJwtCallback: mockSignJwtCallback,
      }),
    ).rejects.toThrow("invalid payload claims provided");
  });
});
