import { beforeEach, describe, expect, it, vi } from "vitest";

import { MrtdPopError } from "../../errors";
import {
  CreateMrtdValidationJwtOptions,
  createMrtdValidationJwt,
} from "../create-mrtd-validation-jwt";

const mockSignJwt = vi.fn();

const mockSigner = {
  alg: "ES256",
  method: "jwk" as const,
  publicJwk: {
    crv: "P-256",
    kid: "wallet-key-1",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  },
};

const validDocumentData = {
  challengeSigned: "c2lnbmVkLWNoYWxsZW5nZQ==",
  dg1: "ZGcx",
  dg11: "ZGcxMQ==",
  iasPk: "cHVibGlja2V5",
  sodIas: "c29kaWFz",
  sodMrtd: "c29kbXJ0ZA==",
};

const baseOptions: CreateMrtdValidationJwtOptions = {
  audience: "https://pid-provider.example.com",
  callbacks: { signJwt: mockSignJwt },
  clientId: "https://wallet.example.com",
  documentData: validDocumentData,
  issuedAt: new Date("2023-11-15T00:00:00Z"),
  signer: mockSigner,
};

describe("createMrtdValidationJwt", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockSignJwt.mockResolvedValue({
      jwt: "signed-validation-jwt",
      signerJwk: mockSigner.publicJwk,
    });
  });

  it("should create a signed validation JWT", async () => {
    const result = await createMrtdValidationJwt(baseOptions);

    expect(result).toEqual({ jwt: "signed-validation-jwt" });
  });

  it("should call signJwt with correct header and payload", async () => {
    await createMrtdValidationJwt(baseOptions);

    expect(mockSignJwt).toHaveBeenCalledWith(mockSigner, {
      header: {
        alg: "ES256",
        kid: "wallet-key-1",
        typ: "mrtd-ias+jwt",
      },
      payload: expect.objectContaining({
        aud: "https://pid-provider.example.com",
        document_type: "cie",
        ias: {
          challenge_signed: "c2lnbmVkLWNoYWxsZW5nZQ==",
          ias_pk: "cHVibGlja2V5",
          sod_ias: "c29kaWFz",
        },
        iss: "https://wallet.example.com",
        mrtd: {
          dg1: "ZGcx",
          dg11: "ZGcxMQ==",
          sod_mrtd: "c29kbXJ0ZA==",
        },
      }),
    });
  });

  it("should set exp to iat + 300 seconds", async () => {
    await createMrtdValidationJwt(baseOptions);

    const callArgs = mockSignJwt.mock.calls[0] as unknown as [
      unknown,
      { header: unknown; payload: { exp: number; iat: number } },
    ];
    const payload = callArgs[1].payload;
    expect(payload.exp - payload.iat).toBe(300);
  });

  it("should use provided issuedAt date", async () => {
    await createMrtdValidationJwt(baseOptions);

    const callArgs = mockSignJwt.mock.calls[0] as unknown as [
      unknown,
      { header: unknown; payload: { iat: number } },
    ];
    expect(callArgs[1].payload.iat).toBe(1700006400);
  });

  it("should throw MrtdPopError when signJwt fails", async () => {
    mockSignJwt.mockRejectedValue(new Error("Signing failed"));

    await expect(createMrtdValidationJwt(baseOptions)).rejects.toThrow(
      MrtdPopError,
    );
    await expect(createMrtdValidationJwt(baseOptions)).rejects.toThrow(
      /Signing failed/,
    );
  });
});
