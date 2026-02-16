import { describe, expect, it } from "vitest";

import {
  zMrtdChallengeJwtHeader,
  zMrtdChallengeJwtPayload,
  zMrtdPopInitResponseJwtHeader,
  zMrtdPopInitResponseJwtPayload,
  zMrtdPopVerifyResponse,
  zMrtdValidationJwtHeader,
  zMrtdValidationJwtPayload,
} from "../z-mrtd-pop";

describe("zMrtdChallengeJwtHeader", () => {
  it("should parse a valid header", () => {
    const result = zMrtdChallengeJwtHeader.safeParse({
      alg: "ES256",
      kid: "key-1",
      typ: "mrtd-ias+jwt",
    });
    expect(result.success).toBe(true);
  });

  it("should reject wrong typ", () => {
    const result = zMrtdChallengeJwtHeader.safeParse({
      alg: "ES256",
      kid: "key-1",
      typ: "jwt",
    });
    expect(result.success).toBe(false);
  });

  it("should allow extra fields (passthrough)", () => {
    const result = zMrtdChallengeJwtHeader.safeParse({
      alg: "ES256",
      extra: "field",
      kid: "key-1",
      typ: "mrtd-ias+jwt",
    });
    expect(result.success).toBe(true);
    expect(result.data).toHaveProperty("extra", "field");
  });
});

describe("zMrtdChallengeJwtPayload", () => {
  const validPayload = {
    aud: "https://wallet.example.com",
    exp: 1700000000,
    htm: "POST",
    htu: "https://pid-provider.example.com/edoc-proof/init",
    iat: 1699999000,
    iss: "https://pid-provider.example.com",
    mrtd_auth_session: "session-123",
    mrtd_pop_jwt_nonce: "nonce-456",
    state: "state-789",
    status: "require_interaction",
    type: "mrtd+ias",
  };

  it("should parse a valid payload", () => {
    const result = zMrtdChallengeJwtPayload.safeParse(validPayload);
    expect(result.success).toBe(true);
  });

  it("should reject wrong status", () => {
    const result = zMrtdChallengeJwtPayload.safeParse({
      ...validPayload,
      status: "done",
    });
    expect(result.success).toBe(false);
  });

  it("should reject wrong type", () => {
    const result = zMrtdChallengeJwtPayload.safeParse({
      ...validPayload,
      type: "other",
    });
    expect(result.success).toBe(false);
  });

  it("should reject missing mrtd_auth_session", () => {
    const result = zMrtdChallengeJwtPayload.safeParse({
      ...validPayload,
      mrtd_auth_session: undefined,
    });
    expect(result.success).toBe(false);
  });
});

describe("zMrtdPopInitResponseJwtHeader", () => {
  it("should parse a valid header", () => {
    const result = zMrtdPopInitResponseJwtHeader.safeParse({
      alg: "ES256",
      kid: "key-1",
      typ: "mrtd-ias-pop+jwt",
    });
    expect(result.success).toBe(true);
  });

  it("should reject wrong typ", () => {
    const result = zMrtdPopInitResponseJwtHeader.safeParse({
      alg: "ES256",
      kid: "key-1",
      typ: "mrtd-ias+jwt",
    });
    expect(result.success).toBe(false);
  });
});

describe("zMrtdPopInitResponseJwtPayload", () => {
  const validPayload = {
    aud: "https://wallet.example.com",
    challenge: "challenge-abc",
    exp: 1700000000,
    htm: "POST",
    htu: "https://pid-provider.example.com/edoc-proof/verify",
    iat: 1699999000,
    iss: "https://pid-provider.example.com",
    mrtd_pop_nonce: "nonce-xyz",
  };

  it("should parse a valid payload", () => {
    const result = zMrtdPopInitResponseJwtPayload.safeParse(validPayload);
    expect(result.success).toBe(true);
  });

  it("should parse payload with optional mrz", () => {
    const result = zMrtdPopInitResponseJwtPayload.safeParse({
      ...validPayload,
      mrz: "P<ITABIANCHI<<MARIO<<<",
    });
    expect(result.success).toBe(true);
    expect(result.data?.mrz).toBe("P<ITABIANCHI<<MARIO<<<");
  });

  it("should reject missing challenge", () => {
    const result = zMrtdPopInitResponseJwtPayload.safeParse({
      ...validPayload,
      challenge: undefined,
    });
    expect(result.success).toBe(false);
  });
});

describe("zMrtdValidationJwtHeader", () => {
  it("should parse a valid header", () => {
    const result = zMrtdValidationJwtHeader.safeParse({
      alg: "ES256",
      kid: "wallet-key-1",
      typ: "mrtd-ias+jwt",
    });
    expect(result.success).toBe(true);
  });
});

describe("zMrtdValidationJwtPayload", () => {
  const validPayload = {
    aud: "https://pid-provider.example.com",
    document_type: "cie",
    exp: 1700000000,
    ias: {
      challenge_signed: "Y2hhbGxlbmdl",
      ias_pk: "cHVibGlja2V5",
      sod_ias: "c29kaWFz",
    },
    iat: 1699999000,
    iss: "https://wallet.example.com",
    mrtd: {
      dg1: "ZGcx",
      dg11: "ZGcxMQ==",
      sod_mrtd: "c29kbXJ0ZA==",
    },
  };

  it("should parse a valid payload", () => {
    const result = zMrtdValidationJwtPayload.safeParse(validPayload);
    expect(result.success).toBe(true);
  });

  it("should reject wrong document_type", () => {
    const result = zMrtdValidationJwtPayload.safeParse({
      ...validPayload,
      document_type: "passport",
    });
    expect(result.success).toBe(false);
  });

  it("should reject missing mrtd data", () => {
    const result = zMrtdValidationJwtPayload.safeParse({
      ...validPayload,
      mrtd: undefined,
    });
    expect(result.success).toBe(false);
  });

  it("should reject missing ias data", () => {
    const result = zMrtdValidationJwtPayload.safeParse({
      ...validPayload,
      ias: undefined,
    });
    expect(result.success).toBe(false);
  });
});

describe("zMrtdPopVerifyResponse", () => {
  const validResponse = {
    mrtd_val_pop_nonce: "final-nonce-123",
    redirect_uri: "https://pid-provider.example.com/callback",
    status: "require_interaction",
    type: "redirect_to_web",
  };

  it("should parse a valid response", () => {
    const result = zMrtdPopVerifyResponse.safeParse(validResponse);
    expect(result.success).toBe(true);
  });

  it("should reject wrong status", () => {
    const result = zMrtdPopVerifyResponse.safeParse({
      ...validResponse,
      status: "done",
    });
    expect(result.success).toBe(false);
  });

  it("should reject wrong type", () => {
    const result = zMrtdPopVerifyResponse.safeParse({
      ...validResponse,
      type: "other",
    });
    expect(result.success).toBe(false);
  });

  it("should reject invalid redirect_uri", () => {
    const result = zMrtdPopVerifyResponse.safeParse({
      ...validResponse,
      redirect_uri: "not-a-url",
    });
    expect(result.success).toBe(false);
  });

  it("should allow extra fields (passthrough)", () => {
    const result = zMrtdPopVerifyResponse.safeParse({
      ...validResponse,
      extra: "field",
    });
    expect(result.success).toBe(true);
    expect(result.data).toHaveProperty("extra", "field");
  });
});
