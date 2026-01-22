import { CredentialRequestV1_0 } from "../z-credential";

/**
 * Mock JWT signer for testing v1.0
 */
export const mockSigner = {
  alg: "ES256" as const,
  method: "jwk" as const,
  publicJwk: {
    crv: "P-256",
    kid: "test-kid-v1.0",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  },
};

/**
 * Sample credential request for v1.0
 */
export const sampleCredentialRequestV1_0: CredentialRequestV1_0 = {
  credential_identifier: "UniversityDegree",
  proof: {
    jwt: "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0In0.eyJhdWQiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTcwMDAwMDAwMCwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJub25jZSI6InRlc3Qtbm9uY2UifQ.signature",
    proof_type: "jwt",
  },
};

/**
 * Sample credential response for v1.0 (immediate flow)
 */
export const sampleCredentialResponseV1_0 = {
  credentials: [
    {
      credential:
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXX19.signature",
    },
  ],
};

/**
 * Sample credential response for v1.0 (deferred flow)
 */
export const sampleDeferredCredentialResponseV1_0 = {
  lead_time: 86400,
  transaction_id: "txn_123456789",
};
