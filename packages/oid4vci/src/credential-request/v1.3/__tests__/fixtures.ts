import { CredentialRequestV1_3 } from "../z-credential";
import { CredentialResponseV1_3 } from "../z-credential-response";

/**
 * Mock JWT signer for testing v1.3
 */
export const mockSigner = {
  alg: "ES256" as const,
  method: "jwk" as const,
  publicJwk: {
    crv: "P-256",
    kid: "test-kid-v1.3",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  },
};

/**
 * Sample key attestation (Wallet Unit Attestation) JWT
 */
export const sampleKeyAttestation =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtleS1hdHRlc3RhdGlvbitqd3QifQ.eyJpc3MiOiJ3YWxsZXQtcHJvdmlkZXIiLCJzdWIiOiJ3YWxsZXQtaW5zdGFuY2UtaWQiLCJpYXQiOjE3MDAwMDAwMDB9.signature";

/**
 * Sample credential request for v1.3 (single credential)
 */
export const sampleCredentialRequestV1_3: CredentialRequestV1_3 = {
  credential_identifier: "education_degree_unibo_2017_l31_informatica",
  proofs: {
    jwt: [
      "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0Iiwia2V5X2F0dGVzdGF0aW9uIjoiZXlKaGJHY2lPaUpGVXpJMU5pSjkuLi4ifQ.eyJhdWQiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImlhdCI6MTcwMDAwMDAwMCwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJub25jZSI6InRlc3Qtbm9uY2UifQ.signature",
    ],
  },
};

/**
 * Sample credential request for v1.3 (batch - multiple credentials)
 */
export const sampleBatchCredentialRequestV1_3: CredentialRequestV1_3 = {
  credential_identifier: "batch_credentials",
  proofs: {
    jwt: [
      "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0In0.proof1.signature1",
      "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0In0.proof2.signature2",
      "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0In0.proof3.signature3",
    ],
  },
};

/**
 * Sample credential response for v1.3 (single credential)
 */
export const sampleCredentialResponseV1_3 = {
  credentials: [
    {
      credential:
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXX19.signature",
    },
  ],
};

/**
 * Sample credential response for v1.3 (batch - multiple credentials)
 */
export const sampleBatchCredentialResponseV1_3 = {
  credentials: [
    {
      credential:
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.credential1-payload.signature1",
    },
    {
      credential:
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.credential2-payload.signature2",
    },
    {
      credential:
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.credential3-payload.signature3",
    },
  ],
};

/**
 * Sample deferred credential response for v1.3
 */
export const sampleDeferredCredentialResponseV1_3: CredentialResponseV1_3 = {
  interval: 86400,
  transaction_id: "txn_v1.3_123456789",
};
