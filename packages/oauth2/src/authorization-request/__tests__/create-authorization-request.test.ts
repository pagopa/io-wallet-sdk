import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createPushedAuthorizationRequest, CreatePushedAuthorizationRequestOptions } from '../create-authorization-request'
import { createPkce } from '../../pkce'

vi.mock('../../pkce')
vi.mock('@openid4vc/utils', () => ({
  encodeToBase64Url: vi.fn((data) => `base64url_${data}`)
}))

const mockCreatePkce = vi.mocked(createPkce)

describe('createPushedAuthorizationRequest', () => {
  const mockCallbacks = {
    hash: vi.fn(),
    generateRandom: vi.fn(),
    signJwt: vi.fn()
  }

  const mockSigner = {
    method: "jwk" as const,
    alg: "ES256",
    publicJwk: {
      kid: 'test-kid',
      kty: 'EC',
      crv: 'P-256',
      x: 'test-x',
      y: 'test-y'
    }
  }

  const baseOptions: CreatePushedAuthorizationRequestOptions = {
    callbacks: mockCallbacks,
    codeChallengeMethodsSupported: ['S256'],
    clientId: 'test-client-id',
    audience: 'https://issuer.example.com',
    scope: 'openid',
    responseMode: 'form_post',
    redirectUri: 'https://client.example.com/callback',
    authorization_details: {
      type: 'openid_credential',
      credential_configuration_id: 'test-config'
    },
    dpop: {
      signer: mockSigner
    }
  }

  beforeEach(() => {
    vi.clearAllMocks()
    mockCallbacks.generateRandom.mockResolvedValue(new Uint8Array([1, 2, 3, 4]))
    mockCallbacks.signJwt.mockResolvedValue({ jwt: 'test-jwt-token' })
    mockCreatePkce.mockResolvedValue({
      codeVerifier: 'test-code-verifier',
      codeChallenge: 'test-code-challenge',
      codeChallengeMethod: 'S256' as any
    })
  })

  it('should create a pushed authorization request with PKCE', async () => {
    const result = await createPushedAuthorizationRequest(baseOptions)

    expect(mockCreatePkce).toHaveBeenCalledWith({
      allowedCodeChallengeMethods: ['S256'],
      callbacks: mockCallbacks,
      codeVerifier: undefined
    })

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: {
        alg: 'ES256',
        kid: 'test-kid',
        typ: 'jwt'
      },
      payload: expect.objectContaining({
        aud: 'https://issuer.example.com',
        exp: expect.any(Number),
        iat: expect.any(Number),
        iss: 'test-kid',
        response_type: 'code',
        response_mode: 'form_post',
        state: 'base64url_1,2,3,4',
        client_id: 'test-client-id',
        redirect_uri: 'https://client.example.com/callback',
        scope: 'openid',
        authorization_details: {
          type: 'openid_credential',
          credential_configuration_id: 'test-config'
        },
        code_challenge: 'test-code-challenge',
        code_challenge_method: 'S256',
        jti: 'base64url_1,2,3,4'
      })
    })

    expect(result).toEqual({
      client_id: 'test-client-id',
      request: 'test-jwt-token'
    })
  })

  it('should use provided PKCE code verifier', async () => {
    const optionsWithCodeVerifier = {
      ...baseOptions,
      pkceCodeVerifier: 'custom-code-verifier'
    }

    await createPushedAuthorizationRequest(optionsWithCodeVerifier)

    expect(mockCreatePkce).toHaveBeenCalledWith({
      allowedCodeChallengeMethods: ['S256'],
      callbacks: mockCallbacks,
      codeVerifier: 'custom-code-verifier'
    })
  })

  it('should set correct JWT payload timestamps', async () => {
    const mockNow = Date.now()
    vi.spyOn(Date, 'now').mockReturnValue(mockNow)

    await createPushedAuthorizationRequest(baseOptions)

    const expectedIat = Math.floor(mockNow / 1000)
    const expectedExp = expectedIat + (3600)

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        iat: expectedIat,
        exp: expectedExp
      })
    })
  })

  it('should use signer kid as issuer in JWT payload', async () => {
    const customSigner = {
      method: "jwk" as const,
      alg: "ES256",
      publicJwk: {
        kid: 'custom-signer-kid',
        kty: 'EC',
        crv: 'P-256',
        x: 'custom-x',
        y: 'custom-y'
      }
    }

    const optionsWithCustomSigner = {
      ...baseOptions,
      dpop: {
        signer: customSigner
      }
    }

    await createPushedAuthorizationRequest(optionsWithCustomSigner)

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(customSigner, {
      header: expect.objectContaining({
        kid: 'custom-signer-kid'
      }),
      payload: expect.objectContaining({
        iss: 'custom-signer-kid'
      })
    })
  })

  it('should include all authorization request fields in JWT payload', async () => {
    await createPushedAuthorizationRequest(baseOptions)

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        response_type: 'code',
        response_mode: 'form_post',
        client_id: 'test-client-id',
        scope: 'openid',
        authorization_details: {
          type: 'openid_credential',
          credential_configuration_id: 'test-config'
        },
        redirect_uri: 'https://client.example.com/callback'
      })
    })
  })
})