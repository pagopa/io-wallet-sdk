import { CallbackContext, JwtSignerJwk } from "@openid4vc/oauth2";
import { AuthorizationRequestObject } from "../z-request-object";
import {describe, it, expect} from 'vitest'
import { parseAuthorizeRequest } from "../parse-authorization-request";
import { Oid4vpParsingError } from "../../error";
import { AuthorizationRequestParsingError } from "../errors";
const jose = import('jose')

const publicKey = {
  kty: 'EC',
  x: 'PHIgk53SKmRS3W4FVcv-JoeR9lCAsMa0dUZCKxqO05k',
  y: 'EzFFYlGAcw5cjcbKey7bYz0CX3hX2raWPokqOB60wCI',
  crv: 'P-256'
}

const wrongPublicKey = {
  kty: 'EC',
  x: 'VJ23NtKusfLrtx1a2CMsieJJ8PiI_olk6RgLEN7xuEU',
  y: 'NU5kLnG73gcamaSd4rilxgNRiz5WmO-EE0zCKe0hG8c',
  crv: 'P-256'
}

const wrongPubKeySigner : JwtSignerJwk = {
    method : 'jwk',
    publicJwk :  wrongPublicKey,
    alg : 'ES256'
}

const signer : JwtSignerJwk = {
    method : 'jwk',
    publicJwk :  publicKey,
    alg : 'ES256'
}


const correctRequestObject : AuthorizationRequestObject = {
    response_type : 'vp_token',
    client_id : 'test-client-id',
    response_uri : 'uri://response.example.com',
    request_uri : "uri://request.example.com",
    request_uri_method : "POST",
    response_mode : "direct_post.jwt",
    nonce : 'test_nonce',
    wallet_nonce : "Test wallet nonce",
    scope : 'test_presentation_scope',
    state : 'test_state',
    dcql_query : {},
    iss : 'test-client-id',
    iat : new Date('2025-09-15').getTime(),
    exp : new Date('2035-09-15').getTime()
}
const correctRequestObjectJwt = "eyJhbGciOiJFUzI1NiJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MjA3MzQyNzIwMDAwMH0.GT369294NeghTjkOYTeNgz7U59ZO921Ln9w7-NDieM-QwIfXIL7Iw3n2vzKCHnIbOIrjOnNVRS-aA66tGAXSzg"

/**
 * The missingMandatoryFieldRequestObjectJwt is obtained by signing the missingMandatoryFieldRequestObject defined below
 * const {response_type : _ , ...missingMandatoryFieldRequestObject} = correctRequestObject
 */
const missingMandatoryFieldRequestObjectJwt = 'eyJhbGciOiJFUzI1NiJ9.eyJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MjA3MzQyNzIwMDAwMH0.yLnTKqriqWMaNGWbppY0HVoQ63VEzbD4isG9VGm61uhn6aB9js7juxjQQZ9W0qJrOUhYVwipg8HsWeUCBHbH5w'

/**
 * The nonConformingRequestObjectJwt is obtained by signing this object
 * const nonConformingRequestObject = {
 *     ...correctRequestObject,
 *     response_type : 3,
 *     response_uri : 'this is not a uri',
 *     request_uri : undefined,
 *     response_mode : 'direct_post',
 *     dcql_query : [],
 * }
 */
const nonConformingRequestObjectJwt = 'eyJhbGciOiJFUzI1NiJ9.eyJyZXNwb25zZV90eXBlIjozLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsInJlc3BvbnNlX3VyaSI6InRoaXMgaXMgbm90IGEgdXJpIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoidGVzdF9ub25jZSIsIndhbGxldF9ub25jZSI6IlRlc3Qgd2FsbGV0IG5vbmNlIiwic2NvcGUiOiJ0ZXN0X3ByZXNlbnRhdGlvbl9zY29wZSIsInN0YXRlIjoidGVzdF9zdGF0ZSIsImRjcWxfcXVlcnkiOltdLCJpc3MiOiJ0ZXN0LWNsaWVudC1pZCIsImlhdCI6MTc1Nzg5NDQwMDAwMCwiZXhwIjoyMDczNDI3MjAwMDAwfQ.G1uqCoFcvdUR8JxQOnrUKfRr388mLEwltwx06kH9TOT-SReyB4syUBhADYjf3AjI89OGvsGkTOVbfe2MOxwW5w'

const expiredRequestObject = {
    ...correctRequestObject,
    exp : new Date('2025-09-16').getTime()
}
const expiredRequestObjectJwt = 'eyJhbGciOiJFUzI1NiJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudC1pZCIsInJlc3BvbnNlX3VyaSI6InVyaTovL3Jlc3BvbnNlLmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmkiOiJ1cmk6Ly9yZXF1ZXN0LmV4YW1wbGUuY29tIiwicmVxdWVzdF91cmlfbWV0aG9kIjoiUE9TVCIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6InRlc3Rfbm9uY2UiLCJ3YWxsZXRfbm9uY2UiOiJUZXN0IHdhbGxldCBub25jZSIsInNjb3BlIjoidGVzdF9wcmVzZW50YXRpb25fc2NvcGUiLCJzdGF0ZSI6InRlc3Rfc3RhdGUiLCJkY3FsX3F1ZXJ5Ijp7fSwiaXNzIjoidGVzdC1jbGllbnQtaWQiLCJpYXQiOjE3NTc4OTQ0MDAwMDAsImV4cCI6MTc1Nzk4MDgwMDAwMH0.KqO6GEbcB4rS8I5PPaxDZurG1ni2ti95ZCdSawcfXf74uNvtJoNL-Wx7gz3mUUtkakIaICsMi-dgbN4u6SibDA'

const callbacks: Pick<CallbackContext, 'verifyJwt'> = {
    verifyJwt : async (signer, {compact}) => {
        const {jwtVerify} = await jose
        if (signer.method === 'jwk') {
            try {
                await jwtVerify(compact, signer.publicJwk)
                return {
                    verified : true,
                    signerJwk : signer.publicJwk
                }
            } catch {
                return {
                    verified : false,
                }
            }
        }
        return {
            verified : false
        }
    }
}

describe('parseAuthorizationRequest tests', async () => {

    it('should parse and verify the request object correctly', async () => {
        const actualRequestObject = await parseAuthorizeRequest({
            requestObjectJwt : correctRequestObjectJwt,
            dpop : {signer},
            callbacks 
        })
        expect(actualRequestObject).toEqual(correctRequestObject)
    })

    it('should throw an OidvpParseError for missing mandatory fields', () => {
        expect(async () => await parseAuthorizeRequest({
            requestObjectJwt : missingMandatoryFieldRequestObjectJwt,
            dpop : {signer},
            callbacks 
        })).rejects.toThrow(Oid4vpParsingError)
    })

    it('should throw an Oid4vpParseError for non conforming structure', () => {
        expect(async () => await parseAuthorizeRequest({
            requestObjectJwt : nonConformingRequestObjectJwt,
            dpop : {signer},
            callbacks 
        })).rejects.toThrow(Oid4vpParsingError)
    })

    it('should parse and verify the request object correctly since expiration is not checked', async () => {
        const actualRequestObject = await parseAuthorizeRequest({
            requestObjectJwt : expiredRequestObjectJwt,
            dpop : {signer},
            callbacks 
        })
        expect(actualRequestObject).toEqual(expiredRequestObject)
    })

    it('should throw an Oid4vpParseError because of a malformed jwt', () => {
        expect(async () => parseAuthorizeRequest({
            requestObjectJwt : 'this is not a JWT',
            dpop : {signer},
            callbacks 
        })).rejects.toThrow(Oid4vpParsingError)
    })

    it('should throw an AuthorizationRequestParsingError because of a malformed signature', () => {
        expect(async () => {
            const [head, payload] = (correctRequestObjectJwt).split('.')
            await parseAuthorizeRequest({
                requestObjectJwt : `${head}.${payload}.this_is_not_a_signature`,
                dpop : {signer},
                callbacks 
            })
        }).rejects.toThrow(AuthorizationRequestParsingError)
    })

    it('should throw an AuthorizationRequestParsingError because of a missing signature', () => {
        expect(async () => {
            const [head, payload] = (correctRequestObjectJwt).split('.')
            await parseAuthorizeRequest({
                requestObjectJwt : `${head}.${payload}.`,
                dpop : {signer},
                callbacks 
            })
        }).rejects.toThrow(AuthorizationRequestParsingError)
    })

    it('should throw an AuthorizationRequestParsingError because of a mismatching public key signer', () => {
        expect(async () => {
            await parseAuthorizeRequest({
                requestObjectJwt : correctRequestObjectJwt,
                dpop : {signer : wrongPubKeySigner},
                callbacks 
            })
        }).rejects.toThrow(AuthorizationRequestParsingError)
    })
})