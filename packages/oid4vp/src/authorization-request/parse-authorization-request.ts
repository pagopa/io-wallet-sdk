import { CallbackContext, decodeJwt, Oauth2JwtParseError, RequestDpopOptions } from '@openid4vc/oauth2'
import { AuthorizationRequestObject, zOpenid4vpAuthorizationRequest } from './z-request-object';
import { AuthorizationRequestParsingError } from './errors';
import { Oid4vpParsingError } from '../error/Oid4vpParsingError';
import { ValidationError } from '@openid4vc/utils';

export interface ParseAuthorizeRequestOptions {
    /**
     * The Authorization Request Object JWT.
     */
    requestObjectJwt : string ;

    /**
     * Callback context for signature verification.
     */
    callbacks : Pick<CallbackContext, 'verifyJwt'>

    /**
     * DPoP options
     */
    dpop: RequestDpopOptions
}

/**
 * This method verifies a JWT containing a Request Object and returns its
 * decoded value for further processing
 * @param options {@link ParseAuthorizeRequestOptions}
 * @returns An {@link AuthorizationRequestObject} containing the RP required
 *          credentials
 */
export async function parseAuthorizeRequest(options: ParseAuthorizeRequestOptions) : Promise<AuthorizationRequestObject> {

    try {
        const decoded = decodeJwt({
            jwt : options.requestObjectJwt,
            payloadSchema : zOpenid4vpAuthorizationRequest
        })
        const verificationResult = await options.callbacks.verifyJwt(options.dpop.signer,{
            compact : options.requestObjectJwt,
            header : decoded.header,
            payload : decoded.payload
        })

        if (!verificationResult.verified) throw new AuthorizationRequestParsingError("Error verifying Request Object signature")

        return decoded.payload

    } catch (error) {
        if (error instanceof Oauth2JwtParseError || error instanceof ValidationError) {
            throw new Oid4vpParsingError(error.message)
        }
        throw new AuthorizationRequestParsingError(
            `Unexpected error during Request Object parsing: ${error instanceof Error ? error.message : String(error)}`
        );
    }
}