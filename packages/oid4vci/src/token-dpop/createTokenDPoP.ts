import { CallbackContext, HttpMethod, JwtSigner } from "@openid4vc/oauth2";

/**
 * Options for Token Request DPoP generation
 */
export interface CreateTokenDPoPOptions {
    /**
     * Jwt Signer corresponding to the DPoP's Crypto Context
     */
    signer : JwtSigner

    /**
     * Object containing callbacks for DPoP generation and signature
     */
    callbacks : Pick<CallbackContext, 'signJwt'> & {
        generateRandom : () => Promise<string>
    }

    /**
     * Customizable headers for DPoP signing.
     * As per technical specifications, the key typ will be set to 'dpop+jwt',
     * overriding any custom value passed. In case the alg and jwk properies
     * will not be set, the responsibility of doing so is left to the signJwt
     * callback, which may as well override such keys if passed
     */
    header : Record<string,any>,

    /**
     * Customizable payload for DPoP signing.
     * In case of a missing jti value, a new one
     * will be provided by invoking the generateRandom
     * callback. Any field might be overridden by the signJwt callback
     */
    payload : {
        htm : HttpMethod,
        htu : string,
    } & Record<string, any>
}

/**
 * Creates a signed Token DPoP with the given cryptographic material and data.
 * @param options 
 * @returns A Promise that resolves with an object containing the signed DPoP JWT and
 *          its corresponding public JWK
 */
export async function createTokenDPoP(options : CreateTokenDPoPOptions) {
    
    return options.callbacks.signJwt(
        options.signer,
        {
            header : {
                ...options.header,
                typ : 'dpop+jwt',
            },
            payload : {
                ...options.payload,
                jti : options.payload.jti ?? await options.callbacks.generateRandom()
            }
        }
    )
}