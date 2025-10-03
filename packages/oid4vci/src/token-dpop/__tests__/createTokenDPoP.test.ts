import { beforeEach, describe, expect, it, vi } from "vitest";
import { createTokenDPoP } from "../createTokenDPoP";
import { JwtSigner } from "@openid4vc/oauth2";

const MOCKED_RANDOM = 'random_string'

const callbacks = {
    signJwt : vi.fn(),
    generateRandom : async () => MOCKED_RANDOM
}

describe('Test createTokenDPoP', () => {
    
    beforeEach(() => {
        callbacks.signJwt.mockClear()
    })

    it('should call signJwt with the default values', async () => {
        const header = {}
        const payload = {
            htm : 'POST' as const,
            htu : 'test://uri.htu'
        }

        await createTokenDPoP({
            signer : {} as JwtSigner,
            header,
            payload,
            callbacks
        })

        expect(callbacks.signJwt).toHaveBeenCalledWith(
            {},
            {
                header : {
                    typ : 'dpop+jwt'
                },
                payload : {
                    ...payload,
                    jti : MOCKED_RANDOM
                } 
            }
        )
    })

    it('should pass all extra records of header and payload through', async () => {
        const header = {
            extra : 'This is an extra record',
            extraObject : {
                title: 'This is an extra object\'s title'
            }
        }
        const payload = {
            extra : 'This is an extra record',
            extraObject : {
                label : "Label of an extra object"
            },
            htm : 'POST' as const,
            htu : 'test://uri.htu'
        }

        await createTokenDPoP({
            signer : {} as JwtSigner,
            header,
            payload,
            callbacks
        })

        expect(callbacks.signJwt).toHaveBeenCalledWith(
            {},
            {
                header : {
                    ...header,
                    typ : 'dpop+jwt'
                },
                payload : {
                    ...payload,
                    jti : MOCKED_RANDOM
                } 
            }
        )
    })

    it('should overwrite the typ field in the header', async () => {
        const header = {
            type : 'I will be overwritten'
        }
        const payload = {
            htm : 'POST' as const,
            htu : 'test://uri.htu'
        }

        await createTokenDPoP({
            signer : {} as JwtSigner,
            header,
            payload,
            callbacks
        })

        expect(callbacks.signJwt).toHaveBeenCalledWith(
            {},
            {
                header : {
                    ...header,
                    typ : 'dpop+jwt'
                },
                payload : {
                    ...payload,
                    jti : MOCKED_RANDOM
                } 
            }
        )
    })

    it('should use the default passed jti', async () => {
        const header = {
        }
        const payload = {
            htm : 'POST' as const,
            htu : 'test://uri.htu',
            jti : 'I will not be overwritten'
        }

        await createTokenDPoP({
            signer : {} as JwtSigner,
            header,
            payload,
            callbacks
        })

        expect(callbacks.signJwt).toHaveBeenCalledWith(
            {},
            {
                header : {
                    ...header,
                    typ : 'dpop+jwt'
                },
                payload : {
                    ...payload,
                } 
            }
        )
    })

    it('should keep the extra values in the header but overwrite the typ field', async () => {
        const header = {
            extra : 'This is an extra record',
            extraObject : {
                title: 'This is an extra object\'s title'
            },
            typ : 'I will be overwritten'
        }
        const payload = {
            htm : 'POST' as const,
            htu : 'test://uri.htu',
            extra : 'This is an extra record',
            extraObject : {
                label : "Label of an extra object"
            },
        }

        await createTokenDPoP({
            signer : {} as JwtSigner,
            header,
            payload,
            callbacks
        })

        expect(callbacks.signJwt).toHaveBeenCalledWith(
            {},
            {
                header : {
                    ...header,
                    typ : 'dpop+jwt'
                },
                payload : {
                    ...payload,
                    jti : MOCKED_RANDOM
                } 
            }
        )
    })

    it('should keep the extra values in the payload and not overwrite the jti field', async () => {
        const header = {
        }
        const payload = {
            htm : 'POST' as const,
            htu : 'test://uri.htu',
            jti : 'I will not be overwritten',
            extra : 'This is an extra record',
            extraObject : {
                title: 'This is an extra object\'s title'
            },
        }

        await createTokenDPoP({
            signer : {} as JwtSigner,
            header,
            payload,
            callbacks
        })

        expect(callbacks.signJwt).toHaveBeenCalledWith(
            {},
            {
                header : {
                    typ : 'dpop+jwt'
                },
                payload : {
                    ...payload,
                } 
            }
        )
    })
})