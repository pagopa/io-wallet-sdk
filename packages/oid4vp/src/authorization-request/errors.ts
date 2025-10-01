
export class AuthorizationRequestParsingError extends Error {
    constructor(message: string) {
        super(message) ;
        this.name = 'AuthorizationRequestParsingError'
    }
}