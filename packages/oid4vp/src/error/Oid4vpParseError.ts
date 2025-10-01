
export class Oid4vpParseError extends Error {
    constructor(message : string) {
        super(message);
        this.name = 'Oid4vpParseError'
    }
}