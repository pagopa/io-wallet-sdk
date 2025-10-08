/**
 * Package level error class which wraps parsing
 * and validation errors
 */
export class Oid4vpParsingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Oid4vpParsingError";
  }
}
