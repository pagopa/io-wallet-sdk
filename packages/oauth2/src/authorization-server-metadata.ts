/**
 * Lean Authorization Server Metadata interface consumed by the oauth2 package.
 *
 * This interface captures only the fields that this package actually reads,
 * keeping it free of any dependency on the `oid-federation` package and preventing
 * a circular build dependency between the two packages.
 *
 * In practice callers pass the richer types produced by `@pagopa/io-wallet-oid-federation`
 * (e.g. `ItWalletAuthorizationServerMetadataV1_3`); those types satisfy this interface
 * structurally, so no explicit cast is required at call sites.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8414 RFC 8414 – OAuth 2.0 Authorization Server Metadata}
 */
export interface BaseAuthorizationServerMetadata {
  /**
   * List of PKCE code-challenge transformation methods supported by the server.
   *
   * IT-Wallet mandates that `"S256"` be present.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7636#section-4.3 RFC 7636 §4.3}
   */
  code_challenge_methods_supported: string[];

  /**
   * URL that uniquely identifies the Authorization Server.
   *
   * Used as the expected `aud` claim when verifying JAR request objects and as the
   * `authorization_server` value when creating Client Attestation PoP JWTs.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8414#section-2 RFC 8414 §2}
   */
  issuer: string;

  /**
   * When `true` the server mandates that every authorization request be sent as a
   * signed JWT (JAR). Unsigned PAR bodies are rejected in that case.
   *
   * Defaults to `false` when absent (permissive mode).
   *
   * @default false
   * @see {@link https://www.rfc-editor.org/rfc/rfc9101#section-10.5 RFC 9101 §10.5}
   */
  require_signed_request_object?: boolean;

  /**
   * Client authentication methods supported by the token endpoint.
   *
   * The oauth2 package inspects this array for the `"attest_jwt_client_auth"` value
   * to determine whether Wallet Attestation–based client authentication is available.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8414#section-2 RFC 8414 §2}
   */
  token_endpoint_auth_methods_supported?: string[];
}
