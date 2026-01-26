import {
  CallbackContext,
  ClientAttestationJwtPayload,
  Jwk,
  JwtSignerX5c,
} from "@openid4vc/oauth2";
import { Openid4vciWalletProvider } from "@openid4vc/openid4vci";
import { addSecondsToDate, dateToSeconds } from "@openid4vc/utils";

import { WalletProviderError } from "../errors";
import { KeyAttestationStatus } from "./z-key-attestation";

/**
 * @interface WalletAttestationOptions
 * @description Defines the options required to create a wallet attestation JWT.
 * This attestation is a signed token that proves the wallet's identity and possession of a cryptographic key.
 */
export interface WalletAttestationOptions {
  /**
   * The public part of the DPoP (Demonstrating Proof-of-Possession) key in JWK (JSON Web Key) format.
   * This key is used to bind the attestation to the client's session.
   * @type {ClientAttestationJwtPayload['cnf']}
   */
  dpopJwkPublic: ClientAttestationJwtPayload["cnf"]["jwk"];

  /**
   * The optional expiration date for the attestation JWT. If not provided, a default lifetime will be used.
   * @type {Date}
   */
  expiresAt?: Date;
  /**
   * The issuer of the attestation, typically the Wallet Provider's identifier.
   * @type {string}
   */
  issuer: string;

  signer: {
    /**
     * An array of JWTs representing the chain of trust from the federation's trust anchor
     * to the wallet provider. This is used in federated identity systems to validate the provider's authenticity.
     * @type {[string, ...string[]]}
     */
    trustChain: [string, ...string[]];

    /**
     * The Key ID (`kid`) of the wallet provider's public key used for signing the attestation.
     * @type {string}
     */
    walletProviderJwkPublicKid: string;
  };

  /**
   * An optional deep link or URL that can be used to open or interact with the wallet.
   * @type {string}
   */
  walletLink?: string;

  /**
   * An optional display name for the wallet.
   * @type {string}
   */
  walletName?: string;
}

export interface KeyAttestationOptions {
  /**
   * The array of JWKs representing the attested keys.
   */
  attestedKeys: [Jwk, ...Jwk[]];

  callbacks: Pick<CallbackContext, "signJwt">;

  /**
   * Optional URL to the key storage component certification.
   */
  certification?: string;

  /**
   * The optional expiration date for the attestation JWT. If not provided, a default lifetime will be used.
   * @type {Date}
   */
  expiresAt?: Date;

  /**
   * The issuance date of the key attestation. Defaults to the current date and time if not provided.
   * @type {Date}
   */
  issuedAt?: Date;

  issuer: string;

  /**
   * The levels of security for key storage as per ISO 18045 standards.
   * @type {[string, ...string[]]}
   */
  keyStorage: [string, ...string[]];

  /**
   * The signer information containing the Key ID and the X.509 certificate chain.
   */
  signer: JwtSignerX5c;

  /**
   * The status information related to the key attestation.
   */
  status: KeyAttestationStatus;

  /**
   * An array of JWTs representing the chain of trust from the federation's trust anchor
   * @type {[string, ...string[]]}
   */
  trustChain?: [string, ...string[]];

  /**
   * The levels of user authentication.
   */
  userAuthentication: [string, ...string[]];
}

/**
 * @class WalletProvider
 * @extends Openid4vciWalletProvider
 * @description An implementation of a wallet provider for the OpenID4VCI protocol, tailored for a specific ecosystem.
 * It handles the creation of wallet attestations required during the credential issuance flow.
 */
export class WalletProvider extends Openid4vciWalletProvider {
  /**
   * Creates a wallet unit attestation.
   *
   * The key attestation is a signed token that describes the attested keys, their storage characteristics,
   * user authentication level, and status, and can include certification and a trust chain as needed.
   *
   * @public
   * @async
   * @param {KeyAttestationOptions} options - The options used to construct and sign the key attestation JWT.
   * @returns {Promise<string>} A promise that resolves to the signed key attestation JWT.
   * @throws {WalletProviderError} Thrown when the JWT cannot be created or signed.
   */
  public async createItKeyAttestationJwt(
    options: KeyAttestationOptions,
  ): Promise<string> {
    const { signJwt } = options.callbacks;

    const issuedAt = options.issuedAt ?? new Date();
    const expiresAt =
      options.expiresAt ?? addSecondsToDate(new Date(), 3600 * 24 * 360);

    const header = {
      alg: options.signer.alg,
      kid: options.signer.kid,
      typ: "key-attestation+jwt" as const,
      x5c: options.signer.x5c,
      ...(options.trustChain && { trust_chain: options.trustChain }),
    };

    const payload = {
      attested_keys: options.attestedKeys,
      exp: dateToSeconds(expiresAt),
      iat: dateToSeconds(issuedAt),
      iss: options.issuer,
      key_storage: options.keyStorage,
      status: options.status,
      user_authentication: options.userAuthentication,
      ...(options.certification && { certification: options.certification }),
    };

    try {
      const { jwt } = await signJwt(options.signer, {
        header,
        payload,
      });

      return jwt;
    } catch (error) {
      throw new WalletProviderError(
        `Failed to create key attestation JWT: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  /**
   * Creates a wallet app attestation JWT.
   *
   * This method constructs a signed JWT that asserts the wallet's control over a specific
   * cryptographic key (DPoP key). This is a security measure to ensure that the entity
   * presenting the credential offer is the legitimate wallet instance.
   *
   * @public
   * @async
   * @param {WalletAttestationOptions} options - The necessary parameters to build the attestation.
   * @returns {Promise<string>} A promise that resolves to the signed wallet attestation JWT as a string.
   */
  public async createItWalletAttestationJwt(
    options: WalletAttestationOptions,
  ): Promise<string> {
    if (!options.dpopJwkPublic.kid) {
      throw new WalletProviderError("The DPoP JWK must have a 'kid' property");
    }

    const walletAttestation = await this.createWalletAttestationJwt({
      clientId: options.dpopJwkPublic.kid,
      confirmation: {
        // We use the same key for DPoP as the wallet attestation
        jwk: options.dpopJwkPublic,
      },
      expiresAt:
        options.expiresAt ?? addSecondsToDate(new Date(), 3600 * 24 * 360),
      issuer: options.issuer,
      signer: {
        alg: "ES256",
        kid: options.signer.walletProviderJwkPublicKid,
        method: "federation", // Indicates the validation method relies on a trust chain.
        trustChain: options.signer.trustChain,
      },
      walletLink: options.walletLink,
      walletName: options.walletName,
    });

    return walletAttestation;
  }
}
