import { ClientAttestationJwtPayload } from "@openid4vc/oauth2";
import { Openid4vciWalletProvider } from "@openid4vc/openid4vci";
import { addSecondsToDate } from "@openid4vc/utils";

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

/**
 * @class ItWalletProvider
 * @extends Openid4vciWalletProvider
 * @description An implementation of a wallet provider for the OpenID4VCI protocol, tailored for a specific ecosystem (e.g., the Italian one).
 * It handles the creation of wallet attestations required during the credential issuance flow.
 */
export class ItWalletProvider extends Openid4vciWalletProvider {
  /**
   * Creates a wallet attestation JWT.
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
    const walletAttestation = await this.createWalletAttestationJwt({
      clientId: options.dpopJwkPublic.kid,
      confirmation: {
        // We use the same key for DPoP as the wallet attestation
        jwk: options.dpopJwkPublic,
      },
      expiresAt:
        options.expiresAt ?? addSecondsToDate(new Date(), 3600 * 24 * 60 * 60),
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
