import { createFetcher } from "@openid4vc/utils";

import type { ResolveCredentialOfferOptions } from "./types";

import { CredentialOfferError } from "../errors";
import { parseCredentialOfferUri } from "./parse-credential-offer-uri";
import { type CredentialOffer, zCredentialOffer } from "./z-credential-offer";

/**
 * Resolves a credential offer from a URI or inline JSON string.
 *
 * This function handles multiple input formats:
 * - **URI with inline offer** (by value): The credential offer JSON is embedded in the URI as a URL-encoded parameter
 * - **URI with reference** (by reference): The URI points to a remote endpoint where the credential offer can be fetched
 * - **Direct JSON string**: The credential offer is provided as a plain JSON string
 *
 * Supported URI schemes:
 * - `openid-credential-offer://` - Standard OpenID scheme
 * - `haip-vci://` - High Assurance Interoperability Profile scheme
 * - `https://` - HTTPS Universal Links (preferred)
 *
 * @param options - Resolution options containing the credential offer and fetch callback
 * @returns Resolved and validated credential offer object
 * @throws {CredentialOfferError} If parsing fails, HTTP request fails, or validation fails
 *
 * @example Resolve by-value offer (inline JSON in URI)
 * ```typescript
 * const offer = await resolveCredentialOffer({
 *   credentialOffer: "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A...",
 *   callbacks: { fetch }
 * });
 * console.log(offer.credential_issuer);
 * ```
 *
 * @example Resolve by-reference offer (fetch from remote URI)
 * ```typescript
 * const offer = await resolveCredentialOffer({
 *   credentialOffer: "openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offers/123",
 *   callbacks: { fetch }
 * });
 * console.log(offer.grants.authorization_code.scope);
 * ```
 *
 * @example Resolve from direct JSON string
 * ```typescript
 * const offerJson = '{"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["UniversityDegree"],"grants":{"authorization_code":{"scope":"openid"}}}';
 * const offer = await resolveCredentialOffer({
 *   credentialOffer: offerJson,
 *   callbacks: { fetch }
 * });
 * ```
 */
export async function resolveCredentialOffer(
  options: ResolveCredentialOfferOptions,
): Promise<CredentialOffer> {
  const { callbacks, credentialOffer } = options;

  try {
    // Check if the input is a URI (starts with a known scheme)
    if (
      credentialOffer.startsWith("openid-credential-offer://") ||
      credentialOffer.startsWith("haip-vci://") ||
      credentialOffer.startsWith("https://")
    ) {
      // Parse the URI to extract the scheme and parameters
      const parsed = await parseCredentialOfferUri({ uri: credentialOffer });

      // By value - inline credential offer
      if (parsed.credential_offer) {
        const decoded = decodeURIComponent(parsed.credential_offer);
        const offerJson = JSON.parse(decoded);
        return zCredentialOffer.parse(offerJson);
      }

      // By reference - fetch from remote URI
      if (parsed.credential_offer_uri) {
        const fetch = createFetcher(callbacks.fetch);

        const response = await fetch(parsed.credential_offer_uri, {
          headers: {
            Accept: "application/json",
          },
          method: "GET",
        });

        if (!response.ok) {
          throw new CredentialOfferError(
            `Failed to fetch credential offer from ${parsed.credential_offer_uri}: HTTP ${response.status} ${response.statusText}`,
            response.status,
          );
        }

        const offerJson = await response.json();
        return zCredentialOffer.parse(offerJson);
      }
    }

    // Assume it's a direct JSON string
    const offerJson = JSON.parse(credentialOffer);
    return zCredentialOffer.parse(offerJson);
  } catch (error) {
    // Re-throw CredentialOfferError as-is
    if (error instanceof CredentialOfferError) {
      throw error;
    }

    // Wrap other errors in CredentialOfferError
    throw new CredentialOfferError(
      `Failed to resolve credential offer: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
