import type { ParseCredentialOfferUriOptions } from "./types";

import { CredentialOfferError } from "../errors";
import {
  type CredentialOfferUri,
  zCredentialOfferUri,
} from "./z-credential-offer";

/**
 * Parses a credential offer URI and extracts the scheme and parameters.
 *
 * This function supports three URL schemes for credential offers:
 * - `openid-credential-offer://` - Standard OpenID scheme (custom URL scheme)
 * - `haip-vci://` - High Assurance Interoperability Profile scheme (custom URL scheme)
 * - `https://` - HTTPS Universal Links (preferred method)
 *
 * Credential offers can be transmitted in two ways:
 * - **By value**: The `credential_offer` parameter contains the JSON directly (URL-encoded)
 * - **By reference**: The `credential_offer_uri` parameter points to a URL where the JSON can be fetched
 *
 * @param options - Parsing options containing the URI and allowed schemes
 * @returns Parsed credential offer URI components with scheme and parameters
 * @throws {CredentialOfferError} If the URI is invalid, uses an unsupported scheme, or is missing required parameters
 *
 * @example Parse by-value offer with custom scheme
 * ```typescript
 * const parsed = await parseCredentialOfferUri({
 *   uri: "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A..."
 * });
 * console.log(parsed.scheme); // "openid-credential-offer"
 * console.log(parsed.credential_offer); // URL-decoded JSON string
 * ```
 *
 * @example Parse by-reference offer with HTTPS Universal Link
 * ```typescript
 * const parsed = await parseCredentialOfferUri({
 *   uri: "https://wallet.example.com/credential-offer?credential_offer_uri=https://issuer.example.com/offers/123"
 * });
 * console.log(parsed.scheme); // "https"
 * console.log(parsed.credential_offer_uri); // "https://issuer.example.com/offers/123"
 * ```
 *
 * @example Restrict allowed schemes
 * ```typescript
 * const parsed = await parseCredentialOfferUri({
 *   uri: "openid-credential-offer://?credential_offer=...",
 *   allowedSchemes: ["openid-credential-offer"] // Only allow standard OpenID scheme
 * });
 * ```
 */
export async function parseCredentialOfferUri(
  options: ParseCredentialOfferUriOptions,
): Promise<CredentialOfferUri> {
  const {
    allowedSchemes = ["openid-credential-offer", "haip-vci", "https"],
    uri,
  } = options;

  try {
    // Parse the URI using the URL API
    const url = new URL(uri);

    // Extract and validate the scheme (protocol without the trailing colon)
    const scheme = url.protocol.replace(":", "");

    if (!allowedSchemes.includes(scheme)) {
      throw new CredentialOfferError(
        `Unsupported URL scheme: ${scheme}. Allowed schemes: ${allowedSchemes.join(", ")}`,
      );
    }

    // Extract query parameters
    const credentialOffer = url.searchParams.get("credential_offer");
    const credentialOfferUri = url.searchParams.get("credential_offer_uri");

    // Construct the parsed result
    const parsed = {
      credential_offer: credentialOffer || undefined,
      credential_offer_uri: credentialOfferUri || undefined,
      scheme: scheme as "haip-vci" | "https" | "openid-credential-offer",
    };

    // Validate the structure using Zod
    // This will ensure that at least one of credential_offer or credential_offer_uri is present
    return zCredentialOfferUri.parse(parsed);
  } catch (error) {
    // Re-throw CredentialOfferError as-is
    if (error instanceof CredentialOfferError) {
      throw error;
    }

    // Wrap other errors in CredentialOfferError
    throw new CredentialOfferError(
      `Failed to parse credential offer URI: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
