import {
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";
import { z } from "zod";

import {
  itWalletAuthorizationServerIdentifier,
  itWalletAuthorizationServerIdentifierV1_3,
  itWalletAuthorizationServerMetadata,
  itWalletAuthorizationServerMetadataV1_3,
  itWalletCredentialIssuerIdentifier,
  itWalletCredentialIssuerIdentifierV1_3,
  itWalletCredentialIssuerMetadata,
  itWalletCredentialIssuerMetadataV1_3,
  itWalletCredentialVerifierIdentifier,
  itWalletCredentialVerifierIdentifierV1_3,
  itWalletCredentialVerifierMetadata,
  itWalletCredentialVerifierMetadataV1_3,
  itWalletFederationEntityIdentifier,
  itWalletFederationEntityMetadata,
  itWalletProviderEntityIdentifier,
  itWalletProviderEntityMetadata,
  itWalletSolutionEntityIdentifierV1_3,
  itWalletSolutionEntityMetadataV1_3,
} from "./entity";

// v1.0 combined metadata
export const itWalletMetadataV1_0 = z.strictObject({
  [itWalletAuthorizationServerIdentifier]:
    itWalletAuthorizationServerMetadata.optional(),
  [itWalletCredentialIssuerIdentifier]:
    itWalletCredentialIssuerMetadata.optional(),
  [itWalletCredentialVerifierIdentifier]:
    itWalletCredentialVerifierMetadata.optional(),
  [itWalletFederationEntityIdentifier]:
    itWalletFederationEntityMetadata.optional(),
  [itWalletProviderEntityIdentifier]: itWalletProviderEntityMetadata.optional(),
});

// v1.3 combined metadata (stubs re-export v1.0 schemas for some entities)
export const itWalletMetadataV1_3 = z.strictObject({
  [itWalletAuthorizationServerIdentifierV1_3]:
    itWalletAuthorizationServerMetadataV1_3.optional(),
  [itWalletCredentialIssuerIdentifierV1_3]:
    itWalletCredentialIssuerMetadataV1_3.optional(),
  [itWalletCredentialVerifierIdentifierV1_3]:
    itWalletCredentialVerifierMetadataV1_3.optional(),
  [itWalletFederationEntityIdentifier]:
    itWalletFederationEntityMetadata.optional(),
  [itWalletSolutionEntityIdentifierV1_3]:
    itWalletSolutionEntityMetadataV1_3.optional(),
});

// Union — used by entity statement / entity configuration claims
// v1.3 is tried first so that v1.3-specific fields are preserved during parsing
export const itWalletMetadataSchema =
  itWalletMetadataV1_3.or(itWalletMetadataV1_0);

export type ItWalletMetadataV1_0 = z.output<typeof itWalletMetadataV1_0>;
export type ItWalletMetadataV1_3 = z.output<typeof itWalletMetadataV1_3>;
export type ItWalletMetadata = ItWalletMetadataV1_0 | ItWalletMetadataV1_3;

export type ItWalletMetadataByVersion<V extends ItWalletSpecsVersion> =
  V extends ItWalletSpecsVersion.V1_0
    ? ItWalletMetadataV1_0
    : V extends ItWalletSpecsVersion.V1_3
      ? ItWalletMetadataV1_3
      : never;

export function isItWalletMetadataVersion<V extends ItWalletSpecsVersion>(
  metadata: unknown,
  version: V,
): metadata is ItWalletMetadataByVersion<V> {
  switch (version) {
    case ItWalletSpecsVersion.V1_0:
      return itWalletMetadataV1_0.safeParse(metadata).success;
    case ItWalletSpecsVersion.V1_3:
      return itWalletMetadataV1_3.safeParse(metadata).success;
    default:
      throw new ItWalletSpecsVersionError(
        "isItWalletMetadataVersion",
        version,
        [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
      );
  }
}

export function parseItWalletMetadataForVersion<V extends ItWalletSpecsVersion>(
  metadata: unknown,
  version: V,
): ItWalletMetadataByVersion<V> {
  switch (version) {
    case ItWalletSpecsVersion.V1_0:
      return parseWithErrorHandling(
        itWalletMetadataV1_0,
        metadata,
        "invalid v1.0 metadata provided",
      ) as ItWalletMetadataByVersion<V>;
    case ItWalletSpecsVersion.V1_3:
      return parseWithErrorHandling(
        itWalletMetadataV1_3,
        metadata,
        "invalid v1.3 metadata provided",
      ) as ItWalletMetadataByVersion<V>;
    default:
      throw new ItWalletSpecsVersionError(
        "parseItWalletMetadataForVersion",
        version,
        [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
      );
  }
}
