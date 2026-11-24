import {
  ItWalletSpecsVersion,
  dispatchByVersion,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";
import { z } from "zod";

import {
  itWalletFederationEntityIdentifier,
  itWalletFederationEntityMetadata,
} from "./entity/itWalletFederationEntity";
import {
  itWalletProviderEntityIdentifier,
  itWalletProviderEntityMetadata,
} from "./entity/v1.0/ItWalletProvider";
import {
  itWalletAuthorizationServerIdentifier,
  itWalletAuthorizationServerMetadata,
} from "./entity/v1.0/itWalletAuthorizationServer";
import {
  itWalletCredentialIssuerIdentifier,
  itWalletCredentialIssuerMetadata,
} from "./entity/v1.0/itWalletCredentialIssuer";
import {
  itWalletCredentialVerifierIdentifier,
  itWalletCredentialVerifierMetadata,
} from "./entity/v1.0/itWalletCredentialVerifier";
import {
  itWalletAuthorizationServerIdentifier as itWalletAuthorizationServerIdentifierV1_3,
  itWalletAuthorizationServerMetadata as itWalletAuthorizationServerMetadataV1_3,
} from "./entity/v1.3/itWalletAuthorizationServer";
import {
  itWalletCredentialIssuerIdentifier as itWalletCredentialIssuerIdentifierV1_3,
  itWalletCredentialIssuerMetadata as itWalletCredentialIssuerMetadataV1_3,
} from "./entity/v1.3/itWalletCredentialIssuer";
import {
  itWalletCredentialVerifierIdentifier as itWalletCredentialVerifierIdentifierV1_3,
  itWalletCredentialVerifierMetadata as itWalletCredentialVerifierMetadataV1_3,
} from "./entity/v1.3/itWalletCredentialVerifier";
import {
  itWalletSolutionEntityIdentifier as itWalletSolutionEntityIdentifierV1_3,
  itWalletSolutionEntityMetadata as itWalletSolutionEntityMetadataV1_3,
} from "./entity/v1.3/itWalletSolution";
import {
  itWalletSolutionEntityIdentifier as itWalletSolutionEntityIdentifierV1_4,
  itWalletSolutionEntityMetadata as itWalletSolutionEntityMetadataV1_4,
} from "./entity/v1.4/itWalletSolution";

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

// v1.4 combined metadata (only wallet_solution diverges from v1.3)
export const itWalletMetadataV1_4 = itWalletMetadataV1_3.extend({
  [itWalletSolutionEntityIdentifierV1_4]:
    itWalletSolutionEntityMetadataV1_4.optional(),
});

// Union — used by entity statement / entity configuration claims.
// Order matters: v1.4 only relaxes v1.3 wallet_solution constraints, so every v1.3
// document also satisfies v1.4. The narrower schema must stay first, otherwise v1.3
// documents would match the v1.4 branch. New versions go after the ones they relax.
export const itWalletMetadataSchema = itWalletMetadataV1_3
  .or(itWalletMetadataV1_4)
  .or(itWalletMetadataV1_0);

// Type-level registry of version -> schema. The generic constraint acts as a
// `satisfies` for types: omitting a version is a compile error here, and every
// version-specific metadata type derives from this single mapping.
type SchemaByVersion<T extends Record<ItWalletSpecsVersion, z.ZodType>> = T;

type ItWalletMetadataSchemaByVersion = SchemaByVersion<{
  [ItWalletSpecsVersion.V1_0]: typeof itWalletMetadataV1_0;
  [ItWalletSpecsVersion.V1_3]: typeof itWalletMetadataV1_3;
  [ItWalletSpecsVersion.V1_4]: typeof itWalletMetadataV1_4;
}>;

export type ItWalletMetadataByVersion<V extends ItWalletSpecsVersion> =
  z.output<ItWalletMetadataSchemaByVersion[V]>;

export type ItWalletMetadataV1_0 =
  ItWalletMetadataByVersion<ItWalletSpecsVersion.V1_0>;
export type ItWalletMetadataV1_3 =
  ItWalletMetadataByVersion<ItWalletSpecsVersion.V1_3>;
export type ItWalletMetadataV1_4 =
  ItWalletMetadataByVersion<ItWalletSpecsVersion.V1_4>;
export type ItWalletMetadata = ItWalletMetadataByVersion<ItWalletSpecsVersion>;

/**
 * Checks whether a metadata object matches the schema for a specific IT-Wallet version.
 *
 * @param metadata - Metadata object to inspect.
 * @param version - IT-Wallet specification version to validate against.
 * @returns True when the metadata satisfies the version-specific schema.
 * @throws {ItWalletSpecsVersionError} If the version is unsupported.
 */
export function isItWalletMetadataVersion<V extends ItWalletSpecsVersion>(
  metadata: unknown,
  version: V,
): metadata is ItWalletMetadataByVersion<V> {
  return dispatchByVersion(version, {
    [ItWalletSpecsVersion.V1_0]: () =>
      itWalletMetadataV1_0.safeParse(metadata).success,
    [ItWalletSpecsVersion.V1_3]: () =>
      itWalletMetadataV1_3.safeParse(metadata).success,
    [ItWalletSpecsVersion.V1_4]: () =>
      itWalletMetadataV1_4.safeParse(metadata).success,
  });
}

/**
 * Parses metadata using the schema for a specific IT-Wallet version.
 *
 * @param metadata - Metadata object to parse.
 * @param version - IT-Wallet specification version to validate against.
 * @returns Version-specific IT-Wallet metadata.
 * @throws {ValidationError} If metadata does not satisfy the selected schema.
 * @throws {ItWalletSpecsVersionError} If the version is unsupported.
 */
export function parseItWalletMetadataForVersion<V extends ItWalletSpecsVersion>(
  metadata: unknown,
  version: V,
): ItWalletMetadataByVersion<V> {
  return dispatchByVersion<ItWalletMetadata>(version, {
    [ItWalletSpecsVersion.V1_0]: () =>
      parseWithErrorHandling(
        itWalletMetadataV1_0,
        metadata,
        "invalid v1.0 metadata provided",
      ),
    [ItWalletSpecsVersion.V1_3]: () =>
      parseWithErrorHandling(
        itWalletMetadataV1_3,
        metadata,
        "invalid v1.3 metadata provided",
      ),
    [ItWalletSpecsVersion.V1_4]: () =>
      parseWithErrorHandling(
        itWalletMetadataV1_4,
        metadata,
        "invalid v1.4 metadata provided",
      ),
  }) as ItWalletMetadataByVersion<V>;
}
