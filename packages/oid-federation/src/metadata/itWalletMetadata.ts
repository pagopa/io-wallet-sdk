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
    : V extends ItWalletSpecsVersion.V1_3 | ItWalletSpecsVersion.V1_4
      ? ItWalletMetadataV1_3
      : never;

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
      itWalletMetadataV1_3.safeParse(metadata).success,
  });
}

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
        itWalletMetadataV1_3,
        metadata,
        "invalid v1.4 metadata provided",
      ),
  }) as ItWalletMetadataByVersion<V>;
}
