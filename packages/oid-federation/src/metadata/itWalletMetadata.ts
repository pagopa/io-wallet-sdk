import { z } from "zod";

import {
  itWalletFederationEntityIdentifier,
  itWalletFederationEntityMetadata,
} from "./entity/itWalletFederationEntity";
import {
  itWalletAuthorizationServerIdentifier,
  itWalletAuthorizationServerMetadata as itWalletAuthorizationServerMetadataV1_0,
  itWalletCredentialIssuerIdentifier,
  itWalletCredentialIssuerMetadata,
  itWalletCredentialVerifierIdentifier,
  itWalletCredentialVerifierMetadata,
  itWalletProviderEntityIdentifier,
  itWalletProviderEntityMetadata,
} from "./entity/v1.0";
import {
  itWalletAuthorizationServerMetadata as itWalletAuthorizationServerMetadataV1_3,
  itWalletSolutionEntityIdentifier,
  itWalletSolutionEntityMetadata,
} from "./entity/v1.3";

// v1.0 combined metadata
export const itWalletMetadataV1_0 = z.object({
  [itWalletAuthorizationServerIdentifier]:
    itWalletAuthorizationServerMetadataV1_0.optional(),
  [itWalletCredentialIssuerIdentifier]:
    itWalletCredentialIssuerMetadata.optional(),
  [itWalletCredentialVerifierIdentifier]:
    itWalletCredentialVerifierMetadata.optional(),
  [itWalletFederationEntityIdentifier]:
    itWalletFederationEntityMetadata.optional(),
  [itWalletProviderEntityIdentifier]: itWalletProviderEntityMetadata.optional(),
});

// v1.3 combined metadata (stubs re-export v1.0 schemas for some entities)
export const itWalletMetadataV1_3 = z.object({
  [itWalletAuthorizationServerIdentifier]:
    itWalletAuthorizationServerMetadataV1_3.optional(),
  [itWalletCredentialIssuerIdentifier]:
    itWalletCredentialIssuerMetadata.optional(),
  [itWalletCredentialVerifierIdentifier]:
    itWalletCredentialVerifierMetadata.optional(),
  [itWalletFederationEntityIdentifier]:
    itWalletFederationEntityMetadata.optional(),
  [itWalletSolutionEntityIdentifier]: itWalletSolutionEntityMetadata.optional(),
});

// Union — used by entity statement / entity configuration claims
export const itWalletMetadataSchema =
  itWalletMetadataV1_0.or(itWalletMetadataV1_3);

export type MetadataV1_0 = z.input<typeof itWalletMetadataV1_0>;
export type MetadataV1_3 = z.input<typeof itWalletMetadataV1_3>;
export type Metadata = MetadataV1_0 | MetadataV1_3;
