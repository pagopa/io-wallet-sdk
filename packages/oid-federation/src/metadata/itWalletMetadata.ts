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
  itWalletSolutionEntityIdentifier,
  itWalletSolutionEntityMetadata,
} from "./entity";

// v1.0 combined metadata
export const itWalletMetadataV1_0 = z.object({
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
export const itWalletMetadataV1_3 = z.object({
  [itWalletAuthorizationServerIdentifierV1_3]:
    itWalletAuthorizationServerMetadataV1_3.optional(),
  [itWalletCredentialIssuerIdentifierV1_3]:
    itWalletCredentialIssuerMetadataV1_3.optional(),
  [itWalletCredentialVerifierIdentifierV1_3]:
    itWalletCredentialVerifierMetadataV1_3.optional(),
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
