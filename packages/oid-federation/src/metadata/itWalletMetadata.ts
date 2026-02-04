import { z } from "zod";

import {
  itWalletFederationEntityIdentifier,
  itWalletFederationEntityMetadata,
} from "./entity/itWalletFederationEntity";
import {
  itWalletAuthorizationServerIdentifier,
  itWalletAuthorizationServerMetadata,
  itWalletCredentialIssuerIdentifier,
  itWalletCredentialIssuerMetadata,
  itWalletCredentialVerifierIdentifier,
  itWalletCredentialVerifierMetadata,
  itWalletProviderEntityIdentifier,
  itWalletProviderEntityMetadata,
} from "./entity/v1.0";
import {
  itWalletSolutionEntityIdentifier,
  itWalletSolutionEntityMetadata,
} from "./entity/v1.3";

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

export type Metadata = z.input<typeof itWalletMetadataSchema>;
