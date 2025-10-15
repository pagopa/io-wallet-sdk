import { z } from "zod";

import {
  itWalletAuthorizationServerIdentifier,
  itWalletAuthorizationServerMetadata,
  itWalletCredentialIssuerIdentifier,
  itWalletCredentialIssuerMetadata,
  itWalletCredentialVerifierIdentifier,
  itWalletCredentialVerifierMetadata,
  itWalletFederationEntityIdentifier,
  itWalletFederationEntityMetadata,
  itWalletProviderEntityIdentifier,
  itWalletProviderEntityMetadata,
} from "./entity";

export const itWalletMetadataSchema = z.object({
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
