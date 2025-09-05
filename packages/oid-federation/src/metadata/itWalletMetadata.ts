import { z } from "zod";
import {
  itWalletFederationEntityMetadata,
  itWalletFederationEntityIdentifier,
  itWalletProviderEntityMetadata,
  itWalletProviderEntityIdentifier,
  itWalletCredentialVerifierMetadata,
  itWalletCredentialVerifierIdentifier,
  itWalletAuthorizationServerIdentifier,
  itWalletAuthorizationServerMetadata,
  itWalletCredentialIssuerIdentifier,
  itWalletCredentialIssuerMetadata,
} from "./entity";

export const itWalletMetadataSchema = z.object({
  [itWalletFederationEntityIdentifier]:
    itWalletFederationEntityMetadata.optional(),
  [itWalletCredentialVerifierIdentifier]:
    itWalletCredentialVerifierMetadata.optional(),
  [itWalletCredentialIssuerIdentifier]:
    itWalletCredentialIssuerMetadata.optional(),
  [itWalletProviderEntityIdentifier]: itWalletProviderEntityMetadata.optional(),
  [itWalletAuthorizationServerIdentifier]:
    itWalletAuthorizationServerMetadata.optional(),
});

export type Metadata = z.input<typeof itWalletMetadataSchema>;
