export * from "./itWalletFederationEntity";
export * from "./v1.0";

// v1.3 exports with version suffixes for disambiguation
export {
  itWalletAuthorizationServerIdentifier as itWalletAuthorizationServerIdentifierV1_3,
  itWalletAuthorizationServerMetadata as itWalletAuthorizationServerMetadataV1_3,
  itWalletCredentialIssuerIdentifier as itWalletCredentialIssuerIdentifierV1_3,
  itWalletCredentialIssuerMetadata as itWalletCredentialIssuerMetadataV1_3,
  itWalletCredentialVerifierIdentifier as itWalletCredentialVerifierIdentifierV1_3,
  itWalletCredentialVerifierMetadata as itWalletCredentialVerifierMetadataV1_3,
  itWalletSolutionEntityIdentifier,
  itWalletSolutionEntityMetadata,
} from "./v1.3";
export type {
  ItWalletAuthorizationServerMetadata as ItWalletAuthorizationServerMetadataV1_3,
  ItWalletCredentialIssuerMetadata as ItWalletCredentialIssuerMetadataV1_3,
  ItWalletCredentialVerifierMetadata as ItWalletCredentialVerifierMetadataV1_3,
  ItWalletSolutionEntityMetadata,
} from "./v1.3";
