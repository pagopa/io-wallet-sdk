/**
 * Supported LoTE profiles for validation
 */
export enum LoTEProfile {
  EUEAAProvidersList = "EUEAAProvidersList",
  EUPIDProvidersList = "EUPIDProvidersList",
  EUPubEAAProvidersList = "EUPubEAAProvidersList",
  EUWRPACProvidersList = "EUWRPACProvidersList",
  EUWRPRCProvidersList = "EUWRPRCProvidersList",
  EUWalletProvidersList = "EUWalletProvidersList",
  mDLProvidersList = "mDLProvidersList",
}

export const LOTE_TYPES = {
  [LoTEProfile.EUEAAProvidersList]:
    "http://uri.etsi.org/19602/LoTEType/EUEAAProvidersList",
  [LoTEProfile.EUPIDProvidersList]:
    "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
  [LoTEProfile.EUPubEAAProvidersList]:
    "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList",
  [LoTEProfile.EUWRPACProvidersList]:
    "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList",
  [LoTEProfile.EUWRPRCProvidersList]:
    "http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList",
  [LoTEProfile.EUWalletProvidersList]:
    "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList",
  [LoTEProfile.mDLProvidersList]:
    "http://trust.ec.europa.eu/lists/mDL/mDLProvidersListType",
} as const;

/** SDK resource safeguard, not a limit imposed by IT-Wallet or ETSI. */
export const MAX_LOTE_PIVOTS = 100;
