import type { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";
import type { z } from "zod";

import {
  ItWalletEntityStatementClaimsByVersion,
  isItWalletEntityStatementClaimsVersion,
  itWalletEntityStatementClaimsSchema,
  parseItWalletEntityStatementClaimsForVersion,
} from "../entityStatement/itWalletEntityStatementClaims";

export const itWalletEntityConfigurationClaimsSchema =
  itWalletEntityStatementClaimsSchema;

export type ItWalletEntityConfigurationClaimsOptions = z.input<
  typeof itWalletEntityConfigurationClaimsSchema
>;

export type ItWalletEntityConfigurationClaims = z.output<
  typeof itWalletEntityConfigurationClaimsSchema
>;

export type ItWalletEntityConfigurationClaimsByVersion<
  V extends ItWalletSpecsVersion,
> = ItWalletEntityStatementClaimsByVersion<V>;

export const isItWalletEntityConfigurationClaimsVersion =
  isItWalletEntityStatementClaimsVersion;

export const parseItWalletEntityConfigurationClaimsForVersion =
  parseItWalletEntityStatementClaimsForVersion;
