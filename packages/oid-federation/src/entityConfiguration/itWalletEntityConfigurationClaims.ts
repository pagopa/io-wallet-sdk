import type { z } from "zod";

import { itWalletEntityStatementClaimsSchema } from "../entityStatement/itWalletEntityStatementClaims";

export const itWalletEntityConfigurationClaimsSchema =
  itWalletEntityStatementClaimsSchema;

export type ItWalletEntityConfigurationClaimsOptions = z.input<
  typeof itWalletEntityConfigurationClaimsSchema
>;

export type ItWalletEntityConfigurationClaims = z.output<
  typeof itWalletEntityConfigurationClaimsSchema
>;
