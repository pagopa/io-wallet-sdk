import type { z } from "zod";

import { itWalletEntityStatementClaimsSchema } from "../entityStatement/itWalletEntityStatementClaims";

export const itWalletEntityConfigurationClaimsSchema =
  itWalletEntityStatementClaimsSchema.refine((data) => data.iss === data.sub, {
    message: "iss and sub must be equal",
    path: ["iss", "sub"],
  });

export type ItWalletEntityConfigurationClaimsOptions = z.input<
  typeof itWalletEntityConfigurationClaimsSchema
>;

export type ItWalletEntityConfigurationClaims = z.output<
  typeof itWalletEntityConfigurationClaimsSchema
>;
