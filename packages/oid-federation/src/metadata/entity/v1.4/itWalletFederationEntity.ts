import { z } from "zod";

import {
  itWalletFederationEntityMetadata as baseItWalletFederationEntityMetadata,
  itWalletFederationEntityIdentifier,
} from "../itWalletFederationEntity";

export const itWalletFederationEntityMetadata =
  baseItWalletFederationEntityMetadata
    .extend({
      organization_uri: z.url().optional(),
    })
    .refine(
      (metadata) =>
        metadata.homepage_uri !== undefined ||
        metadata.organization_uri !== undefined,
      {
        message: "at least one of homepage_uri or organization_uri is required",
        path: ["homepage_uri"],
      },
    );

export type ItWalletFederationEntityMetadata = z.input<
  typeof itWalletFederationEntityMetadata
>;

export { itWalletFederationEntityIdentifier };
