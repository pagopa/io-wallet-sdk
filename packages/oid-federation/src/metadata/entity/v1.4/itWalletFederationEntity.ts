import { z } from "zod";

import { itWalletFederationEntityMetadata as itWalletFederationEntityMetadataBase } from "../itWalletFederationEntity";

export const itWalletFederationEntityMetadata =
  itWalletFederationEntityMetadataBase
    .extend({ organization_uri: z.url().optional() })
    .refine(
      (metadata) =>
        metadata.homepage_uri !== undefined ||
        metadata.organization_uri !== undefined,
      {
        message:
          "Either 'homepage_uri' or 'organization_uri' must be provided.",
        path: ["homepage_uri"],
      },
    );

export type ItWalletFederationEntityMetadata = z.input<
  typeof itWalletFederationEntityMetadata
>;
