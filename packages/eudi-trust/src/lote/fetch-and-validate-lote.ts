import {
  CallbackContext,
  createFetcher,
  decodeJwt,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { EudiTrustError } from "../errors";
import { LOTE_TYPES, LoTEProfile } from "./constants";
import { zLoTEJwtHeader } from "./z-lote";
import {
  zEAAProvidersList,
  zMDLProvidersList,
  zPIDProvidersList,
  zPubEAAProvidersList,
  zWRPACProvidersList,
  zWRPRCProvidersList,
  zWalletProvidersList,
} from "./z-profiles";

export interface FetchLoTEOptions {
  callbacks: Pick<CallbackContext, "fetch">;
  url: string;
}

export async function fetchLoTE(options: FetchLoTEOptions): Promise<string> {
  const fetch = createFetcher(options.callbacks.fetch);

  const response = await fetch(options.url, {
    headers: { Accept: "application/jose, application/jwt" },
  });

  const contentType = response.headers.get("Content-Type");
  if (
    !contentType?.includes("application/jose") &&
    !contentType?.includes("application/jwt")
  ) {
    throw new EudiTrustError(
      `Unsupported LoTE format ${contentType}: only JWT is currently supported.`,
    );
  }

  await hasStatusOrThrow(200)(response);
  return (await response.text()).trim();
}

interface FetchAndValidateLoTEOptions {
  callbacks: Pick<CallbackContext, "fetch">;
  profile: LoTEProfile;
  url: string;
}

const profileConfig: Record<
  LoTEProfile,
  { loTEType: string; schema: z.ZodType }
> = {
  [LoTEProfile.EUEAAProvidersList]: {
    loTEType: LOTE_TYPES.EUEAAProvidersList,
    schema: zEAAProvidersList,
  },
  [LoTEProfile.EUPIDProvidersList]: {
    loTEType: LOTE_TYPES.EUPIDProvidersList,
    schema: zPIDProvidersList,
  },
  [LoTEProfile.EUPubEAAProvidersList]: {
    loTEType: LOTE_TYPES.EUPubEAAProvidersList,
    schema: zPubEAAProvidersList,
  },
  [LoTEProfile.EUWRPACProvidersList]: {
    loTEType: LOTE_TYPES.EUWRPACProvidersList,
    schema: zWRPACProvidersList,
  },
  [LoTEProfile.EUWRPRCProvidersList]: {
    loTEType: LOTE_TYPES.EUWRPRCProvidersList,
    schema: zWRPRCProvidersList,
  },
  [LoTEProfile.EUWalletProvidersList]: {
    loTEType: LOTE_TYPES.EUWalletProvidersList,
    schema: zWalletProvidersList,
  },
  [LoTEProfile.mDLProvidersList]: {
    loTEType: LOTE_TYPES.mDLProvidersList,
    schema: zMDLProvidersList,
  },
};

export async function fetchAndValidateLoTE(
  options: FetchAndValidateLoTEOptions,
  // @ts-ignore
): Promise<any> {
  const loteJwt = await fetchLoTE(options);

  const payloadSchema = profileConfig[options.profile].schema;

  const decodedLote = decodeJwt({
    headerSchema: zLoTEJwtHeader,
    jwt: loteJwt,
    payloadSchema,
  });

  return decodedLote;
}
