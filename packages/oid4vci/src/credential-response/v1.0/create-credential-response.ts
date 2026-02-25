import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";

import type { DeferredFlowOptionsV1_0, ImmediateFlowOptions } from "../types";

import {
  type CredentialResponseV1_0,
  zCredentialResponseV1_0,
} from "./z-credential-response";

export function createCredentialResponseV1_0(
  flow: DeferredFlowOptionsV1_0 | ImmediateFlowOptions,
): CredentialResponseV1_0 {
  if ("credentials" in flow) {
    return parseWithErrorHandling(
      zCredentialResponseV1_0,
      {
        credentials: flow.credentials,
        ...(flow.notificationId !== undefined && {
          notification_id: flow.notificationId,
        }),
      },
      "Invalid credential response for ItWalletSpecsVersion 1.0",
    );
  }

  return parseWithErrorHandling(
    zCredentialResponseV1_0,
    {
      lead_time: flow.leadTime,
      transaction_id: flow.transactionId,
    },
    "Invalid credential response for ItWalletSpecsVersion 1.0",
  );
}
