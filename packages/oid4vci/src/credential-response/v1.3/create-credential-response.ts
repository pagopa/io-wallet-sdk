import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";

import type { DeferredFlowOptionsV1_3, ImmediateFlowOptions } from "../types";

import {
  type CredentialResponseV1_3,
  zCredentialResponseV1_3,
} from "./z-credential-response";

export function createCredentialResponseV1_3(
  flow: DeferredFlowOptionsV1_3 | ImmediateFlowOptions,
): CredentialResponseV1_3 {
  if ("credentials" in flow) {
    return parseWithErrorHandling(
      zCredentialResponseV1_3,
      {
        credentials: flow.credentials,
        ...(flow.notificationId !== undefined && {
          notification_id: flow.notificationId,
        }),
      },
      "Invalid credential response for ItWalletSpecsVersion 1.3",
    );
  }

  return parseWithErrorHandling(
    zCredentialResponseV1_3,
    {
      interval: flow.interval,
      transaction_id: flow.transactionId,
    },
    "Invalid credential response for ItWalletSpecsVersion 1.3",
  );
}
