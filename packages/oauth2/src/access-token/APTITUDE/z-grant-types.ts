import z from "zod";

export const zPreAuthorizedCodeGrantIdentifier = z.literal(
  "urn:ietf:params:oauth:grant-type:pre-authorized_code",
);
export const preAuthorizedCodeGrantIdentifier =
  zPreAuthorizedCodeGrantIdentifier.value;
export type PreAuthorizedCodeGrantIdentifier = z.infer<
  typeof zPreAuthorizedCodeGrantIdentifier
>;
