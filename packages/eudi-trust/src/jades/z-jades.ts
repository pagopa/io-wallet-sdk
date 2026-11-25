import { HashAlgorithm } from "@pagopa/io-wallet-utils";
import { z } from "zod";

const JADES_DIGEST_ALGORITHMS = {
  S256: HashAlgorithm.Sha256,
  S384: HashAlgorithm.Sha384,
  S512: HashAlgorithm.Sha512,
} as const;

/**
 * ETSI SPEC-DEVIATION
 *
 * ETSI TS 119 182-1 (JAdES) section 5.2.2.2 states that `digAlg` must be one
 * registered at the IANA "Named Information Hash Algorithm Registry".
 * @see https://www.iana.org/assignments/named-information/namedinformation.xhtml#hash-alg
 *
 * EUDIW Launchpad LoTEs use short names S256/S384/S512; here they are normalized
 * to the IANA hash names used by the hash callback.
 */
const zX5tODigestAlgorithm = z.union([
  z.enum(HashAlgorithm),
  z
    .enum(["S256", "S384", "S512"])
    .transform((alg) => JADES_DIGEST_ALGORITHMS[alg]),
]);

/**
 * Critical header parameters this SDK processes (ETSI TS 119 182-1 section 5.1.9).
 * Currently only `x5t#o` is supported; see `verifyJAdESSignature`.
 *
 * TODO: full JAdES header processing will be implemented later.
 */
const SUPPORTED_CRITICAL_PARAMETERS: readonly string[] = ["x5t#o"];

const zCrit = z
  .array(z.string())
  .min(1, "crit must not be empty")
  .superRefine((crit, ctx) => {
    for (const name of crit) {
      if (!SUPPORTED_CRITICAL_PARAMETERS.includes(name)) {
        ctx.addIssue({
          code: "custom",
          message: `Unsupported critical header parameter: ${name}`,
        });
      }
    }
  });

/**
 * Protected header of a compact JAdES Baseline B signature (ETSI TS 119 182-1),
 * with the signing certificate chain in `x5c`.
 *
 * The payload is always attached and base64url-encoded, so detached
 * signatures (`sigD`) and unencoded payloads (`b64`) are rejected; `iat`
 * replaces the legacy `sigT` signing time.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf
 */
export type JAdESHeader = z.infer<typeof zJAdESHeader>;
export const zJAdESHeader = z.object({
  alg: z
    .string()
    .refine(
      (alg) => alg !== "none" && !alg.startsWith("HS"),
      "alg must be an asymmetric signature algorithm",
    ),
  b64: z.never().optional(),
  crit: zCrit.optional(),
  cty: z.string().optional(),
  iat: z.number().int(),
  kid: z.string().optional(),
  sigD: z.never().optional(),
  sigT: z.never().optional(),
  typ: z.string(),
  x5c: z.tuple([z.string()], z.string()),
  "x5t#o": z
    .object({
      digAlg: zX5tODigestAlgorithm,
      digVal: z.string(),
    })
    .optional(),
});
