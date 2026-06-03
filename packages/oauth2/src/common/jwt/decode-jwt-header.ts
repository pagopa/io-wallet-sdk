import {
  BaseSchema,
  decodeBase64,
  encodeToUtf8String,
  formatError,
  parseWithErrorHandling,
  stringToJsonWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import type { InferSchemaOrDefaultOutput } from "./decode-jwt";

import { Oauth2Error, Oauth2JwtParseError } from "../../errors";
import { JwtHeader, JwtPayload, JwtSigner, zJwtHeader } from "./z-jwt";

export interface DecodeJwtHeaderOptions<
  HeaderSchema extends BaseSchema | undefined,
> {
  /**
   * Optional prefix for error messages thrown during decoding, to provide more context on where the error occurred
   */
  errorMessagePrefix?: string;

  /**
   * Schema to use for validating the header. If not provided the
   * default `zJwtHeader` schema will be used
   */
  headerSchema?: HeaderSchema;

  /**
   * The compact encoded jwt
   */
  jwt: string;
}

export interface DecodeJwtHeaderResult<
  HeaderSchema extends BaseSchema | undefined = undefined,
> {
  header: InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>;
}

/**
 * Decodes and validates the header of a compact JWT.
 *
 * This helper does not verify the JWT signature or parse the payload.
 *
 * @param options - Header decode options.
 * @param options.errorMessagePrefix - Optional context prefix for thrown parse/validation errors.
 * @param options.headerSchema - Optional schema for the JWT header; defaults to `zJwtHeader`.
 * @param options.jwt - Compact JWT to decode.
 * @returns Decoded and schema-validated JWT header.
 * @throws {Oauth2JwtParseError} If the JWT shape or header JSON is invalid.
 * @throws {ValidationError} If header schema validation fails.
 */
export function decodeJwtHeader<
  HeaderSchema extends BaseSchema | undefined = undefined,
>(
  options: DecodeJwtHeaderOptions<HeaderSchema>,
): DecodeJwtHeaderResult<HeaderSchema> {
  const jwtParts = options.jwt.split(".");
  if (jwtParts.length <= 2) {
    throw new Oauth2JwtParseError(
      formatError(
        "Unable to decode because Jwt is not a valid!",
        options.errorMessagePrefix,
      ),
    );
  }

  const [headerPart] = jwtParts as [string, ...string[]];

  let headerJson: Record<string, unknown>;
  try {
    headerJson = stringToJsonWithErrorHandling(
      encodeToUtf8String(decodeBase64(headerPart)),
      formatError(
        "Unable to parse jwt header to JSON",
        options.errorMessagePrefix,
      ),
    );
  } catch (error) {
    throw new Oauth2JwtParseError(
      formatError(
        `Error parsing JWT. ${error instanceof Error ? error.message : ""}`,
        options.errorMessagePrefix,
      ),
    );
  }

  const header = parseWithErrorHandling(
    options.headerSchema ?? zJwtHeader,
    headerJson,
    formatError("Invalid JWT header", options.errorMessagePrefix),
  ) as InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>;

  return {
    header,
  };
}

/**
 * Builds a JWT header from an SDK signer descriptor.
 *
 * @param signer - Signer descriptor used by SDK signing callbacks.
 * @returns Header fields required by the signer method.
 */
export function jwtHeaderFromJwtSigner(signer: JwtSigner) {
  if (signer.method === "did") {
    return {
      alg: signer.alg,
      kid: signer.didUrl,
    };
  }

  if (signer.method === "federation") {
    return {
      alg: signer.alg,
      kid: signer.kid,
      trust_chain: signer.trustChain,
    };
  }

  if (signer.method === "jwk") {
    return {
      alg: signer.alg,
      jwk: signer.publicJwk,
    };
  }

  if (signer.method === "x5c") {
    return {
      alg: signer.alg,
      kid: signer.kid,
      trust_chain: signer.trustChain,
      x5c: signer.x5c,
    };
  }

  return { alg: signer.alg };
}

// eslint-disable-next-line complexity
export function jwtSignerFromJwt(options: {
  allowedSignerMethods?: JwtSigner["method"][];
  header: Pick<JwtHeader, "alg" | "jwk" | "kid" | "trust_chain" | "x5c">;
  payload: Pick<JwtPayload, "iss">;
}): JwtSigner {
  const { allowedSignerMethods, header, payload } = options;
  const found: (
    | {
        error: string;
        method: JwtSigner["method"];
        valid: false;
      }
    | {
        method: JwtSigner["method"];
        signer: JwtSigner;
        valid: true;
      }
  )[] = [];

  if (header.x5c) {
    found.push({
      method: "x5c",
      signer: {
        alg: header.alg,
        kid: header.kid,
        method: "x5c",
        trustChain: header.trust_chain,
        x5c: header.x5c,
      },
      valid: true,
    });
  }

  if (header.trust_chain) {
    if (!header.kid) {
      found.push({
        error:
          "When 'trust_chain' is used in jwt header, the 'kid' parameter is required.",
        method: "federation",
        valid: false,
      });
    } else {
      found.push({
        method: "federation",
        signer: {
          alg: header.alg,
          kid: header.kid,
          method: "federation",
          trustChain: header.trust_chain,
        },
        valid: true,
      });
    }
  }

  if (header.kid?.startsWith("did:") || payload.iss?.startsWith("did:")) {
    if (
      payload.iss &&
      header.kid?.startsWith("did:") &&
      !header.kid.startsWith(payload.iss)
    ) {
      found.push({
        error:
          "kid in header starts with did that is different from did value in 'iss'",
        method: "did",
        valid: false,
      });
    } else if (
      !header.kid?.startsWith("did:") &&
      !header.kid?.startsWith("#")
    ) {
      found.push({
        error:
          "kid in header must start with either 'did:' or '#' when 'iss' value is a did",
        method: "did",
        valid: false,
      });
    } else if (header.kid) {
      found.push({
        method: "did",
        signer: {
          alg: header.alg,
          didUrl: header.kid.startsWith("did:")
            ? header.kid
            : `${payload.iss}${header.kid}`,
          method: "did",
        },
        valid: true,
      });
    }
  }

  if (header.jwk) {
    found.push({
      method: "jwk",
      signer: {
        alg: header.alg,
        method: "jwk",
        publicJwk: header.jwk,
      },
      valid: true,
    });
  }

  const allowedFoundMethods = found.filter(
    (candidate) =>
      !allowedSignerMethods || allowedSignerMethods.includes(candidate.method),
  );
  const allowedValidMethods = allowedFoundMethods.filter(
    (candidate) => candidate.valid,
  );

  const firstAllowedValidMethod = allowedValidMethods[0];
  if (firstAllowedValidMethod && firstAllowedValidMethod.valid) {
    return firstAllowedValidMethod.signer;
  }

  if (allowedFoundMethods.length > 0) {
    throw new Oauth2Error(
      `Unable to extract signer method from jwt. Found ${allowedFoundMethods.length} allowed signer method(s) but contained invalid configuration:\n${allowedFoundMethods
        .map((candidate) =>
          candidate.valid
            ? ""
            : `FAILED: method ${candidate.method} - ${candidate.error}`,
        )
        .join("\n")}`,
    );
  }

  if (found.length > 0) {
    throw new Oauth2Error(
      `Unable to extract signer method from jwt. Found ${found.length} signer method(s) that are not allowed:\n${found
        .map((candidate) =>
          candidate.valid
            ? `SUCCEEDED: method ${candidate.method}`
            : `FAILED: method ${candidate.method} - ${candidate.error}`,
        )
        .join("\n")}`,
    );
  }

  if (!allowedSignerMethods || allowedSignerMethods.includes("custom")) {
    return {
      alg: header.alg,
      kid: header.kid,
      method: "custom",
    };
  }

  throw new Oauth2Error(
    "Unable to extract signer method from jwt. Found no signer methods and 'custom' signer method is not allowed.",
  );
}
