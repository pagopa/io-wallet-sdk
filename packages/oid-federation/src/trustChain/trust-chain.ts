import {
  CallbackContext,
  JwtSignerJwk,
  decodeJwt,
} from "@pagopa/io-wallet-oauth2";
import {
  Fetch,
  UnexpectedStatusCodeError,
  createFetcher,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { entityConfigurationHeaderSchema } from "../entityConfiguration";
import { itWalletEntityStatementClaimsSchema } from "../entityStatement/itWalletEntityStatementClaims";
import { TrustChainEvaluationError } from "../errors";
import { jsonWebKeySchema } from "../jwk/jwk";

interface ChainEntry {
  compact: string;
  header: z.output<typeof entityConfigurationHeaderSchema>;
  payload: z.output<typeof itWalletEntityStatementClaimsSchema>;
}

function decodeEntityStatement(jwt: string): ChainEntry {
  const { header, payload } = decodeJwt({
    headerSchema: entityConfigurationHeaderSchema,
    jwt,
    payloadSchema: itWalletEntityStatementClaimsSchema,
  });
  return { compact: jwt, header, payload };
}

async function fetchEntityConfigurationJwt(
  entityUrl: string,
  fetcher: Fetch,
): Promise<string> {
  const url = `${entityUrl}/.well-known/openid-federation`;
  const response = await fetcher(url, {
    headers: { Accept: "application/entity-statement+jwt" },
  });
  await hasStatusOrThrow(200, UnexpectedStatusCodeError)(response);
  return response.text();
}

function verifyJwtWithKeySet(
  jwt: Parameters<VerifyJwtCallback>[1],
  kid: string,
  keys: z.output<typeof jsonWebKeySchema>[],
  verifyJwt: VerifyJwtWithJwkCallback,
  ecKeys: undefined | z.output<typeof jsonWebKeySchema>[] = undefined,
): ReturnType<VerifyJwtWithJwkCallback> {
  const key = keys.find((k) => k.kid === kid);
  if (!key) {
    throw new TrustChainEvaluationError(
      `signing key with kid "${kid}" not found`,
    );
  }

  if (ecKeys) {
    if (!ecKeys.find((ecKey) => ecKey.kid === key.kid)) {
      throw new TrustChainEvaluationError(
        `signing key with kid "${kid}" not found in EC's declared keys`,
      );
    }
  }

  if (key.alg && key.alg !== jwt.header.alg) {
    throw new Error(
      `Error, signing key ${kid}'s alg doesn't match its signed jwt counterpart. Key alg: ${key.alg}, Jwt alg: ${jwt.header.alg}`,
    );
  }

  return verifyJwt(
    {
      alg: jwt.header.alg,
      method: "jwk",
      publicJwk: key,
    },
    jwt,
  );
}

type ECSequence = [ChainEntry, ...ChainEntry[]];

async function fetchECSequence(
  entityUrl: string,
  trustAnchorUrls: string[],
  fetcher: Fetch,
): Promise<ECSequence> {
  const jwt = await fetchEntityConfigurationJwt(entityUrl, fetcher);
  const entry = decodeEntityStatement(jwt);

  if (trustAnchorUrls.find((url) => url === entry.payload.iss)) {
    return [entry];
  }

  const authorityHints = entry.payload.authority_hints ?? [];
  if (!authorityHints.length) {
    throw new TrustChainEvaluationError(
      `entity config for "${entityUrl}" has no authority_hints`,
    );
  }

  const reachedAnchor = authorityHints.find((h) => trustAnchorUrls.includes(h));
  if (reachedAnchor) {
    const anchorJwt = await fetchEntityConfigurationJwt(reachedAnchor, fetcher);
    return [entry, decodeEntityStatement(anchorJwt)];
  }

  let lastError: unknown;
  for (const hint of authorityHints) {
    try {
      const restChain = await fetchECSequence(hint, trustAnchorUrls, fetcher);
      return [entry, ...restChain];
    } catch (error) {
      // Store the last error to provide better diagnostics if no path is found
      lastError = error;
      continue;
    }
  }
  const lastErrorMessage =
    lastError instanceof Error
      ? lastError.message
      : lastError !== undefined
        ? String(lastError)
        : "unknown error";
  throw new TrustChainEvaluationError(
    `no path to a trusted anchor found from "${entityUrl}" (last error: ${lastErrorMessage})`,
  );
}

async function buildTrustChain(
  ecs: ECSequence,
  fetcher: Fetch,
  verifyJwtCb: VerifyJwtWithJwkCallback,
): Promise<ECSequence> {
  for (const ec of ecs) {
    if (ec.payload.iss !== ec.payload.sub) {
      throw new TrustChainEvaluationError(
        `entity configuration iss "${ec.payload.iss}" does not match sub "${ec.payload.sub}"`,
      );
    }
    const verificationResult = await verifyJwtWithKeySet(
      ec,
      ec.header.kid,
      ec.payload.jwks.keys,
      verifyJwtCb,
    );

    if (!verificationResult.verified) {
      throw new TrustChainEvaluationError(
        `Jwt verification failed for entity configuration ${ec.payload.iss}`,
      );
    }
  }

  checkExpiry(ecs);

  // If there's only a single EC, return it directly
  if (ecs.length === 1) return ecs;

  const subStmtEntries: (ChainEntry | undefined)[] = await Promise.all(
    ecs.map(async (entry, idx) => {
      if (idx === ecs.length - 1) return undefined;

      const superior = ecs[idx + 1];
      if (!superior) return undefined;

      const fetchEndpoint =
        superior.payload.metadata?.federation_entity?.federation_fetch_endpoint;
      if (!fetchEndpoint) {
        throw new TrustChainEvaluationError(
          `superior entity at index ${idx + 1} has no federation_fetch_endpoint`,
        );
      }

      const fetchUrl = `${fetchEndpoint}?sub=${encodeURIComponent(entry.payload.sub)}`;
      const response = await fetcher(fetchUrl, {
        headers: { Accept: "application/entity-statement+jwt" },
      });
      await hasStatusOrThrow(200, UnexpectedStatusCodeError)(response);

      const subJwt = await response.text();
      const subEntry = decodeEntityStatement(subJwt);

      return subEntry;
    }),
  );

  const subStmts = subStmtEntries.filter(
    (e): e is ChainEntry => e !== undefined,
  );
  const lastEc = ecs[ecs.length - 1];
  if (!lastEc) {
    throw new TrustChainEvaluationError(
      "trust chain sequence has no last element",
    );
  }
  const chain: ECSequence = [ecs[0], ...subStmts, lastEc];

  for (let i = 0; i < chain.length - 1; i++) {
    const statement = chain[i];
    const superior = chain[i + 1];
    const statementEc = ecs[i];
    if (!statement || !superior || !statementEc) {
      throw new TrustChainEvaluationError(
        `invalid chain element at position ${i}`,
      );
    }

    // §3.2 point 6: the issuer of the subordinate statement must be listed
    // in the subject entity's authority_hints.
    const hints = statementEc.payload.authority_hints ?? [];
    if (hints.length > 0 && !hints.includes(superior.payload.iss)) {
      throw new TrustChainEvaluationError(
        `"${superior.payload.iss}" is not listed in authority_hints of "${statementEc.payload.sub}"`,
      );
    }

    const { verified } = await verifyJwtWithKeySet(
      statement,
      statement.header.kid,
      superior.payload.jwks.keys,
      verifyJwtCb,
      statementEc.payload.jwks.keys,
    );

    if (!verified) {
      const elementType = i === 0 ? "leaf EC" : "subordinate statement";
      throw new TrustChainEvaluationError(
        `Error verifying signature for ${elementType} at position ${i} (iss="${statement.payload.iss}", sub="${statement.payload.sub}")`,
      );
    }
  }

  return chain;
}

// Allowed clock skew in seconds for iat/exp checks (§3.2 points 7–8).
const CLOCK_SKEW_SECONDS = 30;

function checkExpiry(chain: ChainEntry[]): void {
  const now = Math.floor(Date.now() / 1000);
  for (let i = 0; i < chain.length; i++) {
    const entry = chain[i];
    if (!entry) {
      throw new TrustChainEvaluationError(
        `trust chain element at position ${i} is undefined`,
      );
    }
    if ((entry.payload.exp ?? 0) < now - CLOCK_SKEW_SECONDS) {
      throw new TrustChainEvaluationError(
        `trust chain element at position ${i} has expired`,
      );
    }
    if (entry.payload.iat > now + CLOCK_SKEW_SECONDS) {
      throw new TrustChainEvaluationError(
        `trust chain element at position ${i} has iat in the future`,
      );
    }
  }
}

function checkStructure(chain: ChainEntry[], trustAnchorUrls?: string[]): void {
  const firstEntry = chain[0];
  const lastEntry = chain[chain.length - 1];

  if (firstEntry && firstEntry.payload.iss !== firstEntry.payload.sub) {
    throw new TrustChainEvaluationError(
      `leaf EC iss "${firstEntry.payload.iss}" does not match sub "${firstEntry.payload.sub}"`,
    );
  }
  if (
    lastEntry &&
    lastEntry !== firstEntry &&
    lastEntry.payload.iss !== lastEntry.payload.sub
  ) {
    throw new TrustChainEvaluationError(
      `trust anchor EC iss "${lastEntry.payload.iss}" does not match sub "${lastEntry.payload.sub}"`,
    );
  }

  if (chain.length > 1) {
    if (!firstEntry || !chain[1]) {
      throw new TrustChainEvaluationError("trust chain is malformed");
    }
    if (firstEntry.payload.sub !== chain[1].payload.sub) {
      throw new TrustChainEvaluationError(
        "leaf EC subject does not match first subordinate statement subject",
      );
    }
    for (let j = 1; j < chain.length - 1; j++) {
      const current = chain[j];
      const next = chain[j + 1];
      if (!current || !next) {
        throw new TrustChainEvaluationError(
          `trust chain element at position ${j} is undefined`,
        );
      }
      if (current.payload.iss !== next.payload.sub) {
        throw new TrustChainEvaluationError(
          `trust chain link broken at position ${j}`,
        );
      }
    }
  }

  if (trustAnchorUrls?.length) {
    if (!lastEntry)
      throw new TrustChainEvaluationError("Trust chain root is not defined");
    if (!trustAnchorUrls.includes(lastEntry.payload.iss)) {
      throw new TrustChainEvaluationError(
        `trust chain root "${lastEntry.payload.iss}" is not a trusted anchor`,
      );
    }
  }
}

type VerifyJwtCallback = CallbackContext["verifyJwt"];

/**
 * A simplified JWT verification callback that accepts a concrete JWK.
 *
 * Using a plain JWK instead of the full `JwtSigner` union avoids a circular
 * dependency when trust-chain verification is itself invoked from inside a
 * `verifyJwt` callback (e.g. when resolving a federation trust chain to
 * obtain the signer's public key).
 */
export type VerifyJwtWithJwkCallback = (
  jwtSigner: JwtSignerJwk,
  jwt: Parameters<VerifyJwtCallback>[1],
) => ReturnType<VerifyJwtCallback>;

export interface ValidateTrustChainOptions {
  callbacks: {
    /**
     * Optional. When provided, each intermediate issuer's entity configuration
     * is fetched and its self-signature verified as an additional integrity
     * check. Subordinate statement signatures are verified against the chain
     * superiors in both cases.
     */
    fetch: CallbackContext["fetch"];
    /**
     * Required for verifying entity statement signatures.
     */
    verifyJwt: VerifyJwtWithJwkCallback;
  };
  /**
   * Optional set of trusted trust anchor URLs. When provided, the chain root
   * must be one of them.
   */
  trustAnchorUrls?: string[];
}

/**
 * Cryptographically validates a pre-built (inline) trust chain.
 *
 * Verifies every element's signature, checks `exp`, enforces structural
 * `iss`/`sub` consistency, and optionally binds the root to a known trust
 * anchor.
 *
 * The first element must be the leaf EC (self-signed). The last element must
 * be the trust anchor EC (self-signed). Intermediate elements are subordinate
 * statements; all but the last require `callbacks.fetch` to resolve the
 * intermediate issuer's EC for signature verification.
 *
 * @param trustChain Array of compact JWTs forming the chain.
 * @param options Validation options including callbacks and trusted anchors.
 * @throws If any signature is invalid, any element is expired, structural
 *   links are broken, or the root is not a trusted anchor.
 */
export async function validateTrustChain(
  trustChain: string[],
  options: ValidateTrustChainOptions,
): Promise<void> {
  if (!trustChain[0]) throw new TrustChainEvaluationError("empty trust chain");

  const chain = trustChain.map(decodeEntityStatement);

  checkExpiry(chain);

  const leafEntry = chain[0];
  if (!leafEntry)
    throw new TrustChainEvaluationError("Leaf certificate is not defined");
  const anchorEntry = chain[chain.length - 1];
  if (!anchorEntry)
    throw new TrustChainEvaluationError(
      "Trust anchor certificate is not defined",
    );

  const { verified: isLeafVerificationSuccessful } = await verifyJwtWithKeySet(
    leafEntry,
    leafEntry.header.kid,
    leafEntry.payload.jwks.keys,
    options.callbacks.verifyJwt,
  );
  if (!isLeafVerificationSuccessful) {
    throw new TrustChainEvaluationError("Error verifying leaf EC");
  }

  const { verified: isTAVerificationSuccessful } = await verifyJwtWithKeySet(
    anchorEntry,
    anchorEntry.header.kid,
    anchorEntry.payload.jwks.keys,
    options.callbacks.verifyJwt,
  );
  if (!isTAVerificationSuccessful) {
    throw new TrustChainEvaluationError("Error verifying Trust Anchor EC");
  }

  checkStructure(chain, options.trustAnchorUrls);

  const fetcher = createFetcher(options.callbacks.fetch);

  // Tracks the subject entity's EC so we can check authority_hints (§3.2 point 6).
  // Starts as the leaf EC; updated to the fetched intermediate EC on each iteration.
  let subjectEcForCheck: ChainEntry = leafEntry;

  for (let i = 0; i < trustChain.length - 1; i++) {
    const subEntry = chain[i];
    const chainSuperior = chain[i + 1];
    if (!subEntry)
      throw new TrustChainEvaluationError(
        `Subordinate statement at step ${i} is not defined`,
      );
    if (!chainSuperior)
      throw new TrustChainEvaluationError(
        `Subordinate statement at step ${i + 1} is not defined`,
      );

    // §3.2 point 6: the issuer of the subordinate statement must be listed
    // in the subject entity's authority_hints.
    if (subjectEcForCheck) {
      const hints = subjectEcForCheck.payload.authority_hints ?? [];
      if (hints.length > 0 && !hints.includes(chainSuperior.payload.iss)) {
        throw new TrustChainEvaluationError(
          `"${chainSuperior.payload.iss}" is not listed in authority_hints of "${subEntry.payload.sub}"`,
        );
      }
    }

    const issuerKeys: z.output<typeof jsonWebKeySchema>[] =
      chainSuperior.payload.jwks.keys;

    const { verified } = await verifyJwtWithKeySet(
      subEntry,
      subEntry.header.kid,
      issuerKeys,
      options.callbacks.verifyJwt,
      subjectEcForCheck.payload.jwks.keys,
    );

    if (!verified) {
      throw new TrustChainEvaluationError(
        `Verification of subordinate statement at step ${i} failed`,
      );
    }

    if (i === trustChain.length - 2) {
      subjectEcForCheck = chainSuperior;
    } else if (i === trustChain.length - 3) {
      const ta = chain[i + 2];
      if (!ta) {
        throw new TrustChainEvaluationError(
          "Error retrieving trust anchor certificate from chain",
        );
      }
      subjectEcForCheck = ta;
    } else {
      const issuerEcJwt = await fetchEntityConfigurationJwt(
        chainSuperior.payload.iss,
        fetcher,
      );
      const issuerEc = decodeEntityStatement(issuerEcJwt);
      const { verified: issuerEcVerified } = await verifyJwtWithKeySet(
        issuerEc,
        issuerEc.header.kid,
        issuerEc.payload.jwks.keys,
        options.callbacks.verifyJwt,
      );
      if (!issuerEcVerified) {
        throw new TrustChainEvaluationError(
          `Error verifying self-signature of intermediate issuer EC for "${subEntry.payload.iss}"`,
        );
      }
      checkExpiry([issuerEc]);
      // The issuer EC is the subject for the next subordinate statement.
      subjectEcForCheck = issuerEc;
    }
  }
}

export interface FetchAndValidateTrustChainOptions {
  callbacks: {
    verifyJwt: VerifyJwtWithJwkCallback;
  } & Pick<CallbackContext, "fetch">;
  /**
   * Set of trusted trust anchor URLs. The resolved chain root must be one of
   * them.
   */
  trustAnchorUrls: string[];
}

/**
 * Fetches and validates a trust chain starting from a leaf entity.
 *
 * Traverses `authority_hints` upward from the leaf entity until a known
 * trust anchor is reached, fetches every entity configuration along the
 * path and the corresponding subordinate statements, verifies all
 * signatures, and returns the assembled chain as an array of compact JWTs.
 *
 * @param entityUrl URL of the leaf entity.
 * @param options Options including fetch/verifyJwt callbacks and trusted anchors.
 * @returns Ordered array of compact JWTs forming the validated trust chain.
 * @throws If the chain cannot be built, any element is expired or invalid, or
 *   the root is not a trusted anchor.
 */
export async function fetchAndValidateTrustChain(
  entityUrl: string,
  options: FetchAndValidateTrustChainOptions,
): Promise<string[]> {
  const fetcher = createFetcher(options.callbacks.fetch);

  const ecs = await fetchECSequence(
    entityUrl,
    options.trustAnchorUrls,
    fetcher,
  );
  const chain = await buildTrustChain(
    ecs,
    fetcher,
    options.callbacks.verifyJwt,
  );

  checkExpiry(chain);
  checkStructure(chain, options.trustAnchorUrls);

  return chain.map((e) => e.compact);
}
