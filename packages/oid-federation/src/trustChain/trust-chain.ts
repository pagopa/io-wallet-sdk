import {
  CallbackContext,
  Fetch,
  HashAlgorithm,
  HashCallback,
  JwtSignerJwk,
  UnexpectedStatusCodeError,
  calculateJwkThumbprint,
  createFetcher,
  decodeJwt,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { entityConfigurationHeaderSchema } from "../entityConfiguration/z-entity-configuration-header";
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

function withHttpsEnforcement(fetcher: Fetch): Fetch {
  return (input, init) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    if (!url.startsWith("https://")) {
      throw new TrustChainEvaluationError(
        `federation requests must use HTTPS, got "${url}"`,
      );
    }
    return fetcher(input, init);
  };
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

interface VerifyCallbacks {
  hash: HashCallback;
  verifyJwt: VerifyJwtWithJwkCallback;
}

async function verifyJwtWithKeySet(
  jwt: Parameters<VerifyJwtCallback>[1],
  kid: string,
  keys: z.output<typeof jsonWebKeySchema>[],
  ecKeys: undefined | z.output<typeof jsonWebKeySchema>[],
  callbacks: VerifyCallbacks,
): Promise<Awaited<ReturnType<VerifyJwtWithJwkCallback>>> {
  const key = keys.find((k) => k.kid === kid);
  if (!key) {
    throw new TrustChainEvaluationError(
      `signing key with kid "${kid}" not found`,
    );
  }

  if (ecKeys) {
    const ecKey = ecKeys.find((k) => k.kid === key.kid);
    if (!ecKey) {
      throw new TrustChainEvaluationError(
        `signing key with kid "${kid}" not found in EC's declared keys`,
      );
    }
    const [subThumbprint, ecThumbprint] = await Promise.all([
      calculateJwkThumbprint({
        hashAlgorithm: HashAlgorithm.Sha256,
        hashCallback: callbacks.hash,
        jwk: key as Parameters<typeof calculateJwkThumbprint>[0]["jwk"],
      }),
      calculateJwkThumbprint({
        hashAlgorithm: HashAlgorithm.Sha256,
        hashCallback: callbacks.hash,
        jwk: ecKey as Parameters<typeof calculateJwkThumbprint>[0]["jwk"],
      }),
    ]);
    if (subThumbprint !== ecThumbprint) {
      throw new TrustChainEvaluationError(
        `signing key with kid "${kid}" has mismatched key material between subordinate statement and entity configuration`,
      );
    }
  }

  if (key.alg && key.alg !== jwt.header.alg) {
    throw new TrustChainEvaluationError(
      `signing key ${kid}'s alg doesn't match its signed jwt counterpart. Key alg: ${key.alg}, Jwt alg: ${jwt.header.alg}`,
    );
  }

  return callbacks.verifyJwt(
    {
      alg: jwt.header.alg,
      method: "jwk",
      publicJwk: key,
    },
    jwt,
  );
}

type ECSequence = [ChainEntry, ...ChainEntry[]];

const MAX_FEDERATION_DEPTH = 200;

async function fetchECSequence(
  entityUrl: string,
  trustAnchorUrls: [string, ...string[]] | undefined,
  fetcher: Fetch,
  visited = new Set<string>(),
  depth = 0,
): Promise<ECSequence> {
  if (visited.has(entityUrl)) {
    throw new TrustChainEvaluationError(
      `cycle detected: "${entityUrl}" was already visited`,
    );
  }
  if (depth >= MAX_FEDERATION_DEPTH) {
    throw new TrustChainEvaluationError(
      `maximum federation depth of ${MAX_FEDERATION_DEPTH} reached at "${entityUrl}"`,
    );
  }

  visited.add(entityUrl);

  const jwt = await fetchEntityConfigurationJwt(entityUrl, fetcher);
  const entry = decodeEntityStatement(jwt);

  if (trustAnchorUrls?.find((url) => url === entry.payload.iss)) {
    return [entry];
  }

  const authorityHints = entry.payload.authority_hints ?? [];
  if (!authorityHints.length) {
    throw new TrustChainEvaluationError(
      `entity config for "${entityUrl}" has no authority_hints`,
    );
  }

  const reachedAnchor = authorityHints.find((h) =>
    trustAnchorUrls?.includes(h),
  );
  if (reachedAnchor) {
    const anchorJwt = await fetchEntityConfigurationJwt(reachedAnchor, fetcher);
    return [entry, decodeEntityStatement(anchorJwt)];
  }

  let lastError: unknown;
  for (const hint of authorityHints) {
    try {
      const restChain = await fetchECSequence(
        hint,
        trustAnchorUrls,
        fetcher,
        visited,
        depth + 1,
      );
      return [entry, ...restChain];
    } catch (error) {
      lastError = error;
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

async function verifyChainLinks(
  chain: ECSequence,
  ecs: ECSequence,
  callbacks: VerifyCallbacks,
): Promise<void> {
  const linkVerifications = await Promise.all(
    Array.from({ length: chain.length - 1 }, (_, i) => {
      const statement = chain[i];
      const superior = chain[i + 1];
      const statementEc = ecs[i];
      if (!statement || !superior || !statementEc) {
        throw new TrustChainEvaluationError(
          `invalid chain element at position ${i}`,
        );
      }
      return verifyJwtWithKeySet(
        statement,
        statement.header.kid,
        superior.payload.jwks.keys,
        statementEc.payload.jwks.keys,
        callbacks,
      );
    }),
  );

  for (const [i, { verified }] of linkVerifications.entries()) {
    if (!verified) {
      const statement = chain[i];
      if (!statement) {
        throw new TrustChainEvaluationError(
          `invalid chain element at position ${i}`,
        );
      }
      const elementType = i === 0 ? "leaf EC" : "subordinate statement";
      throw new TrustChainEvaluationError(
        `Error verifying signature for ${elementType} at position ${i} (iss="${statement.payload.iss}", sub="${statement.payload.sub}")`,
      );
    }
  }
}

async function buildTrustChain(
  ecs: ECSequence,
  fetcher: Fetch,
  callbacks: VerifyCallbacks,
): Promise<ECSequence> {
  for (const ec of ecs) {
    if (ec.payload.iss !== ec.payload.sub) {
      throw new TrustChainEvaluationError(
        `entity configuration iss "${ec.payload.iss}" does not match sub "${ec.payload.sub}"`,
      );
    }
  }

  if (ecs.length === 1) {
    const leaf = ecs[0];
    const { verified } = await verifyJwtWithKeySet(
      leaf,
      leaf.header.kid,
      leaf.payload.jwks.keys,
      undefined,
      callbacks,
    );
    if (!verified) {
      throw new TrustChainEvaluationError(
        `Jwt verification failed for entity configuration ${leaf.payload.iss}`,
      );
    }
    checkExpiry(ecs);
    return ecs;
  }

  const ecVerifications = await Promise.all(
    ecs
      .slice(1)
      .map((ec) =>
        verifyJwtWithKeySet(
          ec,
          ec.header.kid,
          ec.payload.jwks.keys,
          undefined,
          callbacks,
        ),
      ),
  );

  for (const [i, { verified }] of ecVerifications.entries()) {
    if (!verified) {
      const ec = ecs[i + 1];
      throw new TrustChainEvaluationError(
        `Jwt verification failed for entity configuration ${ec?.payload.iss ?? i + 1}`,
      );
    }
  }

  checkExpiry(ecs);

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
  }

  checkMaxPathLength(chain);

  await verifyChainLinks(chain, ecs, callbacks);

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

function checkMaxPathLength(chain: ChainEntry[]): void {
  for (let i = 1; i < chain.length - 1; i++) {
    const subStmt = chain[i];
    const maxPath = subStmt?.payload.constraints?.max_path_length;
    if (maxPath !== undefined) {
      const remainingIntermediates = chain.length - 2 - i;
      if (remainingIntermediates > maxPath) {
        throw new TrustChainEvaluationError(
          `chain exceeds max_path_length constraint at position ${i}: allowed ${maxPath} more intermediates, found ${remainingIntermediates}`,
        );
      }
    }
  }
}

function checkStructure(
  chain: ChainEntry[],
  trustAnchorUrls?: [string, ...string[]],
): void {
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

  // WARNING: when trustAnchorUrls is not provided, any chain root is accepted
  // without binding to a known trust anchor. Callers that omit this parameter
  // must apply their own root-of-trust verification.
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
     * Required for chains with intermediate entities (chains longer than two
     * elements). Used to fetch each intermediate issuer's entity configuration
     * for self-signature verification.
     */
    fetch: CallbackContext["fetch"];
    /**
     * Required for hashing operations, used to compute JWK thumbprints when
     * comparing key material across subordinate statements and entity
     * configurations.
     */
    hash: HashCallback;
    /**
     * Required for verifying entity statement signatures.
     */
    verifyJwt: VerifyJwtWithJwkCallback;
  };
  /**
   * Non-empty list of trusted trust anchor URLs. When provided, the chain root
   * must be one of them. When omitted, any chain root is accepted without
   * binding to a known trust anchor — callers are responsible for applying
   * their own root-of-trust verification in that case.
   */
  trustAnchorUrls?: [string, ...string[]];
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
 *
 * @warning When `options.trustAnchorUrls` is omitted, the chain root is
 *   accepted unconditionally. Callers are responsible for applying their own
 *   root-of-trust verification in that case.
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

  const verifyCallbacks: VerifyCallbacks = {
    hash: options.callbacks.hash,
    verifyJwt: options.callbacks.verifyJwt,
  };

  const fetcher = withHttpsEnforcement(createFetcher(options.callbacks.fetch));

  const subjectEcs: ChainEntry[] = new Array(chain.length - 1);
  subjectEcs[0] = leafEntry;
  if (chain.length >= 3) {
    subjectEcs[chain.length - 2] = anchorEntry;
  }

  const intermediateIndices = Array.from(
    { length: Math.max(0, chain.length - 3) },
    (_, k) => k + 1,
  );

  const fetchedEcs = await Promise.all(
    intermediateIndices.map(async (k) => {
      const superior = chain[k];
      if (!superior) {
        throw new TrustChainEvaluationError(
          `invalid chain element at position ${k}`,
        );
      }
      const jwt = await fetchEntityConfigurationJwt(
        superior.payload.iss,
        fetcher,
      );
      const ec = decodeEntityStatement(jwt);
      const { verified } = await verifyJwtWithKeySet(
        ec,
        ec.header.kid,
        ec.payload.jwks.keys,
        undefined,
        verifyCallbacks,
      );
      if (!verified) {
        throw new TrustChainEvaluationError(
          `Error verifying self-signature of intermediate issuer EC for "${superior.payload.iss}"`,
        );
      }
      checkExpiry([ec]);
      return { ec, k };
    }),
  );

  for (const { ec, k } of fetchedEcs) {
    subjectEcs[k] = ec;
  }

  // §3.2 point 6: the issuer of the subordinate statement must be listed
  // in the subject entity's authority_hints.
  for (let i = 0; i < trustChain.length - 1; i++) {
    const subEntry = chain[i];
    const chainSuperior = chain[i + 1];
    const subjectEc = subjectEcs[i];
    if (!subEntry || !chainSuperior || !subjectEc) {
      throw new TrustChainEvaluationError(
        `invalid chain element at position ${i}`,
      );
    }
    const hints = subjectEc.payload.authority_hints ?? [];
    if (hints.length > 0 && !hints.includes(chainSuperior.payload.iss)) {
      throw new TrustChainEvaluationError(
        `"${chainSuperior.payload.iss}" is not listed in authority_hints of "${subEntry.payload.sub}"`,
      );
    }
  }

  const verificationCount = trustChain.length - 1;
  const allVerifications = await Promise.all([
    ...Array.from({ length: verificationCount }, (_, i) => {
      const subEntry = chain[i];
      const chainSuperior = chain[i + 1];
      const subjectEc = subjectEcs[i];
      if (!subEntry || !chainSuperior || !subjectEc) {
        throw new TrustChainEvaluationError(
          `invalid chain element at position ${i}`,
        );
      }
      return verifyJwtWithKeySet(
        subEntry,
        subEntry.header.kid,
        chainSuperior.payload.jwks.keys,
        subjectEc.payload.jwks.keys,
        verifyCallbacks,
      );
    }),
    verifyJwtWithKeySet(
      anchorEntry,
      anchorEntry.header.kid,
      anchorEntry.payload.jwks.keys,
      undefined,
      verifyCallbacks,
    ),
  ]);

  for (let i = 0; i < verificationCount; i++) {
    const result = allVerifications[i];
    if (!result?.verified) {
      throw new TrustChainEvaluationError(
        `Verification of subordinate statement at step ${i} failed`,
      );
    }
  }

  const anchorVerification = allVerifications[verificationCount];
  if (!anchorVerification?.verified) {
    throw new TrustChainEvaluationError("Error verifying Trust Anchor EC");
  }

  checkMaxPathLength(chain);

  checkStructure(chain, options.trustAnchorUrls);
}

export interface FetchAndValidateTrustChainOptions {
  callbacks: {
    /**
     * Required for hashing operations, used to compute JWK thumbprints when
     * comparing key material across subordinate statements and entity
     * configurations.
     */
    hash: HashCallback;
    verifyJwt: VerifyJwtWithJwkCallback;
  } & Pick<CallbackContext, "fetch">;
  /**
   * Non-empty list of trusted trust anchor URLs. When provided, traversal
   * stops as soon as one of these URLs is reached and the resolved chain root
   * is verified against the list. When omitted, traversal follows
   * `authority_hints` until no further hints exist (or a cycle / depth limit
   * is hit), and any chain root is accepted — callers are responsible for
   * applying their own root-of-trust verification in that case.
   */
  trustAnchorUrls?: [string, ...string[]];
}

/**
 * Fetches and validates a trust chain starting from a leaf entity.
 *
 * Traverses `authority_hints` upward from the leaf entity until a known
 * trust anchor is reached (or until no further hints exist), fetches every
 * entity configuration along the path and the corresponding subordinate
 * statements, verifies all signatures, and returns the assembled chain as an
 * array of compact JWTs.
 *
 * @param entityUrl URL of the leaf entity.
 * @param options Options including fetch/verifyJwt callbacks and trusted anchors.
 * @returns Ordered array of compact JWTs forming the validated trust chain.
 * @throws If the chain cannot be built, any element is expired or invalid, or
 *   the root is not a trusted anchor.
 *
 * @warning When `options.trustAnchorUrls` is omitted, the chain root is
 *   accepted unconditionally. Callers are responsible for applying their own
 *   root-of-trust verification in that case.
 */
export async function fetchAndValidateTrustChain(
  entityUrl: string,
  options: FetchAndValidateTrustChainOptions,
): Promise<string[]> {
  const fetcher = withHttpsEnforcement(createFetcher(options.callbacks.fetch));

  const ecs = await fetchECSequence(
    entityUrl,
    options.trustAnchorUrls,
    fetcher,
  );
  const chain = await buildTrustChain(ecs, fetcher, {
    hash: options.callbacks.hash,
    verifyJwt: options.callbacks.verifyJwt,
  });

  checkExpiry(chain);
  checkStructure(chain, options.trustAnchorUrls);

  return chain.map((e) => e.compact);
}
