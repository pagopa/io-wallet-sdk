import {
  HashAlgorithm,
  type HashCallback,
  decodeBase64,
  encodeToBase64Url,
} from "@pagopa/io-wallet-utils";

import { Oid4vpError, ParseAuthorizeRequestError } from "../errors";
import {
  Openid4vpAuthorizationRequestHeaderV1_3,
  Openid4vpAuthorizationRequestPayload,
} from "./z-authorization-request";

export enum ClientIdPrefix {
  NONE = "none",
  OPENID_FEDERATION = "openid_federation",
  X509_HASH = "x509_hash",
}

export interface ClientIdParts {
  clientId: string;
  prefix: ClientIdPrefix;
}

export interface CreateX509HashClientIdOptions {
  certificateChain: string[];
  hash: HashCallback;
}

export function extractClientIdPrefix(clientId: string): ClientIdParts {
  const colonIndex = clientId.indexOf(":");

  if (colonIndex === -1) {
    return { clientId, prefix: ClientIdPrefix.NONE };
  }

  if (clientId.startsWith("https://") || clientId.startsWith("http://")) {
    return { clientId, prefix: ClientIdPrefix.NONE };
  }

  const rawPrefix = clientId.slice(0, colonIndex);
  const rest = clientId.slice(colonIndex + 1);

  if (rawPrefix === ClientIdPrefix.X509_HASH) {
    return { clientId: rest, prefix: ClientIdPrefix.X509_HASH };
  }
  if (rawPrefix === ClientIdPrefix.OPENID_FEDERATION) {
    return { clientId: rest, prefix: ClientIdPrefix.OPENID_FEDERATION };
  }

  throw new Oid4vpError(
    `Unsupported client_id prefix "${rawPrefix}": only "openid_federation" and "x509_hash" are allowed by the IT-Wallet profile`,
  );
}

export async function createX509HashClientId(
  options: CreateX509HashClientIdOptions,
): Promise<string> {
  return `${ClientIdPrefix.X509_HASH}:${await calculateX509CertificateHash(options)}`;
}

async function calculateX509CertificateHash(
  options: CreateX509HashClientIdOptions,
) {
  const leafCertificate = getLeafCertificate(options.certificateChain);

  return encodeToBase64Url(
    await options.hash(decodeBase64(leafCertificate), HashAlgorithm.Sha256),
  );
}

export async function validateAuthorizationRequestClientBinding(options: {
  hash?: HashCallback;
  header: Openid4vpAuthorizationRequestHeaderV1_3;
  payload: Openid4vpAuthorizationRequestPayload;
}): Promise<ClientIdParts> {
  const clientIdParts = extractClientIdPrefix(options.payload.client_id);

  if (clientIdParts.prefix !== ClientIdPrefix.X509_HASH) {
    return clientIdParts;
  }

  const { x5c } = options.header;
  if (!Array.isArray(x5c) || x5c.length === 0) {
    throw new ParseAuthorizeRequestError(
      "x5c is required in JWT header for x509_hash client_id",
    );
  }

  if (!options.hash) {
    return clientIdParts;
  }

  const expectedCertificateHash = await calculateX509CertificateHash({
    certificateChain: x5c,
    hash: options.hash,
  });

  if (expectedCertificateHash !== clientIdParts.clientId) {
    throw new ParseAuthorizeRequestError(
      "x509_hash client_id does not match the JWT header leaf certificate",
    );
  }

  return clientIdParts;
}

function getLeafCertificate(certificateChain: string[]) {
  const leafCertificate = certificateChain[0];

  if (!leafCertificate) {
    throw new ParseAuthorizeRequestError(
      "Certificate chain is empty, cannot validate x509_hash",
    );
  }

  return leafCertificate;
}
