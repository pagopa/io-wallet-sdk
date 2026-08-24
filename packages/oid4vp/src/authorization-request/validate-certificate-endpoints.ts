import { Oid4vpError } from "../errors";

export interface X509CertificateMetadata {
  sanDnsNames?: string[];
  sanUriNames?: string[];
}

export type GetX509CertificateMetadataCallback = (
  certificate: string,
) => Promise<X509CertificateMetadata> | X509CertificateMetadata;

export interface X509CertificateBinding {
  getX509CertificateMetadata: GetX509CertificateMetadataCallback;
}

export interface CertificateEndpoint {
  name: string;
  uri?: string;
}

export interface ValidateCertificateEndpointsOptions {
  callbacks: X509CertificateBinding;
  certificate: string;
  endpoints: CertificateEndpoint[];
}

export async function validateCertificateEndpoints(
  options: ValidateCertificateEndpointsOptions,
): Promise<void> {
  const metadata = await options.callbacks.getX509CertificateMetadata(
    options.certificate,
  );

  for (const endpoint of options.endpoints) {
    if (!endpoint.uri) {
      continue;
    }

    validateEndpointAgainstMetadata(
      { name: endpoint.name, uri: endpoint.uri },
      metadata,
    );
  }
}

function validateEndpointAgainstMetadata(
  endpoint: { name: string; uri: string },
  metadata: X509CertificateMetadata,
) {
  const endpointUrl = parseEndpointUrl(endpoint);
  const sanUriNames = metadata.sanUriNames ?? [];
  const matchesUriSan = sanUriNames.some(
    (sanUriName) => normalizeUriForComparison(sanUriName) === endpointUrl.href,
  );
  const sanDnsNames = metadata.sanDnsNames ?? [];
  const matchesDnsSan = sanDnsNames.some((sanDnsName) =>
    matchesDnsSanHostname(sanDnsName, endpointUrl.hostname),
  );

  if (matchesUriSan || matchesDnsSan) {
    return;
  }

  throw new Oid4vpError(
    `${endpoint.name} is not covered by the Relying Party certificate SAN entries`,
  );
}

function normalizeUriForComparison(uri: string) {
  try {
    return new URL(uri).href;
  } catch (error) {
    throw new Oid4vpError(`Certificate URI SAN is not a valid URL: ${uri}`, {
      cause: error,
    });
  }
}

function matchesDnsSanHostname(sanDnsName: string, hostname: string) {
  const normalizedSanDnsName = sanDnsName.toLowerCase();
  const normalizedHostname = hostname.toLowerCase();

  if (normalizedSanDnsName === normalizedHostname) {
    return true;
  }

  if (!normalizedSanDnsName.includes("*")) {
    return false;
  }

  const wildcardCount = [...normalizedSanDnsName].filter(
    (character) => character === "*",
  ).length;
  const sanLabels = normalizedSanDnsName.split(".");
  const hostnameLabels = normalizedHostname.split(".");

  return (
    wildcardCount === 1 &&
    sanLabels[0] === "*" &&
    sanLabels.length === hostnameLabels.length &&
    sanLabels
      .slice(1)
      .every((label, index) => label === hostnameLabels[index + 1])
  );
}

function parseEndpointUrl(endpoint: { name: string; uri: string }) {
  try {
    return new URL(endpoint.uri);
  } catch (error) {
    throw new Oid4vpError(
      `${endpoint.name} is not a valid URL: ${endpoint.uri}`,
      { cause: error },
    );
  }
}
