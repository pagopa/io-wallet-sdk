## @pagopa/io-wallet-oid-federation

This package provides a set of tools, schemas, and utilities to work with the **IT Wallet OpenID Federation** specification. It is designed to help developers create and validate artifacts such as Entity Configurations and Entity Statements in a compliant and secure manner.

## Installation

To install the package, use your preferred package manager:

```bash
# Using pnpm
pnpm add @pagopa/io-wallet-oid-federation

# Using yarn
yarn add @pagopa/io-wallet-oid-federation
```

## Core Concepts

OpenID Federation is a protocol that allows different entities (like Wallet Providers, Credential Issuers, and Verifiers) to establish trust with each other in a decentralized way. Instead of relying on a central authority, each entity publishes its own metadata in a self-signed JWT document called an Entity Configuration.

This package provides the necessary tools to:

- **Define Metadata**: Use pre-built Zod schemas to define the metadata for different entity types (wallet_provider, openid_credential_issuer, etc.).

- **Create Entity Configurations**: Generate a valid, signed JWT that represents your entity's configuration, which can then be published for other entities to discover and trust.

- **Validate Artifacts**: Ensure that incoming federation documents are correctly structured and compliant with the IT Wallet specification.

## Usage

### Creating an Entity Configuration

The primary function of this package is `createItWalletEntityConfiguration`. It takes your entity's claims and a signing callback to produce a signed JWT.

Here is an example of how to create an Entity Configuration for a Credential Issuer:

```javascript
import { createItWalletEntityConfiguration } from "@pagopa/io-wallet-oid-federation";
import { JWK, SignCallback } from "@openid-federation/core";

// Define your entity's base URL and JWKS repository
const baseURL = "https://issuer.example.it";
const jwksRepository = {
  /* your JWKS implementation */
};
const jwk = jwksRepository.get();

// Define a signing callback that uses your private key
const signJwtCallback: SignCallback = async ({ toBeSigned, jwk }) => {
  // Your signing logic here.
  ...
};

// Create the Entity Configuration JWT
const entityConfigurationJwt = await createItWalletEntityConfiguration({
  header: {
    alg: "ES256",
    kid: jwk.public.kid,
    typ: "entity-statement+jwt",
  },
  claims: {
    iss: baseURL,
    sub: baseURL,
    exp: Math.floor(Date.now() / 1000) + 3600, // Expires in 1 hour
    iat: Math.floor(Date.now() / 1000),
    jwks: {
      keys: [jwk.public],
    },
    authority_hints: [`${baseURL}/trust_anchor`],
    metadata: {
      federation_entity: {
        organization_name: "PagoPa S.p.A.",
        homepage_uri: "https://io.italia.it",
        policy_uri: "https://io.italia.it/privacy-policy",
        logo_uri: "https://io.italia.it/assets/img/io-it-logo-blue.svg",
        contacts: ["info@pagopa.it"],
        federation_resolve_endpoint: `${baseURL}/resolve`,
      },
      openid_credential_issuer: {
        // ... your issuer-specific metadata
      },
      oauth_authorization_server: {
        // ... your authorization server metadata
      },
    },
  },
  signJwtCallback,
});

console.log(entityConfigurationJwt);
// This JWT can now be served at `https://issuer.example.it/.well-known/openid-federation`
```

## API Reference

### Functions

`createItWalletEntityConfiguration(options)`: Creates and signs an Entity Configuration JWT.

### Zod Schemas

This package exports a comprehensive set of Zod schemas to validate all parts of the federation artifacts.

- JWK Schemas:
  - `JWK`: Validates a single JSON Web Key.

  - `JWKS`: Validates a JSON Web Key Set.

- Metadata Schemas:
  - `itWalletFederationEntityMetadata`: For `federation_entity` metadata.

  - `itWalletProviderEntityMetadata`: For `wallet_provider` metadata.

  - `itWalletCredentialIssuerMetadata`: For `openid_credential_issuer` metadata.

  - `itWalletCredentialVerifierMetadata`: For `openid_credential_verifier` metadata.

  - `itWalletAuthorizationServerMetadata`: For `oauth_authorization_server` metadata.

- Claims Schemas:
  - `itWalletEntityStatementClaimsSchema`: Validates the claims within an Entity Statement.

  - `itWalletEntityConfigurationClaimsSchema`: Validates the claims for an Entity Configuration (where iss must equal sub).
