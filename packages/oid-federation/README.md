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
import {
  createItWalletEntityConfiguration,
  SignCallback,
} from "@pagopa/io-wallet-oid-federation";

// Define your entity's base URL and public JWK
const baseURL = "https://issuer.example.it";
const publicJwk = {
  kty: "EC",
  crv: "P-256",
  x: "...",
  y: "...",
  kid: "key-1",
};

// Define a signing callback that uses your private key
const signJwtCallback: SignCallback = async ({ toBeSigned, jwk }) => {
  // Your signing logic here using the jwk parameter
  // Return the signature as Uint8Array
  // ...
};

// Create the Entity Configuration JWT
const entityConfigurationJwt = await createItWalletEntityConfiguration({
  header: {
    alg: "ES256",
    kid: publicJwk.kid,
    typ: "entity-statement+jwt",
  },
  claims: {
    iss: baseURL,
    sub: baseURL,
    exp: Math.floor(Date.now() / 1000) + 3600, // Expires in 1 hour
    iat: Math.floor(Date.now() / 1000),
    jwks: {
      keys: [publicJwk],
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

## Versioned Entity Metadata Layout

Entity metadata schemas are organised by specification version under `src/metadata/entity/`:

```
metadata/entity/
├── v1.0/                              # Spec v1.0 schemas
│   ├── ItWalletProvider.ts            # wallet_provider
│   ├── itWalletAuthorizationServer.ts # oauth_authorization_server
│   ├── itWalletCredentialIssuer.ts    # openid_credential_issuer
│   ├── itWalletCredentialVerifier.ts  # openid_credential_verifier
│   └── index.ts
├── v1.3/                              # Spec v1.3 schemas
│   ├── itWalletSolution.ts            # wallet_solution (replaces wallet_provider)
│   ├── itWalletAuthorizationServer.ts # re-export of v1.0 (unchanged)
│   ├── itWalletCredentialIssuer.ts    # openid_credential_issuer (updated for v1.3)
│   ├── itWalletCredentialVerifier.ts  # openid_credential_verifier (updated for v1.3)
│   └── index.ts
├── itWalletFederationEntity.ts        # shared across versions
└── index.ts
```

The combined metadata schemas (`itWalletMetadataV1_0`, `itWalletMetadataV1_3`) and the `itWalletMetadataSchema` union are exported from `src/metadata/itWalletMetadata.ts`.

## API Reference

### Functions

- **`createItWalletEntityConfiguration(options)`**: Creates and signs an Entity Configuration JWT.
  - **Parameters**:
    - `options.header`: JWT header with algorithm, key id, and type
    - `options.claims`: Entity configuration claims (issuer, subject, metadata, etc.)
    - `options.signJwtCallback`: Callback function to sign the JWT
  - **Returns**: A signed JWT string

### Types

- **`SignCallback`**: Function type for signing JWT tokens
  ```typescript
  type SignCallback = (options: {
    jwk: JsonWebKey;
    toBeSigned: Uint8Array;
  }) => Promise<Uint8Array>;
  ```

- **`JsonWebKey`**: Type for JSON Web Key objects

- **`ItWalletEntityConfigurationClaimsOptions`**: Input type for entity configuration claims

- **`ItWalletEntityConfigurationClaims`**: Output type for entity configuration claims

- **`ItWalletEntityStatementClaimsOptions`**: Input type for entity statement claims

- **`ItWalletEntityStatementClaims`**: Output type for entity statement claims

### Zod Schemas

This package exports a comprehensive set of Zod schemas to validate all parts of the federation artifacts.

#### JWK Schemas:
- **`jsonWebKeySchema`**: Validates a single JSON Web Key (includes support for x5c certificate chain)

- **`jsonWebKeySetSchema`**: Validates a JSON Web Key Set

#### Metadata Schemas:
- **`itWalletFederationEntityMetadata`**: For `federation_entity` metadata

- **`itWalletProviderEntityMetadata`**: For `wallet_provider` metadata (v1.0)

- **`itWalletSolutionEntityMetadata`**: For `wallet_solution` metadata (v1.3)

- **`itWalletCredentialIssuerMetadata`**: For `openid_credential_issuer` metadata

- **`itWalletCredentialVerifierMetadata`**: For `openid_credential_verifier` metadata (default export - uses v1.3 schema)

- **`itWalletCredentialVerifierMetadataV1_3`**: For `openid_credential_verifier` metadata (v1.3 - with `logo_uri`, `encrypted_response_enc_values_supported`, and enhanced `vp_formats_supported`)

- **`itWalletAuthorizationServerMetadata`**: For `oauth_authorization_server` metadata

- **`itWalletMetadataV1_0`**: Combined metadata schema for v1.0 entity types

- **`itWalletMetadataV1_3`**: Combined metadata schema for v1.3 entity types

- **`itWalletMetadataSchema`**: Union of `itWalletMetadataV1_0` and `itWalletMetadataV1_3`

#### Claims Schemas:
- **`itWalletEntityStatementClaimsSchema`**: Validates the claims within an Entity Statement

- **`itWalletEntityConfigurationClaimsSchema`**: Validates the claims for an Entity Configuration (where iss must equal sub)
