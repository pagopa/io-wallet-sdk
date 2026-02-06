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
│   ├── itWalletCredentialIssuer.ts    # v1.3 schema with breaking changes
│   ├── itWalletCredentialVerifier.ts  # re-export of v1.0 (unchanged)
│   └── index.ts
├── itWalletFederationEntity.ts        # shared across versions
└── index.ts
```

The combined metadata schemas (`itWalletMetadataV1_0`, `itWalletMetadataV1_3`) and the `itWalletMetadataSchema` union are exported from `src/metadata/itWalletMetadata.ts`.

## Breaking Changes in v1.3

The v1.3 specification introduces breaking changes to the `openid_credential_issuer` metadata schema. These changes are isolated to the v1.3 version to maintain backward compatibility with existing v1.0 implementations.

### Removed Fields

The following fields have been removed from the top-level `openid_credential_issuer` metadata:

- **`revocation_endpoint`** - Replaced by status list aggregation mechanisms
- **`status_assertion_endpoint`** - Replaced by `status_list_aggregation_endpoint`
- **`credential_hash_alg_supported`** - No longer used in the specification
- **`evidence_supported`** - Moved to credential-specific metadata

### Added Fields

New fields introduced at the top level:

- **`batch_credential_issuance`** (optional) - Configuration for batch credential issuance
  - `batch_size` (integer, positive) - Maximum number of credentials in a single batch request
- **`status_list_aggregation_endpoint`** (optional, string URL) - Endpoint for TOKEN-STATUS-LIST aggregation per the specification

### Enhanced Credential Configuration

Each entry in `credential_configurations_supported` now requires additional mandatory fields:

#### New Required Fields

- **`credential_metadata`** (required) - Comprehensive display and claims metadata structure
  - `display[]` (optional) - Enhanced display metadata with:
    - `name` (required) - Display name
    - `locale` (required) - Locale identifier
    - `description` (optional) - Description text
    - `logo` (optional) - Logo image with URI and integrity hash
    - `background_color` (optional) - Background color
    - `background_image` (optional) - Background image with URI and integrity hash
    - `watermark_image` (optional) - Watermark image with URI and integrity hash
  - `claims[]` (optional) - Claim-level configuration with:
    - `path` (required) - JSON path to the claim
    - `mandatory` (optional, boolean) - Whether the claim is mandatory
    - `sd` (optional, enum: "always" | "never") - Selective disclosure configuration
    - `display[]` (optional) - Display metadata for the claim

- **`schema_id`** (required, string) - Reference to the credential schema in the Schema Registry

- **`authentic_sources`** (required) - Data source attribution
  - `entity_id` (required, string) - Source entity identifier
  - `dataset_id` (required, string) - Dataset identifier within the source

#### Enhanced Proof Types

The `proof_types_supported.jwt` object now supports an additional optional field:

- **`key_attestations_required`** (optional, boolean) - Indicates whether key attestation is required per OpenID4VCI Appendix F.1 and Section 12.2

### Migration from v1.0 to v1.3

To migrate from v1.0 to v1.3, update your imports and adjust your metadata structure:

```typescript
// v1.0 (old)
import { itWalletCredentialIssuerMetadata } from '@pagopa/io-wallet-oid-federation/entity/v1.0';

// v1.3 (new)
import { itWalletCredentialIssuerMetadata } from '@pagopa/io-wallet-oid-federation/entity/v1.3';

// Update your metadata structure
const metadata = {
  // Remove these fields:
  // revocation_endpoint: "...",
  // status_assertion_endpoint: "...",
  // credential_hash_alg_supported: "...",
  // evidence_supported: [...],

  // Add these (batch_credential_issuance is optional):
  batch_credential_issuance: {
    batch_size: 10
  },
  status_list_aggregation_endpoint: "https://issuer.example.org/status-list",

  credential_configurations_supported: {
    MyCredential: {
      // Existing fields remain...
      format: "dc+sd-jwt",
      vct: "MyCredential",
      scope: "MyCredential",
      credential_signing_alg_values_supported: ["ES256"],
      cryptographic_binding_methods_supported: ["jwk"],
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ["ES256"],
          // Optional: add key attestation requirement
          key_attestations_required: true
        }
      },

      // Add these required fields:
      credential_metadata: {
        display: [{
          name: "My Credential",
          locale: "en-US",
          description: "Description of the credential",
          logo: {
            uri: "https://issuer.example.org/logo.svg",
            "uri#integrity": "sha256-..."
          }
        }],
        claims: [{
          path: ["credentialSubject", "name"],
          mandatory: true,
          sd: "never",
          display: [{
            name: "Full Name",
            locale: "en-US"
          }]
        }]
      },
      schema_id: "https://schema.example.org/MyCredential.json",
      authentic_sources: {
        entity_id: "https://source.example.org",
        dataset_id: "credentials"
      }
    }
  }
};
```

### Image Metadata

Images in v1.3 support integrity verification through subresource integrity hashes:

```typescript
{
  uri: "https://example.org/image.svg",
  "uri#integrity": "sha256-base64encodedHash",
  alt_text: "Alternative text for accessibility"
}
```

The `uri#integrity` field follows the Subresource Integrity specification format.

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

- **`itWalletCredentialVerifierMetadata`**: For `openid_credential_verifier` metadata

- **`itWalletAuthorizationServerMetadata`**: For `oauth_authorization_server` metadata

- **`itWalletMetadataV1_0`**: Combined metadata schema for v1.0 entity types

- **`itWalletMetadataV1_3`**: Combined metadata schema for v1.3 entity types

- **`itWalletMetadataSchema`**: Union of `itWalletMetadataV1_0` and `itWalletMetadataV1_3`

#### Claims Schemas:
- **`itWalletEntityStatementClaimsSchema`**: Validates the claims within an Entity Statement

- **`itWalletEntityConfigurationClaimsSchema`**: Validates the claims for an Entity Configuration (where iss must equal sub)
