import pagopa from "@pagopa/eslint-config";

export default [
  ...pagopa,
  {
    languageOptions: {
      parserOptions: {
        project: [
          "./tsconfig.json",
          "./packages/*/tsconfig.json"
        ],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/consistent-type-exports": [
        "error",
        { fixMixedExportsWithInlineTypeSpecifier: true },
      ],
    },
  },
  {
    // Allow separate overloads for better type inference in version-specific APIs
    files: [
      "packages/oauth2/src/client-attestation/client-attestation.ts",
      "packages/oid4vci/src/wallet-provider/WalletProvider.ts",
    ],
    rules: {
      "@typescript-eslint/unified-signatures": "off",
    },
  },
];