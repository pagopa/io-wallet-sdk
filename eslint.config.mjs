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
      // Allow separate overloads for better type inference in version-specific APIs
      "@typescript-eslint/unified-signatures": "off",
    },
  },
];