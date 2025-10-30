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
];