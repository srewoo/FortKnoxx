// FortKnoxx frontend ESLint config (flat config — ESLint 9.x).
//
// WHY this exists: the CI `frontend` job ran `yarn lint` with no
// rule set; this gives it teeth. Rules are intentionally lenient on
// the legacy CRA-craco code (App.js is ~1,800 LOC and would generate
// thousands of issues if we ran the strict React Hooks plugin). The
// strict plugins kick in once the FE is migrated to Vite/Next.

import js from "@eslint/js";
import globals from "globals";
import react from "eslint-plugin-react";
import jsxA11y from "eslint-plugin-jsx-a11y";
import importPlugin from "eslint-plugin-import";
import security from "eslint-plugin-security";
import sonarjs from "eslint-plugin-sonarjs";
import noSecrets from "eslint-plugin-no-secrets";

export default [
  {
    ignores: [
      "build/**",
      "node_modules/**",
      "public/help.html",
      "**/*.min.js",
      "components.json",
    ],
  },
  js.configs.recommended,
  {
    files: ["src/**/*.{js,jsx}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
      globals: {
        ...globals.browser,
        ...globals.es2024,
        // CRA injects these.
        process: "readonly",
      },
    },
    plugins: {
      react,
      "jsx-a11y": jsxA11y,
      import: importPlugin,
      security,
      sonarjs,
      "no-secrets": noSecrets,
    },
    settings: {
      react: { version: "detect" },
    },
    rules: {
      // ---- React core ----
      "react/jsx-uses-react": "off",       // not needed with React 17+ JSX transform
      "react/react-in-jsx-scope": "off",
      "react/prop-types": "off",           // codebase doesn't use PropTypes
      "react/jsx-uses-vars": "error",
      "react/no-unescaped-entities": "warn",

      // ---- Accessibility ----
      "jsx-a11y/alt-text": "warn",
      "jsx-a11y/anchor-is-valid": "warn",
      "jsx-a11y/aria-props": "error",

      // ---- Security ----
      "security/detect-eval-with-expression": "error",
      "security/detect-non-literal-fs-filename": "off",
      "no-secrets/no-secrets": [
        "warn",
        { tolerance: 4.5 },                // looser than default to avoid false positives on long URLs
      ],

      // ---- Code health (lenient on legacy code) ----
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "no-empty": ["error", { allowEmptyCatch: true }],
      "no-debugger": "error",
      "no-console": "off",                 // console is the dev's primary debugging tool today
      "no-undef": "error",
      "prefer-const": "warn",

      // ---- SonarJS (catch real bugs without yelling about complexity) ----
      "sonarjs/no-identical-functions": "warn",
      "sonarjs/no-duplicate-string": "off",
      "sonarjs/cognitive-complexity": "off",
      "sonarjs/no-collapsible-if": "warn",
    },
  },
];
