import globals from "globals";
import pluginJs from "@eslint/js";

export default [
  {files: ["**/*.js"], languageOptions: {sourceType: "commonjs"}},
  {languageOptions: { globals: {...globals.browser, ...globals.node} }},
  pluginJs.configs.recommended,
  {
    "rules": {
      "no-unused-vars": "error",
      "no-undef": "error",
      "camelcase": "error",
      "capitalized-comments": "always"
    }
  }
];