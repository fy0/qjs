# Host runtime fixtures

`typescript-5.9.3-canary.mjs` is a single-file Node-platform ESM bundle generated from:

- `typescript@5.9.3`
- npm integrity: `sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdiaUpFT4bXlb1RHhLpp8wtm6M5TgSw==`
- `esbuild@0.25.6`
- entry point: `typescript_canary_entry.mjs`

The bundle uses `platform=node`, `format=esm`, and `target=node24`. It preserves Node built-in `require` calls and injects stable bundle values for `__filename` and `__dirname`. Whitespace and syntax are minified, but identifiers are not. TypeScript's legal comments remain inline.

The canary executes a non-watch `ts.createProgram()` compilation with a virtual compiler host. It verifies that a real bundled Node tool can initialize against the QJS host runtime and emit JavaScript without diagnostics.

`typescript-5.9.3.LICENSE.txt` and `typescript-5.9.3.NOTICE.txt` preserve the npm package text with line endings and trailing whitespace normalized for the repository.
