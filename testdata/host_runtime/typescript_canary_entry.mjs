import ts from "typescript";

const sourceFile = "/src/index.ts";
const libraryFile = "/lib.d.ts";
const files = new Map([
  [sourceFile, `
    interface User { name: string }
    const user = { name: "Ada" } satisfies User;
    export const greeting: string = ` + "`hello ${user.name}`" + `;
  `],
  [libraryFile, `
    interface Array<T> { readonly length: number; readonly [index: number]: T }
    interface Boolean {}
    interface Function {}
    interface CallableFunction extends Function {}
    interface NewableFunction extends Function {}
    interface IArguments { readonly length: number; readonly [index: number]: unknown }
    interface Number {}
    interface Object {}
    interface RegExp {}
    interface String {}
  `],
]);
const outputs = new Map();
const options = {
  module: ts.ModuleKind.ES2022,
  target: ts.ScriptTarget.ES2022,
  strict: true,
  noEmitOnError: true,
};
const host = {
  getSourceFile(fileName, languageVersion) {
    const source = files.get(fileName);
    return source === undefined ? undefined : ts.createSourceFile(fileName, source, languageVersion, true);
  },
  getDefaultLibFileName() { return libraryFile; },
  writeFile(fileName, text) { outputs.set(fileName, text); },
  getCurrentDirectory() { return "/"; },
  getDirectories() { return []; },
  fileExists(fileName) { return files.has(fileName); },
  readFile(fileName) { return files.get(fileName); },
  getCanonicalFileName(fileName) { return fileName; },
  useCaseSensitiveFileNames() { return true; },
  getNewLine() { return "\n"; },
};

const program = ts.createProgram([sourceFile], options, host);
const diagnostics = ts.getPreEmitDiagnostics(program);
const emit = program.emit();
const output = outputs.get("/src/index.js") || "";

export default JSON.stringify({
  version: ts.version,
  diagnostics: diagnostics.map(diagnostic => ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n")),
  emitSkipped: emit.emitSkipped,
  output,
});
