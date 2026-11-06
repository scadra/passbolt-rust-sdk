// Writes each ```ts example of a Markdown page to its own module, for `tsc --strict` to check them
// against the installed package. The values an example takes as given (`serverUrl`, `session`…)
// are declared, unless the example declares them.
//
//   node doc-examples.mjs ../../docs/sdk/javascript.md examples/
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [page, outDir] = process.argv.slice(2);
const given = {
  serverUrl: "string",
  privateKeyArmored: "string",
  publicKeyArmored: "string",
  passphrase: "string",
  id: "string",
  userId: "string",
  groupId: "string",
  folderId: "string",
  session: 'import("@switch-case/passbolt-sdk").PassboltSession',
  browser:
    "{ cookies: { get(details: { name: string; url: string }): Promise<{ value: string } | null> } }",
};

const examples = [...readFileSync(page, "utf8").matchAll(/^```ts\n([\s\S]*?)^```$/gm)].map(
  (match) => match[1],
);
if (examples.length === 0) throw new Error(`no ts example in ${page}`);
mkdirSync(outDir, { recursive: true });
examples.forEach((example, index) => {
  const declarations = Object.entries(given)
    .filter(([name]) => new RegExp(`\\b${name}\\b`).test(example))
    .filter(([name]) => !new RegExp(`\\b(const|let|using)\\s+${name}\\b`).test(example))
    .map(([name, type]) => `declare const ${name}: ${type};\n`);
  writeFileSync(join(outDir, `example-${index + 1}.mts`), `${declarations.join("")}${example}export {};\n`);
});
console.log(`${examples.length} examples`);
