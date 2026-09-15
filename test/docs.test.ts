import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as api from "../src/index.js";

/**
 * The README is the integration contract for a package whose whole job is to be
 * hard to misuse, and it drifts silently: nothing compiles it, so a renamed
 * field leaves behind an example that reads as current and does not work.
 *
 * Both failures these cases exist for were real. A section was duplicated
 * wholesale during a rebase, and an example went on branching on a `notRun`
 * field after it had been replaced by `status`. Neither was caught by any suite;
 * both were found by eye, once.
 */
const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
const typesSource = readFileSync(new URL("../src/types.ts", import.meta.url), "utf8");
const indexSource = readFileSync(new URL("../src/index.ts", import.meta.url), "utf8");

/** The fenced ts blocks, which are what a reader will copy. */
function codeBlocks(): string {
  return [...readme.matchAll(/```ts\n([\s\S]*?)```/g)].map((m) => m[1]!).join("\n");
}

/** Property names declared on an interface in types.ts. */
function interfaceProperties(name: string): Set<string> {
  const start = typesSource.indexOf(`export interface ${name}`);
  assert.ok(start > 0, `types.ts no longer declares ${name}`);
  const body = typesSource.slice(start, typesSource.indexOf("\n}", start));
  return new Set([...body.matchAll(/^ {2}(\w+)\??:/gm)].map((m) => m[1]!));
}

test("no section of the README appears twice", () => {
  const headings = [...readme.matchAll(/^## (.+)$/gm)].map((m) => m[1]!);
  const seen = new Set<string>();
  for (const heading of headings) {
    assert.ok(!seen.has(heading), `"## ${heading}" appears more than once`);
    seen.add(heading);
  }
});

test("every name the README imports is actually exported", () => {
  const imports = [...codeBlocks().matchAll(/import \{([^}]+)\} from "@identities-ai\/ratify-receiver"/g)];
  assert.ok(imports.length > 0, "the README no longer shows an import");
  const exported = new Set(Object.keys(api));
  for (const match of imports) {
    for (const raw of match[1]!.split(",")) {
      const name = raw.trim().replace(/^type /, "");
      if (!name) continue;
      const isType = new RegExp(`type ${name}\\b`).test(indexSource);
      assert.ok(
        exported.has(name) || isType,
        `the README imports "${name}", which the package does not export`,
      );
    }
  }
});

test("every result field the README reads exists on GuardResult", () => {
  const properties = interfaceProperties("GuardResult");
  const referenced = [...codeBlocks().matchAll(/\bresult\.(\w+)/g)].map((m) => m[1]!);
  assert.ok(referenced.length > 0, "the README no longer shows a result being read");
  for (const field of referenced) {
    assert.ok(properties.has(field), `the README reads result.${field}, which GuardResult does not declare`);
  }
});

test("every context field the README reads exists on HandlerContext", () => {
  const properties = interfaceProperties("HandlerContext");
  // Destructured in the reconciliation example: guard(action, proof, ({ x }) => ...)
  const destructured = [...codeBlocks().matchAll(/async \(\{([^}]+)\}\)/g)]
    .flatMap((m) => m[1]!.split(",").map((s) => s.trim()))
    .filter(Boolean);
  for (const field of destructured) {
    assert.ok(properties.has(field), `the README destructures ${field}, which HandlerContext does not declare`);
  }
});

// The replay contract is the one an integrator is most likely to get wrong, and
// the reason there is no `allowed` boolean. If that explanation ever falls out
// of the README, the API's most surprising decision is left unexplained.
test("the README explains why there is no allowed boolean", () => {
  assert.match(readme, /no `allowed` boolean/i);
  assert.ok(!/\bresult\.allowed\b/.test(codeBlocks()), "an example reads result.allowed, which does not exist");
});

test("the README names the protocol and managed Verify boundary", () => {
  assert.match(readme, /https:\/\/github\.com\/identities-ai\/ratify-protocol/);
  assert.match(readme, /https:\/\/ratifyprotocol\.com/);
  assert.match(readme, /Apache-2\.0/i);
});
