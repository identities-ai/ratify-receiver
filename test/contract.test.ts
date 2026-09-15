import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { RatifyReceiver, githubDeployV1, GITHUB_DEPLOY_V1 } from "../src/index.js";

/**
 * The helper and the API agree on a wire format. This repository keeps the
 * receiver-facing portion of that contract as a small fixture so a clean clone
 * does not depend on the commercial API repository being present.
 *
 * The fixture is intentionally minimal. A minimal parse is enough because the
 * operation block is flat, and it avoids a YAML dependency in a package that a
 * customer installs. The fixture must be updated when the Verify API changes.
 */
function operationSpec(): { required: string[]; properties: string[] } {
  const spec = readFileSync(new URL("./fixtures/verify-contract.yaml", import.meta.url), "utf8");
  const start = spec.indexOf("                operation:");
  assert.ok(start > 0, "the verify request no longer declares an operation block");
  const required = /required: \[([^\]]+)\]/.exec(spec.slice(start, start + 400));
  assert.ok(required, "the operation block declares no required fields");

  // Property names are the keys indented one level inside `properties:`.
  const propsAt = spec.indexOf("properties:", start);
  const block = spec.slice(propsAt, spec.indexOf("\n      responses:", propsAt));
  const properties = [...block.matchAll(/^ {20}([a-z_]+):/gm)].map((m) => m[1]!);
  return {
    required: required[1]!.split(",").map((f) => f.trim()),
    properties,
  };
}

/** The operation the helper actually puts on the wire. */
async function sentOperation(): Promise<Record<string, unknown>> {
  let captured: Record<string, unknown> | undefined;
  const receiver = new RatifyReceiver({
    apiKey: "rat_test_key_0123456789",
    verifierId: "receiver:test",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: (async (_u: string | URL, init?: RequestInit) => {
      captured = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(JSON.stringify({ decision: "deny", decision_reason: "untrusted_root", identity_status: "unauthorized", receipt_hash: "sha256:" + "0".repeat(64), receipt: { receipt_id: "00000000-0000-0000-0000-000000000000" } }), { status: 200 });
    }) as unknown as typeof globalThis.fetch,
  });
  await receiver.decide(
    githubDeployV1({
      owner: "acme",
      repo: "payments",
      service: "payments",
      environment: "staging",
      artifactDigest: "sha256:abc",
      agentId: "agent-1",
      sessionId: "session-1",
      invocationId: "inv-1",
    }),
    {},
  );
  return (captured!.operation ?? {}) as Record<string, unknown>;
}

test("the helper sends every field the API requires", async () => {
  const { required } = operationSpec();
  const operation = await sentOperation();
  for (const field of required) {
    assert.ok(
      operation[field] !== undefined && operation[field] !== null,
      `the spec requires operation.${field} and the helper does not send it`,
    );
  }
});

test("the helper sends no field the API does not declare", async () => {
  const { properties } = operationSpec();
  const operation = await sentOperation();
  for (const field of Object.keys(operation)) {
    assert.ok(
      properties.includes(field),
      `the helper sends operation.${field}, which the spec does not declare`,
    );
  }
});

test("the profile builder produces the contract the reference demonstrates", async () => {
  const operation = await sentOperation();
  assert.equal(operation.action, "github.deploy");
  assert.equal(operation.resource_id, "github:acme/payments");
  assert.equal(operation.requested_path, "/services/payments/environments/staging");
  assert.equal(operation.action_profile, GITHUB_DEPLOY_V1);
});

// A named version has to mean one thing. This pins the current output so any
// change to the bytes behind github.deploy/v1 fails here, which is the point:
// revising the contract is a new version, not an edit to an existing one.
//
// It is a change detector, not an independent derivation — the value was taken
// from this implementation. What makes the implementation trustworthy is the
// field-sensitivity and determinism coverage in binding.test.ts; this only
// guarantees it stops moving.
test("github.deploy/v1 is pinned to a fixed request hash", async () => {
  const operation = await sentOperation();
  assert.equal(
    operation.request_hash,
    "nhFyVFKdQYWGTCCOgOJnrFtnHCnCo2LmnHt2RFWPcbM=",
    "the bytes behind github.deploy/v1 changed; that is a new version, not an edit",
  );
});

// The API bounds action_profile and rejects rather than truncates, so a profile
// name that outgrows the bound is a 400 an integrator meets in production. The
// spec carries the numbers; this reads them rather than restating them.
test("every shipped profile name fits the contract the API declares", () => {
  const spec = readFileSync(new URL("./fixtures/verify-contract.yaml", import.meta.url), "utf8");
  const at = spec.indexOf("                    action_profile:");
  assert.ok(at > 0, "the verify request no longer declares action_profile");
  const block = spec.slice(at, at + 300);
  const declared = /maxLength: (\d+)/.exec(block);
  assert.ok(declared, "action_profile declares no maxLength, so nothing bounds a receipt field");

  // Go measures bytes and JSON Schema maxLength counts characters. The ASCII
  // pattern is what makes those the same contract, so its absence is a defect
  // even though every current name would still pass the length check.
  assert.match(block, /pattern: '\^\[!-~\]\+\$'/, "no ASCII pattern: bytes and characters would diverge");
  assert.match(block, /minLength: 1/, "no minLength: a declared-but-empty profile would be silently absent");

  const limit = Number(declared[1]);
  for (const name of [GITHUB_DEPLOY_V1]) {
    assert.ok(/^[!-~]+$/.test(name), `profile "${name}" is not printable ASCII`);
    assert.equal(Buffer.byteLength(name, "utf8"), name.length, `profile "${name}" is multi-byte`);
    assert.ok(name.length <= limit, `profile "${name}" is ${name.length}, over the declared ${limit}`);
  }
});

// The helper pins the code the server actually emits. The spec disagreed with
// the server here, and a pilot branching on the documented value would never
// have matched.
test("the documented conflict code is the one the server sends", () => {
  const spec = readFileSync(new URL("./fixtures/verify-contract.yaml", import.meta.url), "utf8");
  assert.ok(
    !spec.includes("invocation_already_recorded"),
    "the spec still documents a conflict code the server never emits",
  );
  assert.ok(spec.includes("invocation_conflict"), "the spec no longer documents the conflict code");
});
