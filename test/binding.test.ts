import assert from "node:assert/strict";
import test from "node:test";
import { buildSessionContext } from "@identities-ai/ratify-protocol";
import {
  PayloadNotCanonical,
  materialize,
  RatifyReceiver,
  canonicalJSON,
  payloadDigest,
  type ProtectedAction,
} from "../src/index.js";

const base: ProtectedAction = {
  action: "github.deploy",
  requiredScope: "custom:github:deploy",
  resourceId: "github:acme/payments",
  requestedPath: "/services/payments/environments/staging",
  payload: { artifact_digest: "sha256:abc" },
  agentId: "agent-1",
  sessionId: "session-1",
  invocationId: "inv-1",
};

/** Returns the operation the helper would send for an action. */
async function sentOperation(action: ProtectedAction): Promise<Record<string, unknown>> {
  let captured: Record<string, unknown> | undefined;
  const receiver = new RatifyReceiver({
    apiKey: "rat_test_key_0123456789",
    verifierId: "receiver:test",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: (async (_url: string | URL, init?: RequestInit) => {
      captured = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(JSON.stringify({ decision: "deny", decision_reason: "untrusted_root", identity_status: "unauthorized", receipt_hash: "sha256:" + "0".repeat(64), receipt: { receipt_id: "00000000-0000-0000-0000-000000000000" } }), { status: 200 });
    }) as unknown as typeof globalThis.fetch,
  });
  await receiver.decide(action, {});
  return (captured!.operation ?? {}) as Record<string, unknown>;
}

// If a field can change without changing request_hash, a presentation signed for
// one action authorizes another. Each case here is that leak, closed.
test("every action field changes the request hash", async () => {
  const original = (await sentOperation(base)).request_hash;
  const variants: Array<[string, ProtectedAction]> = [
    ["action", { ...base, action: "github.destroy" }],
    ["requiredScope", { ...base, requiredScope: "custom:github:admin" }],
    ["resourceId", { ...base, resourceId: "github:acme/other" }],
    ["requestedPath", { ...base, requestedPath: "/services/payments/environments/production" }],
    ["payload", { ...base, payload: { artifact_digest: "sha256:def" } }],
  ];
  for (const [field, variant] of variants) {
    const changed = (await sentOperation(variant)).request_hash;
    assert.notEqual(changed, original, `changing ${field} left request_hash unchanged`);
  }
});

test("the same action always produces the same request hash", async () => {
  const first = (await sentOperation(base)).request_hash;
  const second = (await sentOperation({ ...base })).request_hash;
  assert.equal(first, second, "a retry of the same action must match its recorded decision");
});

// Key order is an accident of construction; the digest must not depend on it,
// or a legitimate retry stops matching its own recorded decision.
test("payload key order does not change the digest", () => {
  const a = payloadDigest({ b: 2, a: 1, nested: { y: 2, x: 1 } });
  const b = payloadDigest({ a: 1, nested: { x: 1, y: 2 }, b: 2 });
  assert.deepEqual(a, b);
});

test("array order does change the digest", () => {
  assert.notDeepEqual(payloadDigest([1, 2]), payloadDigest([2, 1]));
});

test("canonical form is stated, not inherited", () => {
  assert.equal(canonicalJSON({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalJSON([1, "x", null]), '[1,"x",null]');
});

test("an absent payload is not the same as an empty one", () => {
  assert.equal(payloadDigest(undefined), undefined);
  assert.notEqual(payloadDigest({}), undefined);
});

test("the operation carries the configured verifier and workspace, not caller-supplied ones", async () => {
  const operation = await sentOperation(base);
  assert.equal(operation.verifier_id, "receiver:test");
  assert.equal(operation.workspace_id, "00000000-0000-0000-0000-000000000001");
});

test("configuration is required rather than defaulted", () => {
  const valid = {
    apiKey: "k",
    verifierId: "v",
    workspaceId: "w",
  };
  for (const missing of ["apiKey", "verifierId", "workspaceId"] as const) {
    assert.throws(() => new RatifyReceiver({ ...valid, [missing]: "" }), new RegExp(missing));
  }
});

/** A receiver whose transport is captured, for exercising both calls at once. */
function capturingReceiver() {
  const bodies: Record<string, unknown>[] = [];
  const receiver = new RatifyReceiver({
    apiKey: "rat_test_key_0123456789",
    verifierId: "receiver:test",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: (async (url: string | URL, init?: RequestInit) => {
      bodies.push(init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {});
      const body = String(url).endsWith("/challenge")
        ? { challenge: "Y2hhbGxlbmdlLWJ5dGVz" }
        : { decision: "deny", decision_reason: "untrusted_root", identity_status: "unauthorized", receipt_hash: "sha256:" + "0".repeat(64), receipt: { receipt_id: "00000000-0000-0000-0000-000000000000" } };
      return new Response(JSON.stringify(body), { status: 200 });
    }) as unknown as typeof globalThis.fetch,
  });
  return { receiver, bodies };
}

// The agent signs the context `challenge` hands out; the server rebuilds it from
// what `decide` sends and refuses a mismatch. If these two disagreed, every
// presentation would be refused as session_context_mismatch and no unit test
// here would say why.
test("the context the challenge hands out is the one the decision binds", async () => {
  const { receiver, bodies } = capturingReceiver();
  const { sessionContext } = await receiver.challenge(base);
  await receiver.decide(base, {});
  const operation = (bodies[1]!.operation ?? {}) as Record<string, string>;

  const expected = buildSessionContext({
    verifier_id: operation.verifier_id,
    workspace_id: operation.workspace_id,
    agent_id: operation.agent_id,
    session_id: operation.session_id,
    invocation_id: operation.invocation_id,
    request_hash: Buffer.from(operation.request_hash!, "base64"),
  });
  assert.equal(sessionContext, Buffer.from(expected).toString("base64"));
});

test("a challenge is carried through unchanged", async () => {
  const { receiver } = capturingReceiver();
  const { challenge } = await receiver.challenge(base);
  assert.equal(challenge, "Y2hhbGxlbmdlLWJ5dGVz");
});

// Absent and empty are different facts on a receipt: one says no contract was
// declared, the other names a contract called "".
test("an action with no profile sends no action_profile field", async () => {
  const operation = await sentOperation(base);
  assert.ok(!("action_profile" in operation), "an undeclared profile went on the wire");
});

test("a declared profile is sent as given", async () => {
  const operation = await sentOperation({ ...base, actionProfile: "acme.thing/v3" });
  assert.equal(operation.action_profile, "acme.thing/v3");
});

// Finding 1. A digest is an authorization binding, so two payloads that differ
// must never reach the same bytes. A serializer that coerces what it does not
// understand into {} lets one action authorize another.
test("payloads that differ cannot share a digest", () => {
  const distinct: [string, unknown, unknown][] = [
    ["an empty array and a one-hole array", [], Array(1)],
    ["two different dates", new Date(0), new Date(999_999)],
    ["two different maps", new Map([["a", 1]]), new Map([["b", 2]])],
    ["a function-valued and a null-valued member", { x: () => 1 }, { x: null }],
    ["two different sets", new Set([1]), new Set([2])],
  ];
  for (const [name, a, b] of distinct) {
    let da: string | undefined;
    let db: string | undefined;
    try {
      da = canonicalJSON(a as never);
    } catch (error) {
      assert.ok(error instanceof PayloadNotCanonical, `${name}: wrong error type`);
    }
    try {
      db = canonicalJSON(b as never);
    } catch (error) {
      assert.ok(error instanceof PayloadNotCanonical, `${name}: wrong error type`);
    }
    // Either both are refused, or they serialize differently. What must not
    // happen is two different inputs quietly producing one digest.
    assert.ok(
      da === undefined || db === undefined || da !== db,
      `${name}: collided on ${da}`,
    );
  }
});

// The first rewrite kept JSON.stringify's array behaviour, which writes `null`
// for both a hole and an explicit undefined. That put three different arrays on
// one digest and recreated the flaw the rewrite existed to remove. Array
// positions are signed by index; there is no absent position.
test("nothing that is not a JSON value can occupy an array position", () => {
  assert.equal(canonicalJSON([]), "[]");
  assert.equal(canonicalJSON([null]), "[null]");
  for (const [name, value] of [
    ["an explicit undefined", [undefined]],
    ["a hole", Array(1)],
    ["a trailing hole", [1, , ] as unknown],
    ["a hole among values", [1, , 3] as unknown],
  ] as [string, unknown][]) {
    assert.throws(
      () => canonicalJSON(value as never),
      PayloadNotCanonical,
      `${name} was accepted into an array position`,
    );
  }
});

test("an array position that is not JSON never shares a digest with null", () => {
  const nullArray = canonicalJSON([null]);
  for (const [name, value] of [
    ["[undefined]", [undefined]],
    ["Array(1)", Array(1)],
  ] as [string, unknown][]) {
    let serialized: string | undefined;
    try {
      serialized = canonicalJSON(value as never);
    } catch (error) {
      assert.ok(error instanceof PayloadNotCanonical);
    }
    assert.notEqual(serialized, nullArray, `${name} collided with [null]`);
  }
});

// Coercing these to null would collide NaN, Infinity, -Infinity and a real null.
test("values JSON cannot represent are refused, not coerced", () => {
  for (const bad of [{ n: NaN }, { n: Infinity }, { n: -Infinity }, { n: 1n }, { n: Symbol("s") }]) {
    assert.throws(() => canonicalJSON(bad as never), PayloadNotCanonical, `${String(Object.values(bad)[0])} was accepted`);
  }
});

test("a cycle is refused rather than overflowing the stack", () => {
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalJSON(cyclic as never), PayloadNotCanonical);
});

test("the error names the path, so a caller can find the offending field", () => {
  try {
    canonicalJSON({ outer: { list: [1, new Date(0)] } } as never);
    assert.fail("accepted a Date");
  } catch (error) {
    assert.ok(error instanceof PayloadNotCanonical);
    assert.match(error.message, /payload\.outer\.list\[1\]/);
  }
});

// This test previously asserted that an undefined member is dropped, "as JSON
// drops it" -- blessing a collision instead of catching it. The handler receives
// the original object, so `{a: 1}` and `{a: 1, b: undefined}` are two actions:
// `"b" in payload`, `Object.keys`, and any schema check tell them apart. What
// JSON.stringify does with them is not the question.
test("an undefined object member is refused, because the handler can see it", () => {
  assert.throws(() => canonicalJSON({ a: 1, b: undefined } as never), PayloadNotCanonical);
  // The message has to name the fix -- omit the property -- or the check earns
  // nothing over the generic "undefined is not JSON" that would fire anyway.
  assert.throws(() => canonicalJSON({ a: 1, b: undefined } as never), /omit the property instead/);
  assert.throws(() => canonicalJSON({ a: 1, b: undefined } as never), /"b" in payload/);
  assert.notEqual(
    (() => { try { return canonicalJSON({ a: 1, b: undefined } as never); } catch { return "refused"; } })(),
    canonicalJSON({ a: 1 }),
  );
});

// The root cause behind that collision, applied to everything else that shares
// it: the digest hashes a projection, the handler acts on the original object.
// Anything readable from one and not the other is a way for two actions to share
// one signature.
test("nothing the handler can read is invisible to the digest", () => {
  const hidden = Object.defineProperty({ a: 1 }, "secret", { value: "x", enumerable: false });
  assert.throws(() => canonicalJSON(hidden as never), /non-enumerable/);

  const symbolKeyed: Record<string | symbol, unknown> = { a: 1 };
  symbolKeyed[Symbol("s")] = "hidden";
  assert.throws(() => canonicalJSON(symbolKeyed as never), /symbol-keyed/);

  // A getter hashed one value and would hand the handler another.
  let reads = 0;
  const volatile = { a: 1, get b() { return ++reads; } };
  assert.throws(() => canonicalJSON(volatile as never), /accessor/);

  // An array is an object too, and the same defect rides on it. This one was
  // found by probing the fix for the defect above, not by any review.
  const decorated: unknown[] & { extra?: string } = [1, 2];
  decorated.extra = "readable by the handler";
  assert.throws(() => canonicalJSON(decorated as never), /property on an array/);
  assert.notEqual(
    (() => { try { return canonicalJSON(decorated as never); } catch { return "refused"; } })(),
    canonicalJSON([1, 2]),
  );

  const symbolOnArray: unknown[] = [1];
  (symbolOnArray as Record<symbol, unknown>)[Symbol("s")] = "hidden";
  assert.throws(() => canonicalJSON(symbolOnArray as never), /symbol-keyed/);

  let arrayReads = 0;
  const volatileArray = Object.defineProperty([1], "0", { get: () => ++arrayReads, enumerable: true, configurable: true });
  assert.throws(() => canonicalJSON(volatileArray as never), /accessor/);
});

// JSON.stringify(-0) is "0", so the digest cannot separate them while the
// handler can: Object.is says false and 1/-0 is -Infinity.
test("negative zero is refused rather than flattened onto zero", () => {
  assert.throws(() => canonicalJSON(-0), /negative zero/);
  assert.throws(() => canonicalJSON({ n: -0 }), /negative zero/);
  assert.throws(() => canonicalJSON([-0]), /negative zero/);
  assert.equal(canonicalJSON(0), "0");
});

test("a rejected payload never reaches the wire", async () => {
  await assert.rejects(
    sentOperation({ ...base, payload: { when: new Date(0) } as never }),
    PayloadNotCanonical,
  );
});

// A hole and an explicit undefined are both refused, but they are different
// mistakes -- a hole is usually a trailing comma or `new Array(n)` -- so the
// message has to tell them apart or the distinction is not worth the branch.
test("a hole is diagnosed as a hole, not as undefined", () => {
  assert.throws(() => canonicalJSON(Array(1) as never), /payload\[0\] is a hole/);
  assert.throws(() => canonicalJSON([1, , 3] as never), /payload\[1\] is a hole/);
  assert.throws(() => canonicalJSON([undefined] as never), /payload\[0\] is undefined/);
});

// Finding R4-1. These are observable on the caller's object and absent from any
// serialization, so under the old projection model each was a way for two
// payloads to share a digest. The snapshot collapses them: the handler acts on
// an owned plain copy, where none of these distinctions exist to be read.
test("distinctions that only exist on the original do not survive into the binding", () => {
  const child = { x: 1 };
  const aliased = canonicalJSON({ a: child, b: child });
  const twins = canonicalJSON({ a: { x: 1 }, b: { x: 1 } });
  assert.equal(aliased, twins, "these must bind identically, because the snapshot has no aliases");

  // And the snapshot really does drop the alias, rather than preserving a
  // distinction the digest cannot see.
  const snapshot = materialize({ a: child, b: child }) as { a: unknown; b: unknown };
  assert.notEqual(snapshot.a, snapshot.b, "the snapshot preserved a shared reference");
  assert.deepEqual(snapshot.a, snapshot.b);
});

test("the snapshot is owned, so the original cannot reach through it", () => {
  const original = { nested: { value: "before" } };
  const snapshot = materialize(original) as { nested: { value: string } };
  original.nested.value = "after";
  assert.equal(snapshot.nested.value, "before", "the snapshot aliased the caller's object");
});

test("a null-prototype object binds the same as a plain one", () => {
  const nullProto = Object.assign(Object.create(null), { a: 1 });
  assert.equal(canonicalJSON(nullProto as never), canonicalJSON({ a: 1 }));
  assert.equal(Object.getPrototypeOf(materialize(nullProto as never)), Object.prototype);
});

test("a sealed or frozen input binds the same as a mutable one", () => {
  assert.equal(canonicalJSON(Object.seal({ a: 1 })), canonicalJSON({ a: 1 }));
  assert.equal(canonicalJSON(Object.freeze({ a: 1 })), canonicalJSON({ a: 1 }));
});

// Finding R4-4. RangeError is neither the promised error type nor a controlled
// failure for a payload shaped by a request or a tool.
test("depth and size are bounded, and the failure is the documented one", () => {
  const deep: Record<string, unknown> = {};
  let cursor = deep;
  for (let i = 0; i < 500; i++) {
    const next: Record<string, unknown> = {};
    cursor.n = next;
    cursor = next;
  }
  assert.throws(() => canonicalJSON(deep as never), PayloadNotCanonical);
  assert.throws(() => canonicalJSON(deep as never), /nested deeper than/);

  const wide: Record<string, unknown> = {};
  for (let i = 0; i < 60_000; i++) wide[`k${i}`] = i;
  assert.throws(() => canonicalJSON(wide as never), /more than 50000 values/);
});

test("a payload at the limits is still accepted", () => {
  const atDepth: Record<string, unknown> = {};
  let cursor = atDepth;
  for (let i = 0; i < 60; i++) {
    const next: Record<string, unknown> = {};
    cursor.n = next;
    cursor = next;
  }
  assert.ok(canonicalJSON(atDepth as never).length > 0);
});

// Finding R5-1. `JSON.parse` produces "__proto__" as an ordinary own property,
// but `out[key] = value` runs the legacy prototype setter instead of creating
// one. The value vanished from the snapshot and the digest while staying
// readable through the snapshot's prototype: attacker-controlled data outside
// the signature, which is precisely what the snapshot exists to prevent.
//
// Worth noting how this survived: `__proto__` was probed and cleared one round
// earlier, under a different implementation, and not re-checked after the
// module was rewritten.
test("__proto__ is bound as data, not applied as a prototype", () => {
  const parsed = JSON.parse('{"__proto__": {"admin": true}, "a": 1}');
  const snapshot = materialize(parsed) as Record<string, unknown>;

  assert.deepEqual(Object.getOwnPropertyNames(snapshot), ["__proto__", "a"]);
  assert.equal(Object.getPrototypeOf(snapshot), Object.prototype, "the payload set the prototype");
  assert.equal((snapshot as { admin?: unknown }).admin, undefined, "payload data leaked onto the prototype");
  assert.deepEqual(snapshot["__proto__"], { admin: true });
});

test("__proto__ reaches the digest, so it cannot be smuggled past the signature", () => {
  const withProto = JSON.parse('{"__proto__": {"admin": true}, "a": 1}');
  const without = JSON.parse('{"a": 1}');
  assert.match(canonicalJSON(withProto), /__proto__/);
  assert.notEqual(
    canonicalJSON(withProto),
    canonicalJSON(without),
    "two payloads differing in __proto__ shared a digest",
  );
});

test("a nested __proto__ is bound too", () => {
  const nested = JSON.parse('{"outer": {"__proto__": {"admin": true}, "b": 2}}');
  const snapshot = materialize(nested) as { outer: Record<string, unknown> };
  assert.deepEqual(Object.getOwnPropertyNames(snapshot.outer), ["__proto__", "b"]);
  assert.equal((snapshot.outer as { admin?: unknown }).admin, undefined);
  assert.match(canonicalJSON(nested), /__proto__/);
});

test("a bound __proto__ property is still frozen", () => {
  const snapshot = materialize(JSON.parse('{"__proto__": {"admin": true}}')) as Record<string, unknown>;
  assert.ok(Object.isFrozen(snapshot));
  assert.throws(() => {
    Object.defineProperty(snapshot, "__proto__", { value: "changed" });
  }, TypeError);
});
