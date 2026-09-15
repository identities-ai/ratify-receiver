import { createHash } from "node:crypto";
import { PayloadNotCanonical, type JsonValue } from "./types.js";

/**
 * Depth and node ceilings. A payload shaped by a request or a tool is not
 * trusted input, and recursion that ends in `RangeError` is both a local
 * denial of service and a broken error contract: callers are told this module
 * signals `PayloadNotCanonical`.
 */
const MAX_DEPTH = 64;
const MAX_NODES = 50_000;

/**
 * Binds a payload by taking an owned, immutable snapshot of it and hashing that
 * exact snapshot.
 *
 * **The snapshot is the payload.** The digest is computed from it, it is what
 * `HandlerContext.payload` hands the handler, and it is frozen, so the value
 * that was authorized is the value that gets acted on.
 *
 * This replaces an approach that tried to hash the caller's object in place
 * while rejecting the ways it could differ from its own hash. That could not
 * work, and the reason is worth stating because it is the whole design:
 *
 * - The caller's object stays mutable. Hashing it, awaiting a network round
 *   trip, and then running a handler that reads it again is a time-of-check to
 *   time-of-use gap. A payload that said `staging` when hashed could say
 *   `production` when the handler ran, under an authorization for `staging`.
 * - Prototypes, aliasing between branches, property descriptors, sealed and
 *   frozen states, and proxies are all observable on the original and absent
 *   from any serialization. Each one is a way for two payloads to share a
 *   digest, and enumerating them does not converge — JavaScript keeps offering
 *   more.
 *
 * Copying out collapses every one of those into a single plain JSON value: the
 * snapshot has no prototype chain worth reading, no shared references, no
 * exotic descriptors, and nothing that can change after the fact.
 *
 * The rejections below are no longer the safety mechanism — the snapshot is.
 * They remain because they are good diagnostics: a payload carrying a `Date`, a
 * getter or a symbol key is not plain data, and silently dropping those from
 * the snapshot would surprise the caller more than refusing them does.
 */
export function bindPayload(payload: JsonValue | undefined): {
  snapshot: JsonValue | undefined;
  digest: Uint8Array | undefined;
} {
  if (payload === undefined) return { snapshot: undefined, digest: undefined };
  const snapshot = materialize(payload);
  const digest = new Uint8Array(
    createHash("sha256").update(serialize(snapshot), "utf8").digest(),
  );
  return { snapshot, digest };
}

/**
 * An owned, deeply frozen copy of a payload.
 *
 * Every value is read exactly once, so a getter or a proxy cannot return one
 * value to the hash and another to the handler.
 */
export function materialize(value: JsonValue): JsonValue {
  return copy(value, [], "payload", 0, { nodes: 0 });
}

/**
 * Deterministic JSON for a payload.
 *
 * Keys are sorted by UTF-16 code unit and arrays keep their order and length.
 * The input is snapshotted first, so this is the serialization of the value
 * that would be bound, not of the caller's object.
 */
export function canonicalJSON(value: JsonValue): string {
  return serialize(materialize(value));
}

/** SHA-256 over the canonical form of a payload, or undefined when there is none. */
export function payloadDigest(payload: JsonValue | undefined): Uint8Array | undefined {
  return bindPayload(payload).digest;
}

function describeType(value: unknown): string {
  if (value === undefined) return "undefined";
  if (typeof value === "object" && value !== null) {
    const name = value.constructor?.name;
    return name && name !== "Object" ? name : "a non-plain object";
  }
  return typeof value;
}

/** Refuses anything an object carries that a JSON snapshot would not. */
function assertPlainData(object: object, path: string): void {
  if (Object.getOwnPropertySymbols(object).length > 0) {
    throw new PayloadNotCanonical(`${path} has symbol-keyed properties, which are not JSON`);
  }
  for (const key of Object.getOwnPropertyNames(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key)!;
    if (descriptor.get !== undefined || descriptor.set !== undefined) {
      throw new PayloadNotCanonical(`${path}.${key} is an accessor; pass a plain value`);
    }
    if (!descriptor.enumerable) {
      throw new PayloadNotCanonical(`${path}.${key} is non-enumerable, so it is not JSON data`);
    }
    if (descriptor.value === undefined) {
      throw new PayloadNotCanonical(
        `${path}.${key} is undefined; omit the property instead, since "${key}" in payload can be branched on`,
      );
    }
  }
}

function copy(
  value: unknown,
  seen: object[],
  path: string,
  depth: number,
  state: { nodes: number },
): JsonValue {
  if (++state.nodes > MAX_NODES) {
    throw new PayloadNotCanonical(`payload has more than ${MAX_NODES} values`);
  }
  if (depth > MAX_DEPTH) {
    throw new PayloadNotCanonical(`${path} is nested deeper than ${MAX_DEPTH}`);
  }
  if (value === null) return null;

  switch (typeof value) {
    case "boolean":
    case "string":
      return value;
    case "number":
      if (!Number.isFinite(value)) {
        throw new PayloadNotCanonical(`${path} is ${String(value)}, which JSON cannot represent`);
      }
      if (Object.is(value, -0)) {
        throw new PayloadNotCanonical(`${path} is negative zero; use 0, or carry the sign another way`);
      }
      return value;
    case "object":
      break;
    default:
      throw new PayloadNotCanonical(
        `${path} is ${describeType(value)}, which is not JSON; convert it before hashing`,
      );
  }

  const object = value as object;
  if (seen.includes(object)) {
    throw new PayloadNotCanonical(`${path} is part of a cycle, which cannot be hashed`);
  }
  const nested = [...seen, object];

  if (Array.isArray(object)) {
    assertPlainArray(object, path);
    const out: JsonValue[] = [];
    for (let i = 0; i < object.length; i++) {
      if (!(i in object)) {
        throw new PayloadNotCanonical(`${path}[${i}] is a hole; JSON arrays have no absent positions`);
      }
      out.push(copy(object[i] as unknown, nested, `${path}[${i}]`, depth + 1, state));
    }
    return Object.freeze(out);
  }

  // Without this a Date, Map or Set snapshots to `{}` — no privilege escalation,
  // since the handler acts on that same `{}`, but silent and total data loss for
  // a caller who meant to authorize a specific value. Refusing says so.
  const proto = Object.getPrototypeOf(object);
  if (proto !== Object.prototype && proto !== null) {
    throw new PayloadNotCanonical(
      `${path} is ${describeType(object)}, which is not JSON; convert it before hashing`,
    );
  }
  assertPlainData(object, path);
  const out: Record<string, JsonValue> = {};
  // Sorted on the way in, so the snapshot itself is canonical.
  for (const key of Object.keys(object).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))) {
    const copied = copy(
      (object as Record<string, unknown>)[key],
      nested,
      `${path}.${key}`,
      depth + 1,
      state,
    );
    // defineProperty, never `out[key] = ...`. For a key of "__proto__" — which
    // `JSON.parse` produces as an ordinary own property — assignment runs the
    // legacy prototype setter instead of creating one. The value would vanish
    // from the snapshot and from the digest while remaining readable by the
    // handler through the prototype: attacker-controlled data outside the
    // signature, which is the exact thing the snapshot exists to prevent.
    Object.defineProperty(out, key, {
      value: copied,
      enumerable: true,
      writable: false,
      configurable: false,
    });
  }
  return Object.freeze(out);
}

/** Refuses anything an array carries besides its elements. */
function assertPlainArray(array: unknown[], path: string): void {
  if (Object.getOwnPropertySymbols(array).length > 0) {
    throw new PayloadNotCanonical(`${path} has symbol-keyed properties, which are not JSON`);
  }
  for (const key of Object.getOwnPropertyNames(array)) {
    if (key === "length") continue;
    const index = Number(key);
    if (!Number.isInteger(index) || index < 0 || index >= array.length) {
      throw new PayloadNotCanonical(`${path}.${key} is a property on an array, which is not JSON data`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(array, key)!;
    if (descriptor.get !== undefined || descriptor.set !== undefined) {
      throw new PayloadNotCanonical(`${path}[${index}] is an accessor; pass a plain value`);
    }
  }
}

/** Serializes an owned snapshot. Keys are already sorted by `copy`. */
function serialize(value: JsonValue): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(serialize).join(",") + "]";
  // getOwnPropertyNames, not Object.entries: both see an own "__proto__", but
  // being explicit here keeps the serializer honest if the snapshot's shape ever
  // changes. Keys are already sorted by `copy`.
  return (
    "{" +
    Object.getOwnPropertyNames(value)
      .map((k) => JSON.stringify(k) + ":" + serialize((value as Record<string, JsonValue>)[k]!))
      .join(",") +
    "}"
  );
}
