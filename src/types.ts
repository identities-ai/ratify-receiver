/**
 * JSON, and only JSON. A payload digest binds an action, so it may not contain
 * values whose serialization we would have to guess at.
 *
 * Read-only because the bound snapshot a handler receives is deeply frozen: the
 * value that was authorized cannot be changed before it is acted on. A mutable
 * array or object is still assignable *into* this type, so building a payload
 * is unaffected.
 */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

/** How the receiver reaches Ratify Verify. */
export interface ReceiverConfig {
  /** Receiver integration API key. Identifies the integration; never a path parameter. */
  apiKey: string;
  /** The stable verifier identity registered for this integration. */
  verifierId: string;
  /** The organization this receiver belongs to. Must be the workspace UUID. */
  workspaceId: string;
  /** Defaults to the hosted API. */
  baseUrl?: string;
  /** Injectable for tests and for callers with their own HTTP stack. */
  fetch?: typeof globalThis.fetch;
}

/**
 * One consequential action, canonicalized by the receiver.
 *
 * Every field here is bound into the proof the agent signs, so changing any of
 * them after the challenge was issued invalidates the presentation rather than
 * silently authorizing a different action.
 */
export interface ProtectedAction {
  /** Action type, e.g. "github.deploy". */
  action: string;
  /** The scope this action requires, e.g. "custom:github:deploy". */
  requiredScope: string;
  /** The resource being acted on, e.g. "github:acme/payments". */
  resourceId: string;
  /** Path within the resource, e.g. "/services/payments/environments/staging". */
  requestedPath?: string;
  /**
   * The request body, if any. Hashed with `canonicalJSON`; the raw value never
   * leaves the receiver and is never sent to Ratify.
   *
   * JSON only. A `Date`, `Map`, class instance or function throws
   * `PayloadNotCanonical` rather than being coerced, because coercion is how two
   * different payloads end up authorizing each other.
   */
  payload?: JsonValue;
  /** The agent the receiver expects to present. */
  agentId: string;
  /** Groups related invocations. */
  sessionId: string;
  /** Unique per attempt. Reusing it with different inputs is a conflict. */
  invocationId: string;
  /**
   * The versioned canonicalization contract this action was built with, e.g.
   * `github.deploy/v1`.
   *
   * Ratify cannot check it — the receiver owns canonicalization — so it is
   * recorded, not validated. Its value is on the receipt afterwards: a request
   * hash is opaque, and without the profile that produced it a stored decision
   * cannot be reproduced or even interpreted once the contract changes. A
   * receiver that revises how it builds a hash must issue a new version rather
   * than silently changing what v1 meant.
   */
  actionProfile?: string;
}

export type Decision = "allow" | "deny" | "indeterminate" | "defer";

/** What Ratify decided, and the evidence for it. */
export interface DecisionResult {
  allowed: boolean;
  decision: Decision;
  reason: string;
  identityStatus: string;
  receiptId: string;
  receiptHash: string;
  /** The decision was recorded earlier and returned from the record. */
  replayed: boolean;
  receipt: Record<string, unknown>;
  /**
   * The frozen snapshot this decision was made about.
   *
   * `guard` hands it to the handler for you. It is here for callers who use
   * `decide` and own the branch themselves: act on this, not on the object you
   * passed in, which is mutable and may since have changed.
   */
  boundPayload: JsonValue | undefined;
}

export type Outcome = "executed" | "failed" | "refused_by_receiver" | "not_attempted";

/**
 * What `guard` did. Branch on this, not on the decision.
 *
 * - `executed` — Ratify allowed and the handler ran to completion.
 * - `refused` — Ratify did not allow. Nothing ran.
 * - `replayed` — Ratify allowed, but answered from a decision it had already
 *   recorded. **Whether the action previously ran is unknown**, so nothing ran
 *   now. This is not a success: see the reconciliation note on `GuardResult`.
 *
 * There is deliberately no `allowed` boolean on the result. A replayed allow is
 * authorized and did not run, and one boolean cannot say both — an integrator
 * reading it as "did my action happen" would acknowledge work that never
 * occurred.
 */
export type GuardStatus = "executed" | "refused" | "replayed";

export interface GuardOptions {
  /**
   * What to do when Ratify answers from an earlier recorded decision.
   *
   * Defaults to `"skip"`. A replayed allow means this invocation was already
   * decided, and the verify response does not say whether the handler ran, so
   * re-running it would risk acting twice on one authorization. Skipping can
   * only fail to repeat an action; running can only repeat one, and for a
   * consequential action those are not equally bad.
   *
   * To genuinely re-attempt an action, issue a **new `invocationId`**: the
   * earlier one is bound to a challenge that has already been spent. Use
   * `"run"` only for a handler that is itself idempotent.
   */
  onReplay?: "skip" | "run";
}

/**
 * The action exactly as it was bound and signed.
 *
 * Normalized, which matters for `requestedPath`: the protocol types it as a
 * plain string in Go and TypeScript, the server decodes it the same way, and
 * OpenAPI marks it required — so the wire format has no way to say "absent".
 * An omitted path and an explicit `""` are one operation and share a signature,
 * which is why this is handed to the handler. Reading `requestedPath` off the
 * object you passed in would let you branch on a difference the signature does
 * not carry.
 */
export interface BoundAction {
  action: string;
  requiredScope: string;
  resourceId: string;
  /** Normalized: an omitted path is `""`, and the two are indistinguishable. */
  requestedPath: string;
  agentId: string;
  sessionId: string;
  invocationId: string;
}

/** What a protected handler is told about the action it is running under. */
export interface HandlerContext {
  /**
   * Use this as the idempotency key of whatever the handler calls downstream.
   *
   * Ratify decides at most once per invocation, but it cannot know whether your
   * handler ran, so at-most-once end to end is only achievable if the thing you
   * call can recognise a repeat. Passing this through is what makes a
   * `replayed` result reconcilable instead of merely alarming.
   */
  invocationId: string;
  /** The receipt this action is evidence against. */
  receiptId: string;
  /**
   * **The action that was authorized. Read fields from here, not from the object
   * you passed in**, for the same reason `payload` exists: the caller's object is
   * mutable and carries distinctions the signature does not.
   */
  action: BoundAction;
  /** The full decision, for a handler that needs the reason or the receipt. */
  decision: DecisionResult;
  /**
   * **The payload that was authorized. Act on this, not on the object you
   * passed in.**
   *
   * It is an owned, deeply frozen snapshot taken before the digest was
   * computed, so it is exactly the value Ratify decided about. The object you
   * handed to `guard` is still mutable and may have changed while the verify
   * request was in flight — reading it here would be acting on a payload that
   * was never authorized.
   */
  payload: JsonValue | undefined;
}

export interface GuardResult<T> {
  /** What `guard` did. Branch on this. */
  status: GuardStatus;
  decision: DecisionResult;
  /** Whether the protected handler actually ran. Assert on this in tests. */
  handlerInvoked: boolean;
  /** The handler's return value. Present only when it ran and completed. */
  value?: T;
  /**
   * The outcome report failed after the handler ran.
   *
   * Reporting is observation, so a failure here never undoes the handler and
   * never becomes a thrown error. It surfaces so a receiver can alert on a
   * decision whose outcome was lost rather than discover the gap in an audit.
   *
   * When the handler itself threw, this is attached to the thrown error instead
   * — read it with `outcomeReportErrorOf(error)`.
   */
  outcomeReportError?: Error;
}

/** Thrown by a handler whose own policy refuses an action Ratify allowed. */
export class ReceiverRefusal extends Error {
  constructor(message = "refused by receiver policy") {
    super(message);
    this.name = "ReceiverRefusal";
  }
}

/**
 * A payload that cannot be canonicalized, and so cannot be hashed.
 *
 * Thrown rather than coerced: a digest is an authorization binding, and a
 * serializer that turns every unsupported value into `{}` lets two different
 * payloads authorize each other.
 */
export class PayloadNotCanonical extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PayloadNotCanonical";
  }
}

/** A Verify call that never reached a decision. */
export class VerifyError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
  ) {
    super(message);
    this.name = "VerifyError";
  }
}

/**
 * Outcome-report failures recorded against the handler errors they accompany.
 *
 * A WeakMap rather than a property on the error, because the thrown value is the
 * caller's and may be frozen, sealed or otherwise non-extensible.
 * `Object.defineProperty` throws on those, and it would throw *while* `guard` is
 * rethrowing — replacing the handler's own error with a TypeError about our
 * bookkeeping, which is the one thing the rethrow promises not to do.
 *
 * The consequence is that a non-object throw (a thrown string) carries no
 * report, since a WeakMap cannot key one. That is the honest limit: there is
 * nowhere on a primitive to put it, and inventing a wrapper would lose the
 * caller's value.
 */
const outcomeReportErrors = new WeakMap<object, Error>();

/**
 * Records this attempt's reporting outcome against a thrown value. Never throws.
 *
 * `reportError` of `undefined` **clears** any earlier association, and the
 * success path must call it that way. A handler can throw the same object twice
 * — a module-level singleton, or a retry rethrowing what it caught — and without
 * clearing, a run whose reporting succeeded would still answer with the previous
 * run's failure. Audit metadata that is confidently wrong is worse than absent.
 *
 * Two guards that throw the *same* object concurrently still race, and the last
 * write wins; carry a distinct error per invocation if that matters to you.
 */
export function recordOutcomeReportError(thrown: unknown, reportError: Error | undefined): void {
  if (typeof thrown !== "object" || thrown === null) return;
  if (reportError === undefined) {
    outcomeReportErrors.delete(thrown);
    return;
  }
  outcomeReportErrors.set(thrown, reportError);
}

/** The outcome-report failure recorded against a thrown handler error, if any. */
export function outcomeReportErrorOf(error: unknown): Error | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  return outcomeReportErrors.get(error);
}
