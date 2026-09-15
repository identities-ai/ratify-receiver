import { buildSessionContext, operationContextHash } from "@identities-ai/ratify-protocol";
import { bindPayload } from "./canonical.js";
import {
  ReceiverRefusal,
  VerifyError,
  recordOutcomeReportError,
  type Decision,
  type DecisionResult,
  type GuardOptions,
  type GuardResult,
  type BoundAction,
  type HandlerContext,
  type JsonValue,
  type Outcome,
  type ProtectedAction,
  type ReceiverConfig,
} from "./types.js";

const DEFAULT_BASE_URL = "https://api.ratifyprotocol.com/v1";

function base64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/**
 * Guards a protected handler with Ratify Verify.
 *
 * The one property worth designing around is that the handler must be
 * unreachable except through an allow. A receiver that verifies and then forgets
 * to branch on the result is indistinguishable from one that never verified, and
 * it looks correct in every test that only inspects decisions. So the handler is
 * passed to `guard` rather than called by the integrator: there is no ordering
 * for a caller to get wrong, and `handlerInvoked` makes the property assertable.
 *
 *   const receiver = new RatifyReceiver({ apiKey, verifierId, workspaceId });
 *   const { challenge, sessionContext } = await receiver.challenge(action);
 *   // ... the agent signs `challenge` over `sessionContext` and returns a proof
 *   const result = await receiver.guard(action, proof, () => deploy(...));
 *
 * `decide` is available for receivers that must own the branch themselves. It
 * returns the same decision without running anything.
 */
export class RatifyReceiver {
  private readonly baseUrl: string;
  private readonly http: typeof globalThis.fetch;
  // Captured here, never re-read from `config`. The object belongs to the
  // caller and stays mutable: reading `verifierId` while binding and again
  // while building the request would let a session context be signed for one
  // identity and sent under another, with the API key belonging to a third.
  // Same defect as the payload and the action envelope, one level further out.
  private readonly apiKey: string;
  private readonly verifierId: string;
  private readonly workspaceId: string;

  constructor(config: ReceiverConfig) {
    if (!config.apiKey) throw new Error("apiKey is required");
    if (!config.verifierId) throw new Error("verifierId is required");
    if (!config.workspaceId) throw new Error("workspaceId is required");
    this.apiKey = config.apiKey;
    this.verifierId = config.verifierId;
    this.workspaceId = config.workspaceId;
    this.baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.http = config.fetch ?? globalThis.fetch;
  }

  /**
   * The operation binding for an action. Every field is folded into a hash the
   * agent signs, so this is what makes a presentation specific to one action
   * rather than transferable to another.
   */
  private binding(action: ProtectedAction) {
    // The whole action is read once, here, and nothing downstream touches the
    // caller's object again. The payload was the case the review found, but the
    // envelope has the same shape: `invocationId` was read once for the decision
    // and again, after two awaits, to report the outcome, so a handler that
    // changed it filed its result against an invocation nobody had decided.
    // Frozen here, and this exact object is what the handler receives. Building
    // a fresh copy for the handler instead left it mutable: a handler could
    // rewrite `resourceId` after authorization and act on the new one, which is
    // the authorized-versus-executed gap the payload snapshot closed.
    const boundAction: BoundAction = Object.freeze({
      action: action.action,
      requiredScope: action.requiredScope,
      resourceId: action.resourceId,
      requestedPath: action.requestedPath ?? "",
      agentId: action.agentId,
      sessionId: action.sessionId,
      invocationId: action.invocationId,
    });
    const bound = { ...boundAction, boundAction, actionProfile: action.actionProfile };
    const { snapshot, digest } = bindPayload(action.payload);
    const requestHash = operationContextHash({
      required_scope: bound.requiredScope,
      operation: bound.action,
      resource_id: bound.resourceId,
      requested_path: bound.requestedPath,
      payload_digest: digest,
    });
    const sessionContext = buildSessionContext({
      verifier_id: this.verifierId,
      workspace_id: this.workspaceId,
      agent_id: bound.agentId,
      session_id: bound.sessionId,
      invocation_id: bound.invocationId,
      request_hash: requestHash,
    });
    return Object.freeze({ ...bound, requestHash, sessionContext, snapshot, digest });
  }

  /**
   * A fresh challenge, and the session context the agent must sign it over.
   * Hand both to the agent; it cannot produce an acceptable presentation for a
   * different action, because the context commits to this one.
   */
  async challenge(action: ProtectedAction): Promise<{ challenge: string; sessionContext: string }> {
    const { sessionContext } = this.binding(action);
    const body = await this.request("POST", "/ratify/challenge", undefined);
    return {
      // Without this, a missing field becomes the literal string "undefined"
      // and the agent signs a challenge the server never issued.
      challenge: requireString(body, "challenge"),
      sessionContext: base64(sessionContext),
    };
  }

  /** Ask Ratify to decide, without running anything. */
  async decide(action: ProtectedAction, proofBundle: unknown): Promise<DecisionResult> {
    return this.decideBound(this.binding(action), proofBundle);
  }

  /** Decides on an already-bound action, so nothing re-reads the caller's object. */
  private async decideBound(
    bound: ReturnType<RatifyReceiver["binding"]>,
    proofBundle: unknown,
  ): Promise<DecisionResult> {
    const { requestHash, snapshot, digest } = bound;
    const body = await this.request("POST", "/ratify/verify", {
      required_scope: bound.requiredScope,
      proof_bundle: proofBundle,
      operation: {
        verifier_id: this.verifierId,
        workspace_id: this.workspaceId,
        agent_id: bound.agentId,
        action: bound.action,
        resource_id: bound.resourceId,
        requested_path: bound.requestedPath,
        payload_digest: base64(digest ?? new Uint8Array()),
        session_id: bound.sessionId,
        invocation_id: bound.invocationId,
        request_hash: base64(requestHash),
        action_profile: bound.actionProfile,
      },
    });

    // A 200 is not yet a decision. The handler runs on the strength of this
    // object, so every field it is trusted for is checked before it can be one:
    // a truncated or wrong-shaped body must fail closed, not authorize on a
    // stray "allow" with nothing behind it.
    const decision = requireDecision(body);
    const receipt = body.receipt;
    if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) {
      throw malformed("verify response has no receipt object");
    }
    const receiptFields = receipt as Record<string, unknown>;
    return Object.freeze({
      // Only an explicit allow permits the action. Anything else — deny,
      // indeterminate, a deferred approval, or a decision this version does not
      // recognise — leaves the handler unreached.
      allowed: decision === "allow",
      decision,
      reason: requireOptionalString(body, "decision_reason"),
      identityStatus: requireString(body, "identity_status"),
      receiptId: requireString(receiptFields, "receipt_id"),
      receiptHash: requireString(body, "receipt_hash"),
      // Validated, not coerced. `body.replayed === true` reads "true", 1 and {}
      // as false, and false here means the handler runs — so a malformed or
      // hostile response could turn the replay guard off silently. Replay
      // handling exists to stop a second consequential action; it may not be
      // switched off by a value nobody checked.
      replayed: requireOptionalBoolean(body, "replayed"),
      receipt: deepFreeze(receiptFields),
      boundPayload: snapshot,
    });
  }

  /**
   * Decide, and run `handler` only on an allow that has not already been given.
   *
   * Two things keep the handler unreachable. A decision that is not an explicit
   * `allow` never reaches it. And neither does a **replayed** allow: Ratify
   * answers a known `invocationId` from the record, and that response does not
   * say whether the handler ran last time, so a receiver that retried after a
   * crash would otherwise act twice on one authorization. `onReplay: "run"`
   * opts out; a real re-attempt should use a new `invocationId` instead.
   *
   * The outcome is reported back to Ratify afterwards so the decision and what
   * followed it can be read together. Reporting is observation: if it fails, the
   * handler's result still stands and the failure is returned on
   * `outcomeReportError` rather than replacing the result.
   *
   * A handler that throws `ReceiverRefusal` records `refused_by_receiver` — the
   * receiver's own policy declining something Ratify allowed. Both facts are
   * kept; neither rewrites the other.
   *
   * **A throwing handler rethrows, so there is no `GuardResult` on that path.**
   * The outcome has already been reported by then, so the fact that the handler
   * ran is recorded server-side even though the caller sees only the error. Any
   * error out of `guard` after an allow came from the handler; a `VerifyError`
   * raised before one means verification itself failed and nothing ran.
   */
  async guard<T>(
    action: ProtectedAction,
    proofBundle: unknown,
    handler: (context: HandlerContext) => Promise<T> | T,
    options: GuardOptions = {},
  ): Promise<GuardResult<T>> {
    // Read before the first await, like everything else the caller owns. The
    // options object can be shared, and a task that flipped `onReplay` to "run"
    // while verification was in flight would get a handler execution the caller
    // never asked for. Same race as the payload, the action envelope and the
    // configuration — this was the last instance.
    const onReplay = options.onReplay ?? "skip";
    const bound = this.binding(action);
    const decision = await this.decideBound(bound, proofBundle);
    if (!decision.allowed) {
      return { status: "refused", decision, handlerInvoked: false };
    }
    if (decision.replayed && onReplay !== "run") {
      // Allowed, but decided earlier, and the response does not say whether the
      // handler ran. Nothing is reported: this attempt did not act, and the
      // invocation that did carries the only outcome the record can hold.
      return { status: "replayed", decision, handlerInvoked: false };
    }

    let outcome: Outcome = "executed";
    // Separate from `thrown`, because `throw undefined` is a real thing a
    // handler can do and would otherwise read as "nothing was thrown" — the one
    // case where a failure would be reported to Ratify and then returned to the
    // caller as a success.
    let didThrow = false;
    let thrown: unknown;
    let value: T | undefined;
    try {
      // The container, not just its contents. Freezing every nested value and
      // leaving the object holding them mutable lets a handler overwrite
      // `invocationId` or `receiptId` and pass the context on -- so the
      // downstream idempotency key or the receipt an action is correlated to is
      // not the authorized one. Ratify's own outcome report is unaffected, since
      // it uses the bound values directly; the integration contract was not.
      const context: HandlerContext = Object.freeze({
        invocationId: bound.invocationId,
        action: bound.boundAction,
        receiptId: decision.receiptId,
        decision,
        payload: decision.boundPayload,
      });
      value = await handler(context);
    } catch (error) {
      didThrow = true;
      thrown = error;
      outcome = isRefusal(error) ? "refused_by_receiver" : "failed";
    }

    const outcomeReportError = await this.reportOutcome(
      bound.invocationId,
      decision.receiptId,
      outcome,
      describe(didThrow, thrown),
    );

    if (didThrow) {
      // The handler's own error is what the caller must see, so it is rethrown
      // unwrapped. But a lost outcome report is exactly as important here as on
      // the success path — more so, since this is the decision whose aftermath
      // an auditor will ask about — so it travels with the error rather than
      // being dropped. Read it with `outcomeReportErrorOf(error)`.
      // Always recorded, including when reporting succeeded: passing undefined
      // clears any association left by an earlier throw of this same object.
      recordOutcomeReportError(thrown, outcomeReportError);
      throw thrown;
    }
    return { status: "executed", decision, handlerInvoked: true, value, outcomeReportError };
  }

  /**
   * Tell Ratify what the receiver did. Never signed by Ratify, and never
   * evidence that the action occurred — it is the receiver's own account.
   *
   * Best effort by design: a receiver that already ran its handler must not have
   * that undone because a reporting call failed. So this never throws — but it
   * returns the failure rather than discarding it, because a decision whose
   * outcome was lost is worth alerting on and is invisible otherwise.
   */
  async reportOutcome(
    invocationId: string,
    receiptId: string,
    outcome: Outcome,
    detail?: string,
  ): Promise<Error | undefined> {
    if (!receiptId) {
      return new Error("no receipt_id: the decision carried none, so no outcome can be correlated");
    }
    try {
      await this.request("POST", `/ratify/invocations/${encodeURIComponent(invocationId)}/outcome`, {
        outcome,
        receipt_id: receiptId,
        detail,
        occurred_at: new Date().toISOString(),
      });
      return undefined;
    } catch (error) {
      // Returned, never thrown. See the method comment.
      return error instanceof Error ? error : new Error(String(error));
    }
  }

  private async request(
    method: string,
    path: string,
    body: unknown,
  ): Promise<Record<string, unknown>> {
    const response = await this.http(this.baseUrl + path, {
      method,
      headers: {
        "X-Ratify-API-Key": this.apiKey,
        "Content-Type": "application/json",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let parsed: Record<string, unknown>;
    try {
      // `null`, `[]` and `"a string"` are all valid JSON and none of them is a
      // response. Rejecting them here keeps every caller below working with an
      // object, rather than turning a bad body into a TypeError on first access.
      const decoded: unknown = text ? JSON.parse(text) : {};
      if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
        throw new SyntaxError("not a JSON object");
      }
      parsed = decoded as Record<string, unknown>;
    } catch {
      // A proxy or load balancer answering with HTML is still a failed verify,
      // and a caller that catches VerifyError should not have a SyntaxError
      // reach it instead with no status or code to branch on.
      throw new VerifyError(
        `Verify returned a body that is not a JSON object (HTTP ${response.status})`,
        response.status,
        "malformed_response",
      );
    }
    if (!response.ok) {
      const raw = parsed.error;
      const envelope: Record<string, unknown> =
        typeof raw === "object" && raw !== null && !Array.isArray(raw)
          ? (raw as Record<string, unknown>)
          : {};
      // A failure path must not fail. These come off the wire, so anything that
      // is not already a string is reported as absent rather than coerced.
      throw new VerifyError(
        typeof envelope.message === "string" ? envelope.message : response.statusText,
        response.status,
        typeof envelope.code === "string" ? envelope.code : "unknown",
      );
    }
    return parsed;
  }
}

/**
 * A short description of a thrown value, for the outcome record. Never throws.
 *
 * The value is the handler's and may be hostile: a `message` getter that throws,
 * a `Symbol.toPrimitive` that throws, a revoked proxy. Any of those would
 * propagate from here — replacing the caller's own error with ours, and skipping
 * the outcome report entirely, which are the two things this path promises not
 * to do.
 */
function describe(didThrow: boolean, thrown: unknown): string | undefined {
  if (!didThrow) return undefined;
  try {
    const message = isRefusal(thrown) || thrown instanceof Error ? (thrown as Error).message : String(thrown);
    // The outcome store bounds detail at 500 characters.
    return typeof message === "string" ? message.slice(0, 500) : "handler threw a non-describable value";
  } catch {
    return "handler threw a non-describable value";
  }
}

/**
 * Whether a thrown value is the receiver's own refusal. Never throws.
 *
 * `instanceof` walks the prototype chain, which throws for a revoked proxy.
 * Getting that wrong misreports the outcome; letting it propagate replaces the
 * caller's error.
 */
function isRefusal(thrown: unknown): boolean {
  try {
    return thrown instanceof ReceiverRefusal;
  } catch {
    return false;
  }
}

/**
 * Freezes a parsed JSON value through. The receipt is evidence, and evidence a
 * handler can edit before passing it on is not evidence.
 */
function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const key of Object.getOwnPropertyNames(value)) {
    deepFreeze((value as Record<string, unknown>)[key]);
  }
  return Object.freeze(value);
}

function malformed(message: string): VerifyError {
  return new VerifyError(message, 200, "malformed_response");
}

const DECISIONS: readonly Decision[] = ["allow", "deny", "indeterminate", "defer"];

/**
 * The decision, checked against the union it is declared to be.
 *
 * Casting an arbitrary string to `Decision` fails closed — it is not "allow" —
 * but hands the caller a value their exhaustive switch does not cover, and hides
 * an incompatible or corrupted server behind something that looks like a
 * refusal. A decision this version cannot name is a response worth surfacing,
 * not one to quietly bucket as "no".
 */
function requireDecision(body: Record<string, unknown>): Decision {
  const value = requireString(body, "decision");
  if (!(DECISIONS as readonly string[]).includes(value)) {
    throw malformed(`verify returned decision "${value}", which this version does not recognise`);
  }
  return value as Decision;
}

/**
 * A field that may be absent, but may not be the wrong type.
 *
 * Absent means the key is missing. `null` is a value, and a present value of the
 * wrong type is a malformed response, not an absent field — accepting it would
 * mean an allow whose reason was silently discarded.
 */
function requireOptionalString(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (value === undefined) return "";
  if (typeof value !== "string") {
    throw malformed(`verify response field "${field}" is not a string`);
  }
  return value;
}

/**
 * A boolean that may be absent. Only a missing key is absent.
 *
 * `null` is not a boolean and must not read as `false`, because `false` here
 * means the handler runs: treating it as absent lets a malformed response switch
 * replay protection off, which is the fail-open case this field exists to
 * prevent.
 */
function requireOptionalBoolean(body: Record<string, unknown>, field: string): boolean {
  const value = body[field];
  if (value === undefined) return false;
  if (typeof value !== "boolean") {
    throw malformed(`verify response field "${field}" is not a boolean`);
  }
  return value;
}

/** A field the caller is trusted to have, checked before it is trusted. */
function requireString(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (typeof value !== "string" || value === "") {
    throw malformed(`verify response field "${field}" is missing or not a string`);
  }
  return value;
}
