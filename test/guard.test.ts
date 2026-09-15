import assert from "node:assert/strict";
import test from "node:test";
import {
  RatifyReceiver,
  type HandlerContext,
  ReceiverRefusal,
  VerifyError,
  outcomeReportErrorOf,
  type ProtectedAction,
} from "../src/index.js";

const action: ProtectedAction = {
  action: "github.deploy",
  requiredScope: "custom:github:deploy",
  resourceId: "github:acme/payments",
  requestedPath: "/services/payments/environments/staging",
  payload: { artifact_digest: "sha256:abc" },
  agentId: "agent-1",
  sessionId: "session-1",
  invocationId: "inv-1",
};

interface Call {
  url: string;
  body: Record<string, unknown> | undefined;
}

/** A Verify stand-in that records what the helper sent and replies as told. */
function stubTransport(replies: Record<string, { status: number; body: unknown }>) {
  const calls: Call[] = [];
  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    const href = String(url);
    calls.push({
      url: href,
      body: init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined,
    });
    const key = Object.keys(replies).find((k) => href.endsWith(k));
    const reply = key ? replies[key]! : { status: 200, body: {} };
    return new Response(JSON.stringify(reply.body), {
      status: reply.status,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof globalThis.fetch;
  return { calls, fetchImpl };
}

function receiverWith(replies: Record<string, { status: number; body: unknown }>) {
  const { calls, fetchImpl } = stubTransport(replies);
  const receiver = new RatifyReceiver({
    apiKey: "rat_test_key_0123456789",
    verifierId: "receiver:test",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: fetchImpl,
  });
  return { receiver, calls };
}

const allowReply = {
  status: 200,
  body: {
    decision: "allow",
    decision_reason: "authorized",
    identity_status: "authorized_agent",
    receipt_hash: "sha256:" + "a".repeat(64),
    receipt: { receipt_id: "11111111-1111-1111-1111-111111111111" },
  },
};

const replayedAllowReply = {
  status: 200,
  body: { ...allowReply.body, replayed: true },
};

function denyReply(reason: string, decision = "deny") {
  return {
    status: 200,
    body: {
      decision,
      decision_reason: reason,
      identity_status: "unauthorized",
      receipt_hash: "sha256:" + "b".repeat(64),
      receipt: { receipt_id: "22222222-2222-2222-2222-222222222222" },
    },
  };
}

test("an allow runs the handler exactly once", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  let invocations = 0;
  const result = await receiver.guard(action, {}, () => {
    invocations += 1;
    return "deployed";
  });
  assert.equal(result.status, "executed");
  assert.equal(result.handlerInvoked, true);
  assert.equal(result.value, "deployed");
  assert.equal(invocations, 1);
});

// The property the whole helper exists for. Asserting on the decision alone
// would pass against a gate that never gated; the invocation count is what
// distinguishes them.
test("no decision other than allow reaches the handler", async () => {
  for (const [decision, reason] of [
    ["deny", "untrusted_root"],
    ["deny", "delegation_revoked"],
    ["deny", "constraint_denied"],
    ["indeterminate", "revocation_state_unavailable"],
    ["defer", "hitl_pending"],
  ] as const) {
    const { receiver } = receiverWith({ "/ratify/verify": denyReply(reason, decision) });
    let invocations = 0;
    const result = await receiver.guard(action, {}, () => {
      invocations += 1;
    });
    assert.equal(invocations, 0, `${decision}/${reason} reached the handler`);
    assert.equal(result.handlerInvoked, false);
    assert.equal(result.status, "refused");
  }
});

test("a refused decision reports no outcome, because nothing happened", async () => {
  const { receiver, calls } = receiverWith({ "/ratify/verify": denyReply("untrusted_root") });
  await receiver.guard(action, {}, () => {});
  assert.equal(calls.filter((c) => c.url.includes("/outcome")).length, 0);
});

test("a completed handler reports executed", async () => {
  const { receiver, calls } = receiverWith({ "/ratify/verify": allowReply });
  await receiver.guard(action, {}, () => "ok");
  const outcome = calls.find((c) => c.url.includes("/outcome"));
  assert.ok(outcome, "no outcome was reported");
  assert.equal(outcome.body?.outcome, "executed");
  assert.equal(outcome.body?.receipt_id, "11111111-1111-1111-1111-111111111111");
});

test("a throwing handler reports failed and rethrows", async () => {
  const { receiver, calls } = receiverWith({ "/ratify/verify": allowReply });
  await assert.rejects(
    receiver.guard(action, {}, () => {
      throw new Error("deploy exploded");
    }),
    /deploy exploded/,
  );
  const outcome = calls.find((c) => c.url.includes("/outcome"));
  assert.equal(outcome?.body?.outcome, "failed");
});

// Ratify allowed, the receiver's own policy did not. Both facts are kept.
test("a local refusal reports refused_by_receiver", async () => {
  const { receiver, calls } = receiverWith({ "/ratify/verify": allowReply });
  await assert.rejects(
    receiver.guard(action, {}, () => {
      throw new ReceiverRefusal("change freeze");
    }),
    /change freeze/,
  );
  const outcome = calls.find((c) => c.url.includes("/outcome"));
  assert.equal(outcome?.body?.outcome, "refused_by_receiver");
});

test("a failed outcome report does not undo a handler that already ran", async () => {
  const { receiver } = receiverWith({
    "/ratify/verify": allowReply,
    "/outcome": { status: 503, body: { error: { code: "outcome_store_unavailable" } } },
  });
  const result = await receiver.guard(action, {}, () => "shipped");
  assert.equal(result.handlerInvoked, true);
  assert.equal(result.value, "shipped");
});

test("a refusal before any decision leaves the handler unreached", async () => {
  const { receiver } = receiverWith({
    "/ratify/verify": { status: 403, body: { error: { code: "verifier_mismatch", message: "wrong receiver" } } },
  });
  let invocations = 0;
  await assert.rejects(
    receiver.guard(action, {}, () => {
      invocations += 1;
    }),
    (error: unknown) => error instanceof VerifyError && error.code === "verifier_mismatch",
  );
  assert.equal(invocations, 0);
});

// Ratify answers a known invocation_id from the record, and that response does
// not say whether the handler ran last time. A receiver that crashed mid-deploy
// and retried would otherwise deploy a second time on one authorization — the
// exact class of mistake passing the handler in was meant to remove.
test("a replayed allow does not run the handler", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": replayedAllowReply });
  let invocations = 0;
  const result = await receiver.guard(action, {}, () => {
    invocations += 1;
  });
  assert.equal(invocations, 0, "a replayed allow acted a second time");
  assert.equal(result.handlerInvoked, false);
  // Not a success: the action is authorized and did not run, and there is
  // deliberately no `allowed` boolean that could be read as "it happened".
  assert.equal(result.status, "replayed");
  assert.equal(result.decision.allowed, true);
  assert.equal(result.decision.replayed, true);
  assert.ok(!("allowed" in result), "a boolean that conflates authorized with executed came back");
});

test("a replayed skip reports no outcome, because this attempt did not act", async () => {
  const { receiver, calls } = receiverWith({ "/ratify/verify": replayedAllowReply });
  await receiver.guard(action, {}, () => {});
  assert.equal(calls.filter((c) => c.url.includes("/outcome")).length, 0);
});

test("a replayed allow runs the handler only when the caller opts in", async () => {
  const { receiver, calls } = receiverWith({ "/ratify/verify": replayedAllowReply });
  let invocations = 0;
  const result = await receiver.guard(
    action,
    {},
    () => {
      invocations += 1;
      return "redeployed";
    },
    { onReplay: "run" },
  );
  assert.equal(invocations, 1);
  assert.equal(result.handlerInvoked, true);
  assert.equal(result.status, "executed");
  assert.equal(result.value, "redeployed");
  assert.equal(calls.filter((c) => c.url.includes("/outcome")).length, 1);
});

// "skip" is the default because the two failure modes are not symmetric: a skip
// can only fail to repeat an action, a run can only repeat one.
test("skipping a replay is the default rather than something to opt into", async () => {
  for (const options of [undefined, {}, { onReplay: "skip" as const }]) {
    const { receiver } = receiverWith({ "/ratify/verify": replayedAllowReply });
    let invocations = 0;
    await receiver.guard(action, {}, () => void (invocations += 1), options);
    assert.equal(invocations, 0, `options ${JSON.stringify(options)} ran a replayed handler`);
  }
});

test("a fresh allow is unaffected by the replay guard", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  const result = await receiver.guard(action, {}, () => "deployed");
  assert.equal(result.handlerInvoked, true);
  assert.equal(result.status, "executed");
  assert.equal(result.decision.replayed, false);
});

test("a refusal says why the handler did not run", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": denyReply("untrusted_root") });
  const result = await receiver.guard(action, {}, () => {});
  assert.equal(result.status, "refused");
});

// A decision whose outcome was never recorded is invisible otherwise: the
// handler ran, and nothing anywhere says so.
test("a lost outcome report surfaces on the result instead of being discarded", async () => {
  const { receiver } = receiverWith({
    "/ratify/verify": allowReply,
    "/outcome": { status: 503, body: { error: { code: "outcome_store_unavailable", message: "down" } } },
  });
  const result = await receiver.guard(action, {}, () => "shipped");
  assert.equal(result.handlerInvoked, true);
  assert.equal(result.value, "shipped");
  assert.ok(result.outcomeReportError instanceof VerifyError, "the reporting failure was discarded");
  assert.equal((result.outcomeReportError as VerifyError).code, "outcome_store_unavailable");
});

test("a successful outcome report leaves no error behind", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  const result = await receiver.guard(action, {}, () => "shipped");
  assert.equal(result.outcomeReportError, undefined);
});

test("reporting an outcome never throws, whatever the transport does", async () => {
  const receiver = new RatifyReceiver({
    apiKey: "rat_test_key_0123456789",
    verifierId: "receiver:test",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: (() => Promise.reject(new TypeError("network down"))) as unknown as typeof globalThis.fetch,
  });
  const error = await receiver.reportOutcome("inv-1", "receipt-1", "executed");
  assert.ok(error instanceof Error);
  assert.match(error.message, /network down/);
});

test("an outcome with no receipt to correlate it is reported as an error", async () => {
  const { receiver, calls } = receiverWith({});
  const error = await receiver.reportOutcome("inv-1", "", "executed");
  assert.ok(error instanceof Error, "a missing receipt_id passed silently");
  assert.equal(calls.length, 0, "an uncorrelatable outcome was still sent");
});

// A proxy answering with HTML is still a failed verify. A SyntaxError reaching
// the caller instead carries no status and no code to branch on.
test("a non-JSON body is a VerifyError, not a parse error", async () => {
  const receiver = new RatifyReceiver({
    apiKey: "rat_test_key_0123456789",
    verifierId: "receiver:test",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: (async () =>
      new Response("<html><body>502 Bad Gateway</body></html>", {
        status: 502,
        headers: { "content-type": "text/html" },
      })) as unknown as typeof globalThis.fetch,
  });
  let invocations = 0;
  await assert.rejects(
    receiver.guard(action, {}, () => void (invocations += 1)),
    (error: unknown) =>
      error instanceof VerifyError && error.status === 502 && error.code === "malformed_response",
  );
  assert.equal(invocations, 0, "an unreadable response reached the handler");
});

test("a malformed 200 is a VerifyError too, not a decision", async () => {
  const receiver = new RatifyReceiver({
    apiKey: "rat_test_key_0123456789",
    verifierId: "receiver:test",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: (async () =>
      new Response("not json at all", { status: 200, headers: { "content-type": "application/json" } })) as unknown as typeof globalThis.fetch,
  });
  let invocations = 0;
  await assert.rejects(
    receiver.guard(action, {}, () => void (invocations += 1)),
    (error: unknown) => error instanceof VerifyError && error.code === "malformed_response",
  );
  assert.equal(invocations, 0);
});

// Reusing an invocation_id for a *different* action is a conflict, never an
// allow. It must not be mistaken for a replay: a replay is the same request
// answered again, a conflict is a different request wearing its name.
test("an invocation conflict is refused, not replayed", async () => {
  const { receiver } = receiverWith({
    "/ratify/verify": {
      status: 409,
      body: {
        error: {
          code: "invocation_conflict",
          message: "This invocation_id is already bound to a different request",
        },
      },
    },
  });
  let invocations = 0;
  await assert.rejects(
    receiver.guard(action, {}, () => void (invocations += 1)),
    (error: unknown) =>
      error instanceof VerifyError && error.status === 409 && error.code === "invocation_conflict",
  );
  assert.equal(invocations, 0, "a conflicting invocation reached the handler");
});

// Finding 4. The throwing path is where lost audit evidence matters most: it is
// the decision an auditor will ask about. Rethrowing the handler's own error is
// right, but the reporting failure must travel with it.
test("a lost outcome report survives a throwing handler", async () => {
  const { receiver } = receiverWith({
    "/ratify/verify": allowReply,
    "/outcome": { status: 503, body: { error: { code: "outcome_store_unavailable", message: "down" } } },
  });
  const thrown = await receiver
    .guard(action, {}, () => {
      throw new Error("deploy exploded");
    })
    .then(() => undefined, (error: unknown) => error);

  assert.ok(thrown instanceof Error);
  assert.equal(thrown.message, "deploy exploded", "the handler's own error was replaced");
  const reportError = outcomeReportErrorOf(thrown);
  assert.ok(reportError instanceof VerifyError, "the reporting failure was dropped on the throw path");
  assert.equal((reportError as VerifyError).code, "outcome_store_unavailable");
});

test("a handler that throws with reporting healthy carries no report error", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  const thrown = await receiver
    .guard(action, {}, () => {
      throw new Error("deploy exploded");
    })
    .then(() => undefined, (error: unknown) => error);
  assert.equal(outcomeReportErrorOf(thrown), undefined);
});

// Finding 5. `throw undefined` is legal. Using undefined as both "nothing was
// thrown" and the thrown value reported the failure to Ratify and then returned
// success to the caller.
test("a handler that throws undefined still fails", async () => {
  const { receiver, calls } = receiverWith({ "/ratify/verify": allowReply });
  let settled = "neither";
  await receiver.guard(action, {}, () => {
    throw undefined;
  }).then(() => (settled = "resolved"), () => (settled = "rejected"));

  assert.equal(settled, "rejected", "throwing undefined was reported as success");
  const outcome = calls.find((c) => c.url.includes("/outcome"));
  assert.equal(outcome?.body?.outcome, "failed");
});

test("a handler that returns undefined is still a success", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  const result = await receiver.guard(action, {}, () => undefined);
  assert.equal(result.status, "executed");
  assert.equal(result.handlerInvoked, true);
});

// Finding 3. At-most-once end to end is only reachable if what the handler calls
// downstream can recognise a repeat, so the key it needs is handed to it.
test("the handler is given the invocation id to use as its idempotency key", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  let seen: { invocationId?: string; receiptId?: string } = {};
  await receiver.guard(action, {}, (context) => {
    seen = context;
    return "ok";
  });
  assert.equal(seen.invocationId, "inv-1");
  assert.equal(seen.receiptId, "11111111-1111-1111-1111-111111111111");
});

// Finding 9. A 200 is not a decision. The handler runs on the strength of this
// object, so a truncated body must fail closed rather than authorize on a bare
// "allow" with no receipt behind it.
test("an allow with nothing behind it does not reach the handler", async () => {
  for (const [name, body] of [
    ["no receipt at all", { decision: "allow", identity_status: "ok", receipt_hash: "h" }],
    ["a receipt with no id", { decision: "allow", identity_status: "ok", receipt_hash: "h", receipt: {} }],
    ["no identity status", { decision: "allow", receipt_hash: "h", receipt: { receipt_id: "r" } }],
    ["no receipt hash", { decision: "allow", identity_status: "ok", receipt: { receipt_id: "r" } }],
    ["no decision", { identity_status: "ok", receipt_hash: "h", receipt: { receipt_id: "r" } }],
    ["a receipt that is an array", { decision: "allow", identity_status: "ok", receipt_hash: "h", receipt: [] }],
    ["a null body", null],
  ] as const) {
    const { receiver } = receiverWith({ "/ratify/verify": { status: 200, body } });
    let invocations = 0;
    await assert.rejects(
      receiver.guard(action, {}, () => void (invocations += 1)),
      (error: unknown) => error instanceof VerifyError && error.code === "malformed_response",
      `${name} was accepted as a decision`,
    );
    assert.equal(invocations, 0, `${name} reached the handler`);
  }
});

test("a challenge that is missing is an error, not the string undefined", async () => {
  const { receiver } = receiverWith({ "/ratify/challenge": { status: 200, body: {} } });
  await assert.rejects(
    receiver.challenge(action),
    (error: unknown) => error instanceof VerifyError && error.code === "malformed_response",
  );
});

// The context is the whole mechanism behind the reconciliation contract, so all
// of it is pinned, not just the key.
test("the handler context carries the decision it is running under", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  let seen: Record<string, unknown> = {};
  await receiver.guard(action, {}, (context) => {
    seen = context as unknown as Record<string, unknown>;
    return "ok";
  });
  assert.deepEqual(Object.keys(seen).sort(), ["action", "decision", "invocationId", "payload", "receiptId"]);
  assert.equal((seen.decision as { decision: string }).decision, "allow");
  assert.equal((seen.decision as { allowed: boolean }).allowed, true);
});

// An opt-in re-run still reports, and reports against the original receipt --
// which is the receipt the store will refuse a differing outcome against.
test("an opted-in replay reports against the original receipt", async () => {
  const { receiver, calls } = receiverWith({ "/ratify/verify": replayedAllowReply });
  await receiver.guard(action, {}, () => "redeployed", { onReplay: "run" });
  const outcome = calls.find((c) => c.url.includes("/outcome"));
  assert.equal(outcome?.body?.receipt_id, "11111111-1111-1111-1111-111111111111");
  assert.equal(outcome?.body?.outcome, "executed");
});

// A deferred approval is not a deny and not an allow. It must not reach the
// handler, and it must not be reported as a refusal that already happened.
test("a deferred approval is refused without reporting an outcome", async () => {
  const { receiver, calls } = receiverWith({ "/ratify/verify": denyReply("hitl_pending", "defer") });
  const result = await receiver.guard(action, {}, () => "ran");
  assert.equal(result.status, "refused");
  assert.equal(result.handlerInvoked, false);
  assert.equal(calls.filter((c) => c.url.includes("/outcome")).length, 0);
});

// Finding 3. Casting an arbitrary string to Decision fails closed -- it is not
// "allow" -- but hands the caller a value their exhaustive switch does not
// cover, and hides an incompatible server behind something that looks like an
// ordinary refusal.
test("a decision this version cannot name is surfaced, not bucketed as a refusal", async () => {
  for (const unknown of ["something_new", "ALLOW", "allow ", "approved"]) {
    const { receiver } = receiverWith({ "/ratify/verify": denyReply("from_a_later_version", unknown) });
    let invocations = 0;
    await assert.rejects(
      receiver.guard(action, {}, () => void (invocations += 1)),
      (error: unknown) =>
        error instanceof VerifyError && error.code === "malformed_response",
      `decision "${unknown}" was accepted`,
    );
    assert.equal(invocations, 0, `decision "${unknown}" reached the handler`);
  }
});

test("every decision the union declares is accepted", async () => {
  for (const decision of ["allow", "deny", "indeterminate", "defer"] as const) {
    const reply = decision === "allow" ? allowReply : denyReply("reason", decision);
    const { receiver } = receiverWith({ "/ratify/verify": reply });
    const result = await receiver.guard(action, {}, () => "ran");
    assert.equal(result.decision.decision, decision);
  }
});

// Finding 2. The thrown value belongs to the caller and may be non-extensible.
// Attaching to it with defineProperty throws *while* guard is rethrowing, which
// replaces the handler's own error with a TypeError about our bookkeeping --
// the one thing the rethrow promises not to do.
test("a frozen or sealed handler error is rethrown unchanged", async () => {
  for (const [name, makeError] of [
    ["frozen", () => Object.freeze(new Error("frozen boom"))],
    ["sealed", () => Object.seal(new Error("sealed boom"))],
    ["non-extensible", () => Object.preventExtensions(new Error("rigid boom"))],
    ["a frozen plain object", () => Object.freeze({ message: "object boom" })],
  ] as [string, () => unknown][]) {
    const { receiver } = receiverWith({
      "/ratify/verify": allowReply,
      "/outcome": { status: 503, body: { error: { code: "outcome_store_unavailable" } } },
    });
    const original = makeError();
    const thrown = await receiver
      .guard(action, {}, () => {
        throw original;
      })
      .then(() => undefined, (error: unknown) => error);

    assert.equal(thrown, original, `${name}: the handler's error was replaced`);
    // And the report still reaches the caller, without having touched the error.
    assert.ok(outcomeReportErrorOf(thrown) instanceof Error, `${name}: the report was lost`);
  }
});

test("attaching a report never mutates the thrown error", async () => {
  const { receiver } = receiverWith({
    "/ratify/verify": allowReply,
    "/outcome": { status: 503, body: { error: { code: "outcome_store_unavailable" } } },
  });
  const original = new Error("boom");
  const before = [...Object.getOwnPropertyNames(original), ...Object.getOwnPropertySymbols(original)];
  const thrown = await receiver
    .guard(action, {}, () => {
      throw original;
    })
    .then(() => undefined, (error: unknown) => error);
  const after = [...Object.getOwnPropertyNames(thrown as object), ...Object.getOwnPropertySymbols(thrown as object)];
  assert.deepEqual(after, before, "guard added a property to the caller's error");
});

// A primitive throw has nowhere to carry a report. Documented limit, pinned so
// it stays a known one rather than a surprise.
test("a primitive throw is rethrown unchanged and carries no report", async () => {
  const { receiver } = receiverWith({
    "/ratify/verify": allowReply,
    "/outcome": { status: 503, body: { error: { code: "outcome_store_unavailable" } } },
  });
  const thrown = await receiver
    .guard(action, {}, () => {
      throw "a string";
    })
    .then(() => undefined, (error: unknown) => error);
  assert.equal(thrown, "a string");
  assert.equal(outcomeReportErrorOf(thrown), undefined);
});

// Finding R3-2. A handler can throw the same object twice -- a module-level
// singleton, or a retry rethrowing what it caught. Recording only on failure
// left the first run's reporting error answering for the second run, which had
// reported fine. Audit metadata that is confidently wrong is worse than absent.
test("a later healthy report clears an earlier reporting failure", async () => {
  const singleton = new Error("the same error object twice");

  const failing = receiverWith({
    "/ratify/verify": allowReply,
    "/outcome": { status: 503, body: { error: { code: "outcome_store_unavailable" } } },
  });
  const first = await failing.receiver
    .guard(action, {}, () => { throw singleton; })
    .then(() => undefined, (e: unknown) => e);
  assert.ok(outcomeReportErrorOf(first) instanceof Error, "the failure was not recorded");

  const healthy = receiverWith({ "/ratify/verify": allowReply });
  const second = await healthy.receiver
    .guard(action, {}, () => { throw singleton; })
    .then(() => undefined, (e: unknown) => e);

  assert.equal(second, singleton);
  assert.equal(
    outcomeReportErrorOf(second),
    undefined,
    "a run whose reporting succeeded still answered with the previous run's failure",
  );
});

test("a reporting failure is scoped to the error it accompanied", async () => {
  const { receiver } = receiverWith({
    "/ratify/verify": allowReply,
    "/outcome": { status: 503, body: { error: { code: "outcome_store_unavailable" } } },
  });
  const failed = await receiver
    .guard(action, {}, () => { throw new Error("one"); })
    .then(() => undefined, (e: unknown) => e);
  assert.ok(outcomeReportErrorOf(failed) instanceof Error);
  // An unrelated error never passed through guard carries nothing.
  assert.equal(outcomeReportErrorOf(new Error("two")), undefined);
});

// Finding R4-2. The caller's object stays mutable. Hashing it, awaiting a
// network round trip, then running a handler that reads it again is a
// time-of-check to time-of-use gap: the payload said "staging" when it was
// authorized and "production" when the handler ran. The snapshot is the fix --
// the handler is given the value that was hashed, not the object it came from.
test("a payload that mutates during verification cannot change what is acted on", async () => {
  const payload = { target: "staging" };
  let actedOn: unknown;
  const mutatingTransport = (async () => {
    payload.target = "production"; // in flight, before the decision returns
    return new Response(JSON.stringify(allowReply.body), { status: 200 });
  }) as unknown as typeof globalThis.fetch;

  const receiver = new RatifyReceiver({
    apiKey: "rat_test_key_0123456789",
    verifierId: "receiver:test",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: mutatingTransport,
  });
  const result = await receiver.guard({ ...action, payload }, {}, (context) => {
    actedOn = (context.payload as { target: string }).target;
  });

  assert.equal(actedOn, "staging", "the handler acted on a payload that was never authorized");
  assert.equal(payload.target, "production", "the original really did change");
  assert.equal((result.decision.boundPayload as { target: string }).target, "staging");
});

test("the bound payload is frozen, so it cannot be edited before it is acted on", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  let bound: Record<string, unknown> | undefined;
  await receiver.guard({ ...action, payload: { target: "staging", nested: { deep: 1 } } }, {}, (c) => {
    bound = c.payload as Record<string, unknown>;
  });
  assert.ok(Object.isFrozen(bound));
  assert.ok(Object.isFrozen((bound as { nested: unknown }).nested), "nested objects are not frozen");
  assert.throws(() => { (bound as { target: string }).target = "production"; }, TypeError);
});

// Arrays are the other half of the snapshot and were not covered above: a
// mutable array inside a frozen object is still a payload that can change after
// it was authorized.
test("arrays inside the bound payload are frozen too", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  let bound: { items: string[]; nested: { deeper: number[] } } | undefined;
  await receiver.guard(
    { ...action, payload: { items: ["a", "b"], nested: { deeper: [1, 2] } } },
    {},
    (c) => { bound = c.payload as typeof bound; },
  );
  assert.ok(Object.isFrozen(bound!.items), "a top-level array was left mutable");
  assert.ok(Object.isFrozen(bound!.nested.deeper), "a nested array was left mutable");
  assert.throws(() => { (bound!.items as string[]).push("c"); }, TypeError);
  assert.throws(() => { (bound!.items as string[])[0] = "z"; }, TypeError);
});

test("the handler is given the same snapshot the decision was made about", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  let fromContext: unknown;
  const result = await receiver.guard({ ...action, payload: { a: 1 } }, {}, (c) => {
    fromContext = c.payload;
  });
  assert.equal(fromContext, result.decision.boundPayload, "two different snapshots were in play");
});

test("decide exposes the same bound payload for callers who own the branch", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  const decision = await receiver.decide({ ...action, payload: { a: 1 } }, {});
  assert.deepEqual(decision.boundPayload, { a: 1 });
  assert.ok(Object.isFrozen(decision.boundPayload));
});

test("an absent payload binds to nothing rather than to an empty object", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  const decision = await receiver.decide({ ...action, payload: undefined }, {});
  assert.equal(decision.boundPayload, undefined);
});

// The envelope has the same shape as the payload, and the same defect. The
// decision is made for one invocationId; the outcome is reported two awaits
// later. Re-reading the caller's object there filed the result against an
// invocation nobody had decided.
test("a mutated action cannot redirect the outcome report", async () => {
  const mutable = { ...action, invocationId: "inv-ORIGINAL" };
  const { receiver, calls } = receiverWith({ "/ratify/verify": allowReply });
  await receiver.guard(mutable, {}, () => {
    mutable.invocationId = "inv-MUTATED";
    mutable.resourceId = "github:someone/else";
  });
  const outcome = calls.find((c) => c.url.includes("/outcome"));
  assert.match(outcome!.url, /inv-ORIGINAL/, "the outcome was filed against a different invocation");
  assert.doesNotMatch(outcome!.url, /inv-MUTATED/);
});

// The mutation has to land *while the decision is in flight* -- before the
// context object is built. Mutating inside the handler is too late to catch a
// context that re-reads the caller's object, because the context already exists
// by then. An earlier version of this test made exactly that mistake and passed
// against the bug.
test("the handler context carries the bound invocation, not the live one", async () => {
  const mutable = { ...action, invocationId: "inv-ORIGINAL" };
  const receiver = new RatifyReceiver({
    apiKey: "rat_test_key_0123456789",
    verifierId: "receiver:test",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: (async () => {
      mutable.invocationId = "inv-MUTATED";
      return new Response(JSON.stringify(allowReply.body), { status: 200 });
    }) as unknown as typeof globalThis.fetch,
  });
  let seen = "";
  await receiver.guard(mutable, {}, (context) => {
    seen = context.invocationId;
  });
  assert.equal(seen, "inv-ORIGINAL", "the context re-read the caller's object");
  assert.equal(mutable.invocationId, "inv-MUTATED", "the original really did change");
});

// The wire must describe the same action that was hashed. A getter returning a
// different value on the second read would otherwise split them.
test("the operation sent matches the operation hashed, even with getters", async () => {
  let reads = 0;
  const shifty = {
    ...action,
    get resourceId() { return `github:acme/repo-${++reads}`; },
  } as unknown as ProtectedAction;
  const { receiver, calls } = receiverWith({ "/ratify/verify": allowReply });
  await receiver.guard(shifty, {}, () => "ok");
  const verify = calls.find((c) => c.url.includes("/ratify/verify"));
  const operation = (verify!.body!.operation ?? {}) as Record<string, unknown>;
  assert.equal(operation.resource_id, "github:acme/repo-1", "the wire disagreed with the hash");
});

// Finding R5-2. The config object belongs to the caller and stays mutable, and
// the receiver read from it on every call. The window that matters is *across*
// calls: a receiver built once, its config mutated later, every later request
// silently carrying a different identity or key.
//
// Note the shape of this test. Mutating during the verify call cannot catch a
// live read of `apiKey` for *that* call, because the headers were already built
// — an earlier version of this test made that mistake and passed against the
// bug. The observable points are the outcome POST that follows, and any
// subsequent call.
test("configuration is captured at construction, not re-read per call", async () => {
  const keys: string[] = [];
  const verifiers: unknown[] = [];
  const workspaces: unknown[] = [];
  const config = {
    apiKey: "rat_ORIGINAL",
    verifierId: "receiver:original",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: undefined as unknown as typeof globalThis.fetch,
  };
  config.fetch = (async (url: string | URL, init?: RequestInit) => {
    const headers = init?.headers as Record<string, string> | undefined;
    keys.push(headers?.["X-Ratify-API-Key"] ?? "<none>");
    if (String(url).includes("/ratify/verify")) {
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
      const operation = (body.operation ?? {}) as Record<string, unknown>;
      verifiers.push(operation.verifier_id);
      workspaces.push(operation.workspace_id);
    }
    return new Response(JSON.stringify(allowReply.body), { status: 200 });
  }) as unknown as typeof globalThis.fetch;

  const receiver = new RatifyReceiver(config);
  await receiver.guard(action, {}, () => "ok");

  // Mutated between calls, which is how a shared config object actually drifts.
  config.apiKey = "rat_MUTATED";
  config.verifierId = "receiver:mutated";
  config.workspaceId = "99999999-9999-9999-9999-999999999999";
  await receiver.guard({ ...action, invocationId: "inv-2" }, {}, () => "ok");

  assert.ok(keys.length >= 3, `expected verify+outcome calls, saw ${keys.length}`);
  assert.deepEqual(
    [...new Set(keys)],
    ["rat_ORIGINAL"],
    `a request carried a mutated API key: ${keys.join(", ")}`,
  );
  assert.deepEqual(
    [...new Set(verifiers)],
    ["receiver:original"],
    `a request carried a mutated verifier: ${verifiers.join(", ")}`,
  );
  assert.deepEqual(
    [...new Set(workspaces)],
    ["00000000-0000-0000-0000-000000000001"],
    `a request carried a mutated workspace: ${workspaces.join(", ")}`,
  );
});

// Finding R6-1. The options object is the caller's and can be shared. Reading
// `onReplay` after the decision returned meant a task that flipped it to "run"
// mid-verification got a handler execution the caller never asked for.
//
// The mutation has to land during the verify call — after `guard` was entered,
// before the replay branch is evaluated. Staging it anywhere else cannot observe
// the defect, which is the mistake the previous two rounds of these tests made.
test("a replay policy flipped during verification does not take effect", async () => {
  const options: { onReplay?: "skip" | "run" } = { onReplay: "skip" };
  let invocations = 0;
  const receiver = new RatifyReceiver({
    apiKey: "rat_test_key_0123456789",
    verifierId: "receiver:test",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: (async () => {
      options.onReplay = "run"; // another task, while the decision is in flight
      return new Response(JSON.stringify(replayedAllowReply.body), { status: 200 });
    }) as unknown as typeof globalThis.fetch,
  });

  const result = await receiver.guard(action, {}, () => { invocations += 1; }, options);

  assert.equal(invocations, 0, "a mid-flight policy change ran the handler");
  assert.equal(result.status, "replayed");
  assert.equal(options.onReplay, "run", "the options object really was mutated");
});

// The mirror: an opt-in revoked mid-flight still runs, because "run" was the
// policy when the call was made. Capturing means the decision is the caller's
// at the moment they made it, in both directions.
test("a replay opt-in revoked during verification still applies", async () => {
  const options: { onReplay?: "skip" | "run" } = { onReplay: "run" };
  let invocations = 0;
  const receiver = new RatifyReceiver({
    apiKey: "rat_test_key_0123456789",
    verifierId: "receiver:test",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: (async (url: string | URL) => {
      options.onReplay = "skip";
      const body = String(url).includes("/outcome") ? {} : replayedAllowReply.body;
      return new Response(JSON.stringify(body), { status: 200 });
    }) as unknown as typeof globalThis.fetch,
  });

  await receiver.guard(action, {}, () => { invocations += 1; }, options);
  assert.equal(invocations, 1, "the policy in force when the call was made was not honoured");
});

// Finding R7-1. `body.replayed === true` reads "true", 1 and {} as false, and
// false means the handler runs — so a malformed or hostile response could switch
// the replay guard off silently. Replay handling exists to stop a second
// consequential action; it may not be disabled by a value nobody checked.
test("a non-boolean replayed flag is refused, never read as false", async () => {
  for (const value of ["true", "false", 1, 0, {}, [], "yes", null] as const) {
    const { receiver } = receiverWith({
      "/ratify/verify": { status: 200, body: { ...allowReply.body, replayed: value } },
    });
    let invocations = 0;
    await assert.rejects(
      receiver.guard(action, {}, () => void (invocations += 1)),
      (error: unknown) => error instanceof VerifyError && error.code === "malformed_response",
      `replayed: ${JSON.stringify(value)} was accepted`,
    );
    assert.equal(invocations, 0, `replayed: ${JSON.stringify(value)} reached the handler`);
  }
});

// Only a missing key is absent. An earlier version of this test asserted that
// `replayed: null` also meant "not replayed" -- encoding the fail-open case as
// intent, in the same round I catalogued that exact mistake. `false` here means
// the handler runs, so null must be refused, not read as false.
test("only a missing replayed key means not replayed", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": { status: 200, body: allowReply.body } });
  const result = await receiver.guard(action, {}, () => "ran");
  assert.equal(result.status, "executed");
  assert.equal(result.decision.replayed, false);
  assert.ok(!("replayed" in (allowReply.body as object)), "the fixture must not carry the key");
});

test("a genuine replayed flag still takes the safe path", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": replayedAllowReply });
  const result = await receiver.guard(action, {}, () => "ran");
  assert.equal(result.status, "replayed");
});

// Finding R7-2. The thrown value belongs to the handler and may be hostile: a
// `message` getter that throws, a Symbol.toPrimitive that throws, a revoked
// proxy. Any of those propagating from describe() would replace the caller's
// error with ours and skip the outcome report — the two things this path
// promises not to do.
test("a hostile thrown value is rethrown unchanged and still reports", async () => {
  const hostile: Record<string, unknown> = {
    get message() { throw new Error("boom in getter"); },
    [Symbol.toPrimitive]() { throw new Error("boom in toPrimitive"); },
  };
  const { receiver, calls } = receiverWith({ "/ratify/verify": allowReply });
  const thrown = await receiver
    .guard(action, {}, () => { throw hostile; })
    .then(() => undefined, (e: unknown) => e);

  assert.equal(thrown, hostile, "the handler's own error was replaced");
  const outcome = calls.find((c) => c.url.includes("/outcome"));
  assert.ok(outcome, "the outcome report was skipped");
  assert.equal(outcome.body?.outcome, "failed");
  assert.equal(outcome.body?.detail, "handler threw a non-describable value");
});

test("a revoked proxy thrown by the handler does not break the rethrow", async () => {
  const { proxy, revoke } = Proxy.revocable({ message: "gone" }, {});
  revoke();
  const { receiver, calls } = receiverWith({ "/ratify/verify": allowReply });

  // Caught, never returned through a promise: resolving one with a revoked
  // proxy makes the runtime probe `.then` on it, which throws. That is a
  // property of the value, not of guard — and it is why this is a try/catch.
  let caught: unknown;
  let sameIdentity = false;
  try {
    await receiver.guard(action, {}, () => { throw proxy; });
    assert.fail("guard resolved instead of rethrowing");
  } catch (error) {
    caught = error;
    sameIdentity = error === proxy;
  }
  assert.ok(caught !== undefined);
  assert.ok(sameIdentity, "the handler's revoked proxy was replaced");
  assert.ok(calls.find((c) => c.url.includes("/outcome")), "the outcome report was skipped");
});

// A refusal must still be classified correctly once the check is defensive.
test("a ReceiverRefusal is still reported as refused_by_receiver", async () => {
  const { receiver, calls } = receiverWith({ "/ratify/verify": allowReply });
  await assert.rejects(
    receiver.guard(action, {}, () => { throw new ReceiverRefusal("change freeze"); }),
    /change freeze/,
  );
  const outcome = calls.find((c) => c.url.includes("/outcome"));
  assert.equal(outcome?.body?.outcome, "refused_by_receiver");
  assert.equal(outcome?.body?.detail, "change freeze");
});

// Every envelope value is JSON-derived, so nothing here can throw on
// stringification — a hostile `toString` does not survive JSON.stringify, and an
// earlier version of this test proved only that. What is reachable is a
// wrong-typed envelope, which must still yield a VerifyError carrying the status
// rather than a message of "[object Object]" or an undefined code.
test("a wrong-typed error envelope still produces a usable VerifyError", async () => {
  for (const body of [
    { error: { message: { nested: true }, code: 42 } },
    { error: { message: [1, 2], code: null } },
    { error: "not an object" },
    { error: null },
    { error: [] },
    {},
  ]) {
    const { receiver } = receiverWith({ "/ratify/verify": { status: 503, body } });
    await assert.rejects(
      receiver.guard(action, {}, () => "ran"),
      (error: unknown) =>
        error instanceof VerifyError &&
        error.status === 503 &&
        typeof error.message === "string" &&
        error.message !== "[object Object]" &&
        typeof error.code === "string",
      `envelope ${JSON.stringify(body)} did not yield a usable VerifyError`,
    );
  }
});

// A code is an identifier a caller branches on. A number coerced to "42" looks
// like one and is not; "unknown" says so.
test("a non-string error code becomes unknown, not a coerced value", async () => {
  const { receiver } = receiverWith({
    "/ratify/verify": { status: 503, body: { error: { message: "down", code: 42 } } },
  });
  await assert.rejects(
    receiver.guard(action, {}, () => "ran"),
    (error: unknown) => error instanceof VerifyError && error.code === "unknown",
  );
});

// A present value of the wrong type is a malformed response, not an absent
// field. Accepting it meant an allow whose reason was silently discarded, which
// is an audit record that cannot be trusted. An earlier version of this test
// asserted the discarding as intent.
test("a wrong-typed decision_reason is refused, not silently discarded", async () => {
  for (const reason of [{ nested: true }, [1, 2], 42, null, true] as const) {
    const { receiver } = receiverWith({
      "/ratify/verify": { status: 200, body: { ...allowReply.body, decision_reason: reason } },
    });
    let invocations = 0;
    await assert.rejects(
      receiver.guard(action, {}, () => void (invocations += 1)),
      (error: unknown) => error instanceof VerifyError && error.code === "malformed_response",
      `decision_reason ${JSON.stringify(reason)} was accepted`,
    );
    assert.equal(invocations, 0, `decision_reason ${JSON.stringify(reason)} reached the handler`);
  }
});

test("an absent decision_reason is still allowed", async () => {
  const body = { ...allowReply.body } as Record<string, unknown>;
  delete body.decision_reason;
  const { receiver } = receiverWith({ "/ratify/verify": { status: 200, body } });
  const result = await receiver.guard(action, {}, () => "ran");
  assert.equal(result.status, "executed");
  assert.equal(result.decision.reason, "");
});

// Finding R9-1. The protocol types requested_path as a plain string in Go and
// TypeScript, the server decodes it the same way, and OpenAPI marks it required
// — so the wire has no way to say "absent", and an omitted path and an explicit
// "" are one operation sharing one signature.
//
// That normalization is only safe if the handler cannot see past it. Reading the
// field off the caller's object would let it branch on a difference the
// signature does not carry, which is the documented invariant broken.
test("an omitted and an empty requestedPath are one operation", async () => {
  const captured: string[] = [];
  for (const act of [
    (() => { const a = { ...action }; delete (a as { requestedPath?: string }).requestedPath; return a; })(),
    { ...action, requestedPath: "" },
  ]) {
    const { receiver, calls } = receiverWith({ "/ratify/verify": allowReply });
    await receiver.guard(act, {}, (context) => {
      captured.push(context.action.requestedPath);
    });
    const verify = calls.find((c) => c.url.includes("/ratify/verify"));
    const operation = (verify!.body!.operation ?? {}) as Record<string, unknown>;
    captured.push(String(operation.request_hash));
  }
  const [pathA, hashA, pathB, hashB] = captured;
  assert.equal(pathA, "", "an omitted path reached the handler as something other than \"\"");
  assert.equal(pathB, "", "an empty path reached the handler as something other than \"\"");
  assert.equal(hashA, hashB, "two spellings of one operation produced different signatures");
});

test("the handler cannot distinguish what the signature cannot", async () => {
  const omitted = { ...action } as { requestedPath?: string };
  delete omitted.requestedPath;
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  let bound: Record<string, unknown> | undefined;
  await receiver.guard(omitted as ProtectedAction, {}, (context) => {
    bound = context.action as unknown as Record<string, unknown>;
  });
  // The caller's object has no such key; the bound one always does.
  assert.ok(!("requestedPath" in omitted), "the caller's object was mutated");
  assert.ok("requestedPath" in bound!, "the bound action omitted the normalized field");
  assert.equal(bound!.requestedPath, "");
});

test("the bound action carries the values that were signed", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  let bound: Record<string, unknown> | undefined;
  await receiver.guard(action, {}, (c) => { bound = c.action as unknown as Record<string, unknown>; });
  assert.deepEqual(Object.keys(bound!).sort(), [
    "action", "agentId", "invocationId", "requestedPath", "requiredScope", "resourceId", "sessionId",
  ]);
  assert.equal(bound!.resourceId, action.resourceId);
  assert.equal(bound!.requiredScope, action.requiredScope);
});

// The envelope race again, now through the bound action rather than the key.
test("the bound action is unaffected by a mutation during verification", async () => {
  const mutable = { ...action, resourceId: "github:acme/original" };
  const receiver = new RatifyReceiver({
    apiKey: "rat_test_key_0123456789",
    verifierId: "receiver:test",
    workspaceId: "00000000-0000-0000-0000-000000000001",
    baseUrl: "https://verify.test/v1",
    fetch: (async () => {
      mutable.resourceId = "github:acme/mutated";
      return new Response(JSON.stringify(allowReply.body), { status: 200 });
    }) as unknown as typeof globalThis.fetch,
  });
  let seen = "";
  await receiver.guard(mutable, {}, (c) => { seen = c.action.resourceId; });
  assert.equal(seen, "github:acme/original");
  assert.equal(mutable.resourceId, "github:acme/mutated");
});

// Finding R10-1. The payload snapshot was frozen and the bound action was not --
// the same invariant applied one layer too late. A handler could rewrite
// `resourceId` after authorization and act on the new value, which is exactly
// the authorized-versus-executed gap the snapshot closed.
//
// Everything handed to the handler is immutable, the decision included: a
// receiptId edited before being passed downstream misreports which receipt
// covers the action.
test("nothing handed to the handler can be mutated", async () => {
  const { receiver } = receiverWith({
    "/ratify/verify": {
      status: 200,
      body: { ...allowReply.body, receipt: { receipt_id: "11111111-1111-1111-1111-111111111111", nested: { deep: 1 } } },
    },
  });
  let seen: HandlerContext | undefined;
  await receiver.guard({ ...action, payload: { a: 1 } }, {}, (context) => {
    seen = context;
    assert.ok(Object.isFrozen(context.action), "context.action is mutable");
    assert.ok(Object.isFrozen(context.payload), "context.payload is mutable");
    assert.ok(Object.isFrozen(context.decision), "context.decision is mutable");
    assert.ok(Object.isFrozen(context.decision.receipt), "the receipt is mutable");
    assert.ok(
      Object.isFrozen((context.decision.receipt as { nested: unknown }).nested),
      "a nested receipt value is mutable",
    );
  });

  assert.ok(Object.isFrozen(seen), "the context object itself is mutable");
  assert.throws(() => { (seen!.action as { resourceId: string }).resourceId = "github:acme/production"; }, TypeError);
  assert.throws(() => { (seen!.decision as { receiptId: string }).receiptId = "forged"; }, TypeError);
  assert.equal(seen!.action.resourceId, action.resourceId, "the bound action was altered");
  assert.equal(seen!.decision.receiptId, "11111111-1111-1111-1111-111111111111");
});

// One object, not a copy per consumer: two copies can drift, and only one of
// them was signed.
test("the handler's action is the same object the binding produced", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  const seen: unknown[] = [];
  await receiver.guard(action, {}, (c) => { seen.push(c.action); });
  await receiver.guard({ ...action, invocationId: "inv-2" }, {}, (c) => { seen.push(c.action); });
  assert.notEqual(seen[0], seen[1], "two different actions shared one bound object");
  assert.equal((seen[0] as { invocationId: string }).invocationId, "inv-1");
  assert.equal((seen[1] as { invocationId: string }).invocationId, "inv-2");
});

test("decide returns a frozen decision too", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  const decision = await receiver.decide(action, {});
  assert.ok(Object.isFrozen(decision));
  assert.ok(Object.isFrozen(decision.receipt));
  assert.throws(() => { (decision as { receiptHash: string }).receiptHash = "forged"; }, TypeError);
});

// Finding R11-1. Every nested value was frozen and the object holding them was
// not -- the invariant applied to the contents and not the container. A handler
// could overwrite `invocationId` or `receiptId` and pass the context on, so the
// downstream idempotency key, or the receipt an action is correlated to, is not
// the authorized one. Ratify's own outcome report was never affected, because it
// uses the bound values directly; the integration contract was.
test("the context object itself cannot be rewritten", async () => {
  const { receiver, calls } = receiverWith({ "/ratify/verify": allowReply });
  let seen: HandlerContext | undefined;
  await receiver.guard({ ...action, invocationId: "real-invocation" }, {}, (context) => {
    seen = context;
    assert.ok(Object.isFrozen(context), "the context is mutable");
    assert.throws(() => { (context as { invocationId: string }).invocationId = "forged-key"; }, TypeError);
    assert.throws(() => { (context as { receiptId: string }).receiptId = "forged-receipt"; }, TypeError);
    assert.throws(() => { (context as { payload: unknown }).payload = { a: 2 }; }, TypeError);
  });

  assert.equal(seen!.invocationId, "real-invocation");
  assert.equal(seen!.receiptId, "11111111-1111-1111-1111-111111111111");
  // And the outcome was filed against the authorized invocation regardless.
  assert.match(calls.find((c) => c.url.includes("/outcome"))!.url, /real-invocation/);
});

test("adding a field to the context is refused too", async () => {
  const { receiver } = receiverWith({ "/ratify/verify": allowReply });
  await receiver.guard(action, {}, (context) => {
    assert.throws(() => {
      (context as unknown as Record<string, unknown>).injected = "value";
    }, TypeError);
    assert.ok(!("injected" in (context as object)));
  });
});
