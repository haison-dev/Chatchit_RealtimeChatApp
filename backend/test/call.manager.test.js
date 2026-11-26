import assert from "node:assert/strict";
import test from "node:test";
import { createCallManager } from "../src/socket/call.manager.js";

const start = (manager, overrides = {}) =>
  manager.start({ callerId: "a", calleeId: "b", kind: "audio", callerSocketId: "sa", ...overrides });

test("start creates a ringing call and rejects invalid or busy requests", () => {
  const manager = createCallManager();
  assert.deepEqual(start(manager, { calleeId: "a" }), { ok: false, reason: "invalid" });
  assert.deepEqual(start(manager, { kind: "screen" }), { ok: false, reason: "invalid" });

  const first = start(manager);
  assert.equal(first.ok, true);
  assert.equal(first.call.state, "ringing");

  assert.deepEqual(start(manager, { callerId: "c", calleeId: "b", callerSocketId: "sc" }), { ok: false, reason: "busy" });
  assert.deepEqual(start(manager, { callerId: "b", calleeId: "c", callerSocketId: "sb" }), { ok: false, reason: "busy" });
  manager.finish(first.call.id, "a", "cancel");
});

test("only the callee can accept, and only while ringing", () => {
  const manager = createCallManager();
  const { call } = start(manager);
  assert.equal(manager.accept(call.id, "a", "sa2"), null);
  assert.equal(manager.accept("missing", "b", "sb"), null);
  assert.equal(manager.accept(call.id, "b", "sb").state, "active");
  assert.equal(manager.accept(call.id, "b", "sb2"), null);
  manager.finish(call.id, "a", "hangup");
});

test("finish enforces who may reject, cancel and hang up", () => {
  const manager = createCallManager();
  const { call } = start(manager);

  assert.equal(manager.finish(call.id, "a", "reject"), null);
  assert.equal(manager.finish(call.id, "b", "cancel"), null);
  assert.equal(manager.finish(call.id, "a", "hangup"), null, "cannot hang up before accept");
  assert.equal(manager.finish(call.id, "c", "reject"), null);
  assert.equal(manager.finish(call.id, "b", "reject").reason, "rejected");
  assert.equal(manager.get(call.id), undefined);

  const second = start(manager).call;
  assert.equal(manager.finish(second.id, "a", "cancel").reason, "cancelled");

  const third = start(manager).call;
  manager.accept(third.id, "b", "sb");
  assert.equal(manager.finish(third.id, "c", "hangup"), null);
  assert.equal(manager.finish(third.id, "b", "hangup").reason, "ended");

  const fourth = start(manager);
  assert.equal(fourth.ok, true, "users are free again after the call ends");
  manager.finish(fourth.call.id, "a", "cancel");
});

test("signalTarget only routes between the bound sockets of an active call", () => {
  const manager = createCallManager();
  const { call } = start(manager);
  assert.equal(manager.signalTarget(call.id, "a", "sa"), null, "not active yet");

  manager.accept(call.id, "b", "sb");
  assert.equal(manager.signalTarget(call.id, "a", "sa"), "sb");
  assert.equal(manager.signalTarget(call.id, "b", "sb"), "sa");
  assert.equal(manager.signalTarget(call.id, "a", "other-device"), null);
  assert.equal(manager.signalTarget(call.id, "c", "sc"), null);
  assert.equal(manager.signalTarget("missing", "a", "sa"), null);
  manager.finish(call.id, "a", "hangup");
});

test("dropSocket ends the call only for the bound socket", () => {
  const manager = createCallManager();
  const { call } = start(manager);
  assert.equal(manager.dropSocket("b", "sb"), null, "callee has not bound a socket yet");
  assert.equal(manager.dropSocket("a", "other-device"), null);
  assert.equal(manager.dropSocket("a", "sa").reason, "disconnected");
  assert.equal(manager.get(call.id), undefined);
  assert.equal(manager.dropSocket("a", "sa"), null);
});

test("an unanswered call times out as missed", async () => {
  const timeouts = [];
  const manager = createCallManager({ ringTimeoutMs: 10, onTimeout: (call, reason) => timeouts.push([call.id, reason]) });
  const { call } = start(manager);
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.deepEqual(timeouts, [[call.id, "missed"]]);
  assert.equal(manager.get(call.id), undefined);
});

test("accepting stops the ring timeout", async () => {
  const timeouts = [];
  const manager = createCallManager({ ringTimeoutMs: 10, onTimeout: (call) => timeouts.push(call.id) });
  const { call } = start(manager);
  manager.accept(call.id, "b", "sb");
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.deepEqual(timeouts, []);
  manager.finish(call.id, "a", "hangup");
});
