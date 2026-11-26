import assert from "node:assert/strict";
import test from "node:test";
import Conversation from "../src/models/conversation.model.js";
import Message from "../src/models/message.model.js";
import { deleteConversation, getConversations, getMessages } from "../src/controllers/conversation.controller.js";
import { searchMessages } from "../src/controllers/message-action.controller.js";
import { getClearedAt, unhideConversation, withClearedAtFilter } from "../src/utils/conversation.util.js";
import { updateConversationAfterCreateMessage } from "../src/services/message.service.js";

const ME = "507f1f77bcf86cd799439011";
const FRIEND = "507f1f77bcf86cd799439012";
const CONVERSATION = "507f1f77bcf86cd799439031";

const createRes = () => {
  const result = { statusCode: 200, body: undefined, sent: false };
  return {
    result,
    status(code) { result.statusCode = code; return this; },
    json(body) { result.body = body; return this; },
    send() { result.sent = true; return this; },
  };
};

// A chainable stand-in for a Mongoose query that resolves to `value`.
const chain = (value) => {
  const query = new Proxy({}, {
    get: (_target, name) => {
      if (name === "then") return (resolve, reject) => Promise.resolve(value).then(resolve, reject);
      return () => query;
    },
  });
  return query;
};

const withStubs = async (stubs, run) => {
  const originals = stubs.map(([target, name]) => [target, name, target[name]]);
  stubs.forEach(([target, name, impl]) => { target[name] = impl; });
  try { await run(); } finally { originals.forEach(([target, name, original]) => { target[name] = original; }); }
};

const CLEARED_AT = new Date("2026-02-01T00:00:00.000Z");
const conversationWith = (extra = {}) => ({
  _id: CONVERSATION,
  type: "direct",
  participants: [
    { userId: ME, ...extra },
    { userId: FRIEND },
  ],
});

test("deleteConversation hides a direct conversation for the current user only", async () => {
  let call;
  await withStubs([[Conversation, "updateOne", async (filter, update) => { call = { filter, update }; }]], async () => {
    const res = createRes();
    await deleteConversation({ user: { _id: ME }, conversation: conversationWith() }, res);

    assert.equal(res.result.statusCode, 204);
    assert.equal(call.filter["participants.userId"], ME, "only the caller's participant entry is touched");
    assert.equal(call.update.$set["participants.$.hidden"], true);
    assert.ok(call.update.$set["participants.$.clearedAt"] instanceof Date);
    assert.equal(call.update.$set[`unreadCounts.${ME}`], 0);
  });
});

test("deleteConversation refuses group conversations", async () => {
  let called = false;
  await withStubs([[Conversation, "updateOne", async () => { called = true; }]], async () => {
    const res = createRes();
    await deleteConversation({ user: { _id: ME }, conversation: { ...conversationWith(), type: "group" } }, res);

    assert.equal(res.result.statusCode, 400);
    assert.equal(called, false);
  });
});

test("getConversations leaves out conversations the user deleted", async () => {
  let filter;
  await withStubs([[Conversation, "find", (value) => { filter = value; return chain([]); }]], async () => {
    const res = createRes();
    await getConversations({ user: { _id: ME } }, res);

    assert.equal(res.result.statusCode, 200);
    assert.deepEqual(filter.participants.$elemMatch, { userId: ME, hidden: { $ne: true } });
  });
});

test("getMessages hides messages from before the user cleared the conversation", async () => {
  let filter;
  await withStubs([[Message, "find", (value) => { filter = value; return chain([]); }]], async () => {
    const res = createRes();
    await getMessages({
      user: { _id: ME },
      params: { conversationId: CONVERSATION },
      query: { cursor: "2026-03-01T00:00:00.000Z" },
      conversation: conversationWith({ clearedAt: CLEARED_AT }),
    }, res);

    assert.equal(res.result.statusCode, 200);
    // Both the cursor and the cutoff apply to the same field.
    assert.equal(filter.createdAt.$gt, CLEARED_AT);
    assert.equal(filter.createdAt.$lt.toISOString(), "2026-03-01T00:00:00.000Z");
  });
});

test("getMessages is unfiltered when the conversation was never cleared", async () => {
  let filter;
  await withStubs([[Message, "find", (value) => { filter = value; return chain([]); }]], async () => {
    await getMessages({ user: { _id: ME }, params: { conversationId: CONVERSATION }, query: {}, conversation: conversationWith() }, createRes());
    assert.equal(filter.createdAt, undefined);
  });
});

test("searchMessages only searches messages after the cutoff", async () => {
  let filter;
  await withStubs([[Message, "find", (value) => { filter = value; return chain([]); }]], async () => {
    await searchMessages({
      user: { _id: ME },
      params: { conversationId: CONVERSATION },
      query: { q: "xin chào" },
      conversation: conversationWith({ clearedAt: CLEARED_AT }),
    }, createRes());

    assert.equal(filter.createdAt.$gt, CLEARED_AT);
  });
});

test("conversation helpers read the cutoff and unhide for everyone", () => {
  const conversation = { participants: [{ userId: ME, hidden: true, clearedAt: CLEARED_AT }, { userId: FRIEND, hidden: true }] };

  assert.equal(getClearedAt(conversation, ME), CLEARED_AT);
  assert.equal(getClearedAt(conversation, FRIEND), null);
  assert.deepEqual(withClearedAtFilter({ conversationId: "c" }, conversation, FRIEND), { conversationId: "c" });

  unhideConversation(conversation);
  assert.deepEqual(conversation.participants.map((participant) => participant.hidden), [false, false]);
});

test("a new message brings a deleted conversation back for the person who deleted it", () => {
  const conversation = {
    participants: [{ userId: ME, hidden: true, clearedAt: CLEARED_AT }, { userId: FRIEND, hidden: false }],
    unreadCounts: new Map(),
    set() {},
  };

  updateConversationAfterCreateMessage(conversation, { _id: "m1", content: "hi", createdAt: new Date() }, FRIEND);

  assert.equal(conversation.participants[0].hidden, false);
  assert.ok(conversation.participants[0].clearedAt, "the history cutoff is kept");
  assert.equal(conversation.unreadCounts.get(ME), 1);
});
