import assert from "node:assert/strict";
import test from "node:test";
import Conversation from "../src/models/Conversation.js";
import {
  requireConversationMember,
  requireGroupAdmin,
  requireGroupMember,
} from "../src/middlewares/conversationMiddleware.js";

const createResponse = () => {
  const result = { statusCode: 200, body: undefined };
  return {
    result,
    status(code) {
      result.statusCode = code;
      return this;
    },
    json(body) {
      result.body = body;
      return this;
    },
  };
};

test("requireConversationMember rejects an invalid conversation ID", async () => {
  const req = {
    params: { conversationId: "not-an-object-id" },
    body: {},
    user: { _id: "507f1f77bcf86cd799439011" },
  };
  const res = createResponse();
  let nextCalled = false;

  await requireConversationMember(req, res, () => {
    nextCalled = true;
  });

  assert.equal(res.result.statusCode, 400);
  assert.equal(nextCalled, false);
});

test("requireConversationMember attaches an authorized conversation", async () => {
  const originalFindOne = Conversation.findOne;
  const conversation = { _id: "507f1f77bcf86cd799439012", type: "direct" };
  Conversation.findOne = async () => conversation;

  try {
    const req = {
      params: { conversationId: conversation._id },
      body: {},
      user: { _id: "507f1f77bcf86cd799439011" },
    };
    const res = createResponse();
    let nextCalled = false;

    await requireConversationMember(req, res, () => {
      nextCalled = true;
    });

    assert.equal(nextCalled, true);
    assert.equal(req.conversation, conversation);
  } finally {
    Conversation.findOne = originalFindOne;
  }
});

test("requireConversationMember hides conversations from non-members", async () => {
  const originalFindOne = Conversation.findOne;
  Conversation.findOne = async () => null;

  try {
    const req = {
      params: { conversationId: "507f1f77bcf86cd799439012" },
      body: {},
      user: { _id: "507f1f77bcf86cd799439011" },
    };
    const res = createResponse();

    await requireConversationMember(req, res, () => assert.fail("next must not be called"));

    assert.equal(res.result.statusCode, 404);
  } finally {
    Conversation.findOne = originalFindOne;
  }
});

test("requireGroupMember rejects direct conversations", () => {
  const req = { conversation: { type: "direct" } };
  const res = createResponse();

  requireGroupMember(req, res, () => assert.fail("next must not be called"));

  assert.equal(res.result.statusCode, 400);
});

test("requireGroupAdmin rejects a regular group member", () => {
  const req = {
    user: { _id: "507f1f77bcf86cd799439011" },
    conversation: {
      type: "group",
      group: {
        createdBy: "507f1f77bcf86cd799439012",
        admins: ["507f1f77bcf86cd799439012"],
      },
    },
  };
  const res = createResponse();

  requireGroupAdmin(req, res, () => assert.fail("next must not be called"));

  assert.equal(res.result.statusCode, 403);
});

test("requireGroupAdmin accepts an assigned administrator", () => {
  const userId = "507f1f77bcf86cd799439011";
  const req = {
    user: { _id: userId },
    conversation: {
      type: "group",
      group: {
        createdBy: "507f1f77bcf86cd799439012",
        admins: [userId],
      },
    },
  };
  const res = createResponse();
  let nextCalled = false;

  requireGroupAdmin(req, res, () => { nextCalled = true; });

  assert.equal(nextCalled, true);
});

test("requireGroupAdmin supports legacy groups owned by their creator", () => {
  const userId = "507f1f77bcf86cd799439011";
  const req = {
    user: { _id: userId },
    conversation: {
      type: "group",
      group: { createdBy: userId },
    },
  };
  const res = createResponse();
  let nextCalled = false;

  requireGroupAdmin(req, res, () => { nextCalled = true; });

  assert.equal(nextCalled, true);
});
