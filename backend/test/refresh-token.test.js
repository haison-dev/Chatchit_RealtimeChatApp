import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import jwt from "jsonwebtoken";
import Session from "../src/models/session.model.js";
import { refreshToken } from "../src/controllers/auth.controller.js";

process.env.ACCESS_TOKEN_SECRET ??= "test-secret-test-secret-test-secret";

const hash = (token) => crypto.createHash("sha256").update(token).digest("hex");
const USER_ID = "507f1f77bcf86cd799439011";

const createRes = () => {
  const result = { statusCode: 200, body: undefined, cookies: [], cleared: 0 };
  return {
    result,
    status(code) { result.statusCode = code; return this; },
    json(body) { result.body = body; return this; },
    cookie(name, value) { result.cookies.push([name, value]); return this; },
    clearCookie() { result.cleared += 1; return this; },
  };
};

const withSession = async (stubs, run) => {
  const original = { findOne: Session.findOne, findOneAndUpdate: Session.findOneAndUpdate };
  Object.assign(Session, stubs);
  try { await run(); } finally { Object.assign(Session, original); }
};

test("refreshToken rotates the token and remembers the previous one", async () => {
  let update;
  const session = { _id: "s1", userId: USER_ID, expiresAt: new Date(Date.now() + 60_000), deleteOne: async () => {} };
  await withSession({
    findOne: async (filter) => (filter.refreshToken === hash("old") ? session : null),
    findOneAndUpdate: async (_filter, value) => { update = value; return { _id: "s1", userId: USER_ID }; },
  }, async () => {
    const res = createRes();
    await refreshToken({ cookies: { refreshToken: "old" } }, res);

    assert.equal(res.result.statusCode, 200);
    const payload = jwt.verify(res.result.body.accessToken, process.env.ACCESS_TOKEN_SECRET);
    assert.equal(payload.userId, USER_ID);
    assert.equal(payload.sid, "s1", "token phải chứa id của phiên");
    assert.equal(res.result.cookies.length, 1);
    assert.equal(update.$set.previousRefreshToken, hash("old"));
    assert.ok(update.$set.rotatedAt instanceof Date);
  });
});

test("refreshToken accepts a just-rotated token without signing the user out", async () => {
  let graceFilter;
  await withSession({
    findOne: async (filter) => {
      if (filter.refreshToken) return null;
      graceFilter = filter;
      return { _id: "s1", userId: USER_ID };
    },
  }, async () => {
    const res = createRes();
    await refreshToken({ cookies: { refreshToken: "old" } }, res);

    assert.equal(res.result.statusCode, 200);
    assert.ok(res.result.body.accessToken);
    assert.equal(res.result.cleared, 0, "the cookie must stay");
    assert.equal(res.result.cookies.length, 0, "no second rotation");
    assert.equal(graceFilter.previousRefreshToken, hash("old"));
    assert.ok(graceFilter.rotatedAt.$gte instanceof Date);
  });
});

test("refreshToken survives losing the rotation race to a parallel request", async () => {
  const session = { _id: "s1", userId: USER_ID, expiresAt: new Date(Date.now() + 60_000), deleteOne: async () => {} };
  let lookups = 0;
  await withSession({
    findOne: async (filter) => {
      lookups += 1;
      return filter.refreshToken ? session : { _id: "s1", userId: USER_ID };
    },
    findOneAndUpdate: async () => null,
  }, async () => {
    const res = createRes();
    await refreshToken({ cookies: { refreshToken: "old" } }, res);

    assert.equal(res.result.statusCode, 200);
    assert.equal(res.result.cleared, 0);
    assert.equal(lookups, 2);
  });
});

test("refreshToken rejects unknown or long-expired tokens and clears nothing it should keep", async () => {
  await withSession({ findOne: async () => null }, async () => {
    const res = createRes();
    await refreshToken({ cookies: { refreshToken: "forged" } }, res);
    assert.equal(res.result.statusCode, 403);
  });

  const missing = createRes();
  await refreshToken({ cookies: {} }, missing);
  assert.equal(missing.result.statusCode, 401);
});
