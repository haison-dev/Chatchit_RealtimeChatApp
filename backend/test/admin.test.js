import assert from "node:assert/strict";
import test from "node:test";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Session from "../src/models/session.model.js";
import User from "../src/models/user.model.js";
import { signIn } from "../src/controllers/auth.controller.js";
import { listUsers, revokeSession, revokeUserSessions } from "../src/controllers/admin.controller.js";
import { requireAdmin } from "../src/middlewares/admin.middleware.js";
import { protectedRoute } from "../src/middlewares/auth.middleware.js";
import { buildDailySeries, startOfVietnamDay, vietnamDayKey } from "../src/utils/admin-stats.util.js";
import { isSessionActive } from "../src/services/session.service.js";
import { describeUserAgent } from "../src/utils/user-agent.util.js";

process.env.ACCESS_TOKEN_SECRET ??= "test-secret";

const ADMIN = "507f1f77bcf86cd799439011";
const USER = "507f1f77bcf86cd799439012";
const CURRENT = "607f1f77bcf86cd799439021";
const OTHER = "607f1f77bcf86cd799439022";

const createRes = () => {
  const result = { statusCode: 200, body: undefined, cookies: {} };
  return {
    result,
    status(code) { result.statusCode = code; return this; },
    json(body) { result.body = body; return this; },
    cookie(name, value) { result.cookies[name] = value; return this; },
  };
};

const chain = (value) => {
  const query = {
    select: () => query,
    sort: () => query,
    skip: () => query,
    limit: () => query,
    lean: async () => value,
    then: (resolve, reject) => Promise.resolve(value).then(resolve, reject),
  };
  return query;
};

const withStubs = async (stubs, run) => {
  const originals = stubs.map(([model, name]) => [model, name, model[name]]);
  stubs.forEach(([model, name, impl]) => { model[name] = impl; });
  try { await run(); } finally { originals.forEach(([model, name, original]) => { model[name] = original; }); }
};

const adminReq = (extra = {}) => ({ user: { _id: ADMIN, role: "admin" }, sessionId: CURRENT, params: {}, query: {}, ...extra });

test("describeUserAgent phân biệt được các thiết bị phổ biến", () => {
  const android = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36";
  const iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
  const edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 Edg/130.0";
  const ipad = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0 Mobile/15E148 Safari/604.1";

  assert.deepEqual(describeUserAgent(android), { browser: "Chrome", os: "Android", deviceType: "mobile" });
  assert.deepEqual(describeUserAgent(iphone), { browser: "Safari", os: "iOS", deviceType: "mobile" });
  assert.deepEqual(describeUserAgent(edge), { browser: "Edge", os: "Windows", deviceType: "desktop" });
  assert.deepEqual(describeUserAgent(ipad), { browser: "Chrome", os: "iOS", deviceType: "tablet" });
  assert.deepEqual(describeUserAgent(undefined), { browser: "Không rõ", os: "Không rõ", deviceType: "desktop" });
});

test("chuỗi theo ngày tính theo giờ Việt Nam và điền 0 cho ngày trống", () => {
  // 18:30 UTC đã là 01:30 ngày hôm sau ở Việt Nam.
  const now = new Date("2026-11-25T18:30:00.000Z");
  assert.equal(vietnamDayKey(now), "2026-11-26");
  assert.equal(startOfVietnamDay(now).toISOString(), "2026-11-25T17:00:00.000Z");

  const series = buildDailySeries([{ _id: "2026-11-24", count: 3 }, { _id: "2026-11-26", count: 1 }], 3, now);
  assert.deepEqual(series, [
    { date: "2026-11-24", count: 3 },
    { date: "2026-11-25", count: 0 },
    { date: "2026-11-26", count: 1 },
  ]);
});

test("requireAdmin trả 404 để giấu API quản trị với người không phải admin", () => {
  let passed = false;
  const res = createRes();
  requireAdmin({ user: { role: "user" } }, res, () => { passed = true; });
  assert.equal(res.result.statusCode, 404);
  assert.equal(passed, false);

  requireAdmin({ user: { role: "admin" } }, createRes(), () => { passed = true; });
  assert.equal(passed, true);
});

test("isSessionActive chấp nhận token cũ không có phiên và kiểm tra các token còn lại", async () => {
  assert.equal(await isSessionActive({ userId: USER }), true);
  assert.equal(await isSessionActive({ userId: USER, sid: "not-an-id" }), false);
  await withStubs([[Session, "exists", async (filter) => (filter._id === OTHER ? { _id: OTHER } : null)]], async () => {
    assert.equal(await isSessionActive({ userId: USER, sid: OTHER }), true);
    assert.equal(await isSessionActive({ userId: USER, sid: CURRENT }), false);
  });
});

test("access token mất hiệu lực ngay khi phiên bị xóa", async () => {
  const token = jwt.sign({ userId: USER, sid: OTHER }, process.env.ACCESS_TOKEN_SECRET);
  const req = { headers: { authorization: `Bearer ${token}` } };
  const res = createRes();
  let passed = false;

  await withStubs([
    [Session, "exists", async () => null],
    [User, "findById", () => { throw new Error("không được tải người dùng"); }],
  ], async () => {
    await protectedRoute(req, res, () => { passed = true; });
  });

  // 403 khiến client thử refresh, và refresh thất bại vì phiên đã bị xóa.
  assert.equal(res.result.statusCode, 403);
  assert.equal(passed, false);
});

test("signIn lưu thiết bị và đưa id phiên vào access token", async () => {
  const hashPassword = await bcrypt.hash("secret12", 4);
  let created;
  await withStubs([
    [User, "findOne", async () => ({ _id: USER, displayName: "An", hashPassword })],
    [Session, "create", async (doc) => { created = doc; return { _id: OTHER, ...doc }; }],
  ], async () => {
    const res = createRes();
    await signIn({ body: { username: "an", password: "secret12" }, ip: "203.0.113.5", get: () => "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0 Safari/537.36" }, res);

    assert.equal(res.result.statusCode, 200);
    assert.equal(created.ip, "203.0.113.5");
    assert.match(created.userAgent, /Windows/);
    assert.ok(created.lastUsedAt instanceof Date);
    assert.equal(jwt.decode(res.result.body.accessToken).sid, OTHER);
  });
});

test("listUsers kèm số thiết bị và từ chối tham số dạng mảng", async () => {
  const bad = createRes();
  await listUsers(adminReq({ query: { q: ["a", "b"] } }), bad);
  assert.equal(bad.result.statusCode, 400);

  await withStubs([
    [User, "find", () => chain([{ _id: USER, username: "an", email: "an@example.com", displayName: "An", createdAt: new Date() }])],
    [User, "countDocuments", async () => 1],
    [Session, "aggregate", async () => [{ _id: { toString: () => USER }, count: 2 }]],
  ], async () => {
    const res = createRes();
    await listUsers(adminReq({ query: { q: "an", page: "1" } }), res);

    assert.equal(res.result.statusCode, 200);
    assert.equal(res.result.body.total, 1);
    assert.deepEqual(
      { sessionCount: res.result.body.users[0].sessionCount, role: res.result.body.users[0].role, online: res.result.body.users[0].online },
      { sessionCount: 2, role: "user", online: false },
    );
  });
});

test("revokeSession không cho đăng xuất thiết bị admin đang dùng, xóa được thiết bị khác", async () => {
  const own = createRes();
  await revokeSession(adminReq({ params: { sessionId: CURRENT } }), own);
  assert.equal(own.result.statusCode, 400);

  const invalid = createRes();
  await revokeSession(adminReq({ params: { sessionId: "nope" } }), invalid);
  assert.equal(invalid.result.statusCode, 400);

  let deleted;
  await withStubs([[Session, "findOneAndDelete", async (filter) => { deleted = filter; return { _id: OTHER }; }]], async () => {
    const res = createRes();
    await revokeSession(adminReq({ params: { sessionId: OTHER } }), res);
    assert.equal(res.result.statusCode, 200);
    assert.deepEqual(deleted, { _id: OTHER });
  });

  await withStubs([[Session, "findOneAndDelete", async () => null]], async () => {
    const res = createRes();
    await revokeSession(adminReq({ params: { sessionId: OTHER } }), res);
    assert.equal(res.result.statusCode, 404);
  });
});

test("revokeUserSessions đăng xuất mọi thiết bị trừ thiết bị admin đang dùng", async () => {
  let findFilter;
  let deleteFilter;
  await withStubs([
    [Session, "find", (filter) => { findFilter = filter; return chain([{ _id: OTHER }]); }],
    [Session, "deleteMany", async (filter) => { deleteFilter = filter; return { deletedCount: 1 }; }],
  ], async () => {
    const res = createRes();
    await revokeUserSessions(adminReq({ params: { userId: ADMIN } }), res);

    assert.equal(res.result.statusCode, 200);
    assert.equal(res.result.body.revoked, 1);
    assert.deepEqual(findFilter, { userId: ADMIN, _id: { $ne: CURRENT } });
    assert.deepEqual(deleteFilter, { _id: { $in: [OTHER] } });
  });
});
