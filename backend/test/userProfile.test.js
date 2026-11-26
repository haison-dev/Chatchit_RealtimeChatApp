import assert from "node:assert/strict";
import test from "node:test";
import Conversation from "../src/models/Conversation.js";
import Friend from "../src/models/Friend.js";
import FriendRequest from "../src/models/FriendRequest.js";
import User from "../src/models/User.js";
import { getUserProfile, searchUsers, updateMe } from "../src/controllers/userController.js";
import { friendPair } from "../src/utils/friendHelper.js";
import { buildNameSearchPattern, sanitizeAvatarUrl } from "../src/utils/sanitize.js";

const ME = "507f1f77bcf86cd799439011";
const OTHER = "507f1f77bcf86cd799439012";
const MUTUAL = "507f1f77bcf86cd799439013";

const createRes = () => {
  const result = { statusCode: 200, body: undefined };
  return {
    result,
    status(code) { result.statusCode = code; return this; },
    json(body) { result.body = body; return this; },
  };
};

const chain = (value) => {
  const query = {
    select: () => query,
    sort: () => query,
    limit: () => query,
    lean: async () => value,
    then: (resolve, reject) => Promise.resolve(value).then(resolve, reject),
  };
  return query;
};

// Replaces model statics for one test and restores them afterwards.
const withStubs = async (stubs, run) => {
  const originals = stubs.map(([model, name]) => [model, name, model[name]]);
  stubs.forEach(([model, name, impl]) => { model[name] = impl; });
  try { await run(); } finally { originals.forEach(([model, name, original]) => { model[name] = original; }); }
};

test("friendPair sorts ids so a pair is the same in both directions", () => {
  assert.deepEqual(friendPair(OTHER, ME), [ME, OTHER]);
  assert.deepEqual(friendPair(ME, OTHER), [ME, OTHER]);
});

test("sanitizeAvatarUrl only accepts clean https URLs", () => {
  assert.equal(sanitizeAvatarUrl("https://example.com/a.png"), "https://example.com/a.png");
  assert.equal(sanitizeAvatarUrl("http://example.com/a.png"), null);
  assert.equal(sanitizeAvatarUrl("javascript:alert(1)"), null);
  assert.equal(sanitizeAvatarUrl("https://user:pw@example.com/a.png"), null);
  assert.equal(sanitizeAvatarUrl({}), null);
});

test("updateMe rejects invalid fields and empty updates", async () => {
  const cases = [
    [{ displayName: "   " }, /tên hiển thị/i],
    [{ bio: "x".repeat(501) }, /giới thiệu/i],
    [{ phone: "abc" }, /số điện thoại/i],
    [{ avatarUrl: "http://insecure.example/a.png" }, /https/i],
    [{ bio: { $ne: "" } }, /chuỗi ký tự/i],
    [{ unknown: "x" }, /không có thông tin hồ sơ/i],
  ];
  for (const [body, pattern] of cases) {
    const res = createRes();
    await updateMe({ user: { _id: ME }, body }, res);
    assert.equal(res.result.statusCode, 400, JSON.stringify(body));
    assert.match(res.result.body.message, pattern);
  }
});

test("updateMe sanitizes values and clears optional fields with $unset", async () => {
  let received;
  await withStubs([[User, "findByIdAndUpdate", (_id, update) => { received = update; return chain({ _id: ME, displayName: "New Name" }); }]], async () => {
    const res = createRes();
    await updateMe({
      user: { _id: ME },
      body: { displayName: " New‮ Name ", bio: "", phone: "+84 912 345 678", avatarUrl: "https://example.com/a.png" },
    }, res);
    assert.equal(res.result.statusCode, 200);
    assert.deepEqual(received.$set, { displayName: "New Name", phone: "+84 912 345 678", avatarUrl: "https://example.com/a.png" });
    assert.deepEqual(received.$unset, { bio: "" });
  });
});

test("getUserProfile hides email and phone from strangers and shows mutual friends", async () => {
  const stranger = { _id: OTHER, displayName: "Stranger", username: "stranger", email: "s@example.com", phone: "123456", bio: "hi" };
  await withStubs([
    [User, "findById", () => chain(stranger)],
    [User, "find", () => chain([{ _id: MUTUAL, displayName: "Mutual", username: "mutual" }])],
    [Friend, "find", (filter) => chain(
      // First call: my friends. Second call: friendships between target and my friends.
      filter.$or[0].userA?.$in
        ? [{ userA: OTHER, userB: MUTUAL }]
        : [{ userA: ME, userB: MUTUAL }],
    )],
    [FriendRequest, "find", () => chain([])],
  ], async () => {
    const res = createRes();
    await getUserProfile({ user: { _id: ME }, params: { userId: OTHER } }, res);
    const { profile } = res.result.body;
    assert.equal(res.result.statusCode, 200);
    assert.equal(profile.email, undefined);
    assert.equal(profile.phone, undefined);
    assert.equal(profile.relationship.status, "none");
    assert.equal(profile.mutualFriends.count, 1);
    assert.equal(profile.mutualFriends.users[0].displayName, "Mutual");
  });
});

test("getUserProfile shows contact info and the direct conversation to friends", async () => {
  const friend = { _id: OTHER, displayName: "Friend", username: "friend", email: "f@example.com", phone: "123456" };
  await withStubs([
    [User, "findById", () => chain(friend)],
    [User, "find", () => chain([])],
    [Friend, "find", () => chain([{ userA: ME, userB: OTHER }])],
    [FriendRequest, "find", () => chain([])],
    [Conversation, "findOne", () => chain({ _id: "conversation-1" })],
  ], async () => {
    const res = createRes();
    await getUserProfile({ user: { _id: ME }, params: { userId: OTHER } }, res);
    const { profile } = res.result.body;
    assert.equal(profile.relationship.status, "friend");
    assert.equal(profile.email, "f@example.com");
    assert.equal(profile.directConversationId, "conversation-1");
  });
});

test("getUserProfile validates the id and reports unknown users", async () => {
  const bad = createRes();
  await getUserProfile({ user: { _id: ME }, params: { userId: "nope" } }, bad);
  assert.equal(bad.result.statusCode, 400);

  await withStubs([[User, "findById", () => chain(null)]], async () => {
    const res = createRes();
    await getUserProfile({ user: { _id: ME }, params: { userId: OTHER } }, res);
    assert.equal(res.result.statusCode, 404);
  });
});

test("searchUsers requires a long enough query and matches email exactly", async () => {
  const short = createRes();
  await searchUsers({ user: { _id: ME }, query: { q: "a" } }, short);
  assert.equal(short.result.statusCode, 400);

  const filters = [];
  await withStubs([
    [User, "find", (value) => { filters.push(value); return chain([]); }],
    [Friend, "find", () => chain([])],
    [FriendRequest, "find", () => chain([])],
  ], async () => {
    const res = createRes();
    await searchUsers({ user: { _id: ME }, query: { q: "Bob@Example.com" } }, res);
    assert.equal(res.result.statusCode, 200);
    // One query for friends and one for everybody else; both include the exact-email condition.
    assert.equal(filters.length, 2);
    filters.forEach((filter) => assert.deepEqual(filter.$or[1], { email: "bob@example.com" }));
    assert.ok(filters[1]._id.$nin.includes(ME), "the viewer never finds themselves");
  });
});

test("searchUsers escapes regex characters in the query", async () => {
  const filters = [];
  await withStubs([
    [User, "find", (value) => { filters.push(value); return chain([]); }],
    [Friend, "find", () => chain([])],
    [FriendRequest, "find", () => chain([])],
  ], async () => {
    await searchUsers({ user: { _id: ME }, query: { q: "x.*" } }, createRes());
    assert.equal(filters[0].$or.length, 1);
    assert.equal(filters[0].$or[0].displayName.$regex, String.raw`x\.\*`);
  });
});

test("searchUsers lists friends before strangers and reports each relationship", async () => {
  const FRIEND = "507f1f77bcf86cd799439021";
  const STRANGER = "507f1f77bcf86cd799439022";
  const calls = [];
  await withStubs([
    [User, "find", (value) => {
      calls.push(value);
      if (value._id.$in) return chain([{ _id: FRIEND, displayName: "Sơn Bạn", username: "sonban" }]);
      if (value._id.$nin) return chain([{ _id: STRANGER, displayName: "Sơn Lạ", username: "sonla" }]);
      return chain([]);
    }],
    [Friend, "find", () => chain([{ userA: ME, userB: FRIEND }])],
    [FriendRequest, "find", () => chain([])],
  ], async () => {
    const res = createRes();
    await searchUsers({ user: { _id: ME }, query: { q: "son" } }, res);

    const { users } = res.result.body;
    assert.deepEqual(users.map((user) => user._id), [FRIEND, STRANGER]);
    assert.equal(users[0].relationship.status, "friend");
    assert.equal(users[1].relationship.status, "none");
    assert.deepEqual(calls[0]._id.$in, [FRIEND]);
  });
});

test("buildNameSearchPattern ignores case and Vietnamese diacritics", () => {
  const matches = (query, name) => new RegExp(buildNameSearchPattern(query), "i").test(name);

  assert.equal(matches("son", "Nguyễn Văn Sơn"), true);
  assert.equal(matches("SƠN", "nguyen van son"), true);
  assert.equal(matches("nguyen van", "Nguyễn Văn Sơn"), true);
  assert.equal(matches("duc", "Đức"), true);
  assert.equal(matches("đức", "Duc Anh"), true);
  assert.equal(matches("son", "Hoa"), false);
  // Regex characters are matched literally.
  assert.equal(matches("a.c", "abc"), false);
  assert.equal(matches("a.c", "a.c"), true);
});
