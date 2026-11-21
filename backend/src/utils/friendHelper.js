import Friend from "../models/Friend.js";
import FriendRequest from "../models/FriendRequest.js";
import User from "../models/User.js";

// Friend documents always store the pair sorted (userA < userB) so a pair is
// unique regardless of who sent the request. Every lookup must use this order.
export const friendPair = (first, second) => {
  const a = first.toString();
  const b = second.toString();
  return a < b ? [a, b] : [b, a];
};

export const PUBLIC_USER_FIELDS = "_id displayName username avatarUrl";

const otherSide = (friendship, userId) =>
  friendship.userA.toString() === userId ? friendship.userB.toString() : friendship.userA.toString();

/** IDs (strings) of everyone the user is friends with. */
export const getFriendIds = async (userId) => {
  const id = userId.toString();
  const friendships = await Friend.find({ $or: [{ userA: id }, { userB: id }] })
    .select("userA userB")
    .lean();
  return friendships.map((friendship) => otherSide(friendship, id));
};

/**
 * Mutual friends between `viewerId` and each of `targetIds`.
 * Returns Map<targetId, User[]> (users limited to `limit` per target) and the
 * total count per target, using one friendship query and one user query no
 * matter how many targets are asked about.
 */
export const getMutualFriends = async (viewerId, targetIds, { limit = 3, viewerFriendIds } = {}) => {
  const result = new Map(targetIds.map((id) => [id.toString(), { count: 0, users: [] }]));
  if (targetIds.length === 0) return result;

  const myFriendIds = viewerFriendIds ?? await getFriendIds(viewerId);
  if (myFriendIds.length === 0) return result;

  const targets = targetIds.map((id) => id.toString());
  const friendships = await Friend.find({
    $or: [
      { userA: { $in: targets }, userB: { $in: myFriendIds } },
      { userB: { $in: targets }, userA: { $in: myFriendIds } },
    ],
  }).select("userA userB").lean();

  const mutualIds = new Map(targets.map((id) => [id, []]));
  const myFriendSet = new Set(myFriendIds);
  const targetSet = new Set(targets);
  friendships.forEach((friendship) => {
    const a = friendship.userA.toString();
    const b = friendship.userB.toString();
    if (targetSet.has(a) && myFriendSet.has(b)) mutualIds.get(a).push(b);
    if (targetSet.has(b) && myFriendSet.has(a)) mutualIds.get(b).push(a);
  });

  const previewIds = new Set();
  mutualIds.forEach((ids) => ids.slice(0, limit).forEach((id) => previewIds.add(id)));
  const users = previewIds.size
    ? await User.find({ _id: { $in: [...previewIds] } }).select(PUBLIC_USER_FIELDS).lean()
    : [];
  const usersById = new Map(users.map((user) => [user._id.toString(), user]));

  mutualIds.forEach((ids, targetId) => {
    result.set(targetId, {
      count: ids.length,
      users: ids.slice(0, limit).map((id) => usersById.get(id)).filter(Boolean),
    });
  });
  return result;
};

/**
 * Relationship of `viewerId` to each target:
 * "friend" | "request_sent" | "request_received" | "none" (and requestId for pending ones).
 * Returns Map<targetId, { status, requestId? }>.
 */
export const getRelationships = async (viewerId, targetIds, { viewerFriendIds } = {}) => {
  const viewer = viewerId.toString();
  const targets = targetIds.map((id) => id.toString());
  const result = new Map(targets.map((id) => [id, { status: "none" }]));
  if (targets.length === 0) return result;

  const [friendIds, requests] = await Promise.all([
    viewerFriendIds ?? getFriendIds(viewer),
    FriendRequest.find({
      $or: [
        { from: viewer, to: { $in: targets } },
        { to: viewer, from: { $in: targets } },
      ],
    }).select("from to").lean(),
  ]);

  requests.forEach((request) => {
    if (request.from.toString() === viewer) {
      result.set(request.to.toString(), { status: "request_sent", requestId: request._id.toString() });
    } else {
      result.set(request.from.toString(), { status: "request_received", requestId: request._id.toString() });
    }
  });
  // A friendship always wins over a stale pending request.
  friendIds.forEach((id) => {
    if (result.has(id)) result.set(id, { status: "friend" });
  });
  return result;
};
