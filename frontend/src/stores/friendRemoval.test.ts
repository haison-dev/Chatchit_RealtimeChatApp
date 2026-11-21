import { beforeEach, describe, expect, it, vi } from "vitest";
import { friendService } from "@/services/friendService";
import { useFriendStore } from "./useFriendStore";

const friend = (id: string) => ({ _id: id, username: id, displayName: id });

describe("friend removal", () => {
  beforeEach(() => {
    useFriendStore.setState({ friends: [friend("a"), friend("b")] });
  });

  it("removeFriend ends the friendship on the server, then drops the friend", async () => {
    const remove = vi.spyOn(friendService, "removeFriend").mockResolvedValue(undefined);

    await useFriendStore.getState().removeFriend("a");

    expect(remove).toHaveBeenCalledWith("a");
    expect(useFriendStore.getState().friends.map((item) => item._id)).toEqual(["b"]);
  });

  it("keeps the friend when the server refuses", async () => {
    vi.spyOn(friendService, "removeFriend").mockRejectedValue(new Error("boom"));

    await expect(useFriendStore.getState().removeFriend("a")).rejects.toThrow("boom");

    expect(useFriendStore.getState().friends).toHaveLength(2);
  });

  it("dropFriend removes a friend locally (socket event from the other side)", () => {
    useFriendStore.getState().dropFriend("b");
    expect(useFriendStore.getState().friends.map((item) => item._id)).toEqual(["a"]);
  });
});
