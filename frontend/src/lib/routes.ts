/** Đường dẫn trang hồ sơ của một người dùng. Mọi liên kết/điều hướng tới hồ sơ phải dùng hàm này. */
export const profilePath = (userId: string) => `/profile/${userId}`;

export const CHAT_PATH = "/";
export const ADMIN_PATH = "/admin";
/** Tab bạn bè của giao diện điện thoại. */
export const FRIENDS_PATH = "/friends";

/** Mỗi hội thoại là một màn hình riêng, để nút Back của điện thoại thoát ra được. */
export const CHAT_ROOM_PATTERN = "/chat/:conversationId";
export const chatRoomPath = (conversationId: string) => `/chat/${conversationId}`;

/** Nơi hiển thị hội thoại đang mở: màn hình riêng trên điện thoại, cạnh sidebar trên máy tính. */
export const conversationPath = (conversationId: string, isMobile: boolean) =>
  isMobile ? chatRoomPath(conversationId) : CHAT_PATH;
