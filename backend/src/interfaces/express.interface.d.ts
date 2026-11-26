// Các trường middleware gắn thêm vào request của Express.
declare global {
  namespace Express {
    interface Request {
      /** Người dùng đã đăng nhập (protectedRoute), không có hashPassword. */
      user: Record<string, any>;
      /** Id phiên đăng nhập của access token; null với token cũ không có "sid". */
      sessionId: string | null;
      /** Hội thoại đã kiểm tra quyền thành viên (requireConversationMember). */
      conversation: Record<string, any>;
    }
  }
}

export {};
