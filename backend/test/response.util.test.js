import assert from "node:assert/strict";
import test from "node:test";
import express from "express";
import request from "supertest";
import { errorHandler, notFoundHandler } from "../src/middlewares/error.middleware.js";
import { createIpLimiter } from "../src/middlewares/security.middleware.js";
import { AppError, ERROR_CODES } from "../src/utils/app-error.util.js";
import { asyncHandler, sendSuccess } from "../src/utils/response.util.js";

// App nhỏ chỉ để kiểm tra dạng response chung, không cần database.
const createApp = (register) => {
  const app = express();
  app.use(express.json({ limit: "1kb" }));
  register(app);
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
};

test("response thành công luôn có success, message và data", async () => {
  const app = createApp((router) => {
    router.get("/ok", (_req, res) => sendSuccess(res, { message: "Xong", data: { value: 1 } }));
    router.post("/created", (_req, res) => sendSuccess(res, { status: 201 }));
  });

  const ok = await request(app).get("/ok");
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.body, { success: true, message: "Xong", data: { value: 1 } });

  const created = await request(app).post("/created");
  assert.equal(created.status, 201);
  assert.deepEqual(created.body, { success: true, message: null, data: null });
});

test("AppError ném từ service thành response lỗi chuẩn kèm mã và chi tiết", async () => {
  const app = createApp((router) => {
    router.get("/conflict", asyncHandler(async () => {
      throw AppError.conflict("Email đã được sử dụng", ERROR_CODES.ACCOUNT_ALREADY_EXISTS, { field: "email" });
    }));
  });

  const res = await request(app).get("/conflict");
  assert.equal(res.status, 409);
  assert.deepEqual(res.body, {
    success: false,
    message: "Email đã được sử dụng",
    code: "ACCOUNT_ALREADY_EXISTS",
    details: { field: "email" },
  });
});

test("lỗi không lường trước trả 500 với thông báo chung, không lộ chi tiết", async (t) => {
  t.mock.method(console, "error", () => {});
  const app = createApp((router) => {
    router.get("/boom", asyncHandler(async () => { throw new Error("mật khẩu database: secret"); }));
  });

  const res = await request(app).get("/boom");
  assert.equal(res.status, 500);
  assert.equal(res.body.success, false);
  assert.equal(res.body.code, "INTERNAL_ERROR");
  assert.doesNotMatch(JSON.stringify(res.body), /secret|stack/);
});

test("đường dẫn không tồn tại và JSON hỏng cũng theo dạng lỗi chuẩn", async () => {
  const app = createApp(() => {});

  const missing = await request(app).get("/khong-co");
  assert.equal(missing.status, 404);
  assert.deepEqual(missing.body, { success: false, message: "Không tìm thấy", code: "NOT_FOUND" });

  const broken = await request(app).post("/khong-co").set("Content-Type", "application/json").send("{hỏng");
  assert.equal(broken.status, 400);
  assert.equal(broken.body.code, "VALIDATION_ERROR");

  const tooLarge = await request(app).post("/khong-co").send({ text: "x".repeat(2000) });
  assert.equal(tooLarge.status, 413);
  assert.equal(tooLarge.body.code, "PAYLOAD_TOO_LARGE");
});

test("vượt giới hạn tần suất trả 429 theo dạng lỗi chuẩn", async () => {
  const limiter = createIpLimiter({ windowMs: 60_000, limit: 1, message: "Chậm lại một chút." });
  const app = createApp((router) => {
    router.get("/limited", limiter, (_req, res) => sendSuccess(res));
  });

  assert.equal((await request(app).get("/limited")).status, 200);
  const blocked = await request(app).get("/limited");
  assert.equal(blocked.status, 429);
  assert.deepEqual(blocked.body, { success: false, message: "Chậm lại một chút.", code: "RATE_LIMITED" });
});

test("asyncHandler chuyển AppError của middleware thành response, không gọi next", async () => {
  let reached = false;
  const guard = asyncHandler(async () => { throw AppError.forbidden("Không có quyền"); });
  const res = { statusCode: 0, body: undefined, headersSent: false, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };

  await guard({ method: "GET", originalUrl: "/x" }, res, () => { reached = true; });

  assert.equal(reached, false);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.code, "FORBIDDEN");
});
