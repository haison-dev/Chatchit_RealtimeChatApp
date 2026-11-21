import test from "node:test";
import assert from "node:assert/strict";
import express from "express";
import request from "supertest";
import { hasUnsafeKeys, sanitizeText } from "../src/utils/sanitize.js";
import { rejectUnsafePayload } from "../src/middlewares/securityMiddleware.js";

const ch = (...codes) => String.fromCodePoint(...codes);

test("sanitizeText strips control, bidi-override and zero-width characters", () => {
  const input = `  hi${ch(0x202e)}evil${ch(0x0000)}${ch(0x200b)} there `;
  assert.equal(sanitizeText(input), "hievil there");
});

test("sanitizeText keeps emoji ZWJ sequences", () => {
  const family = ch(0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467);
  assert.equal(sanitizeText(family), family);
});

test("sanitizeText collapses line breaks in single-line fields", () => {
  assert.equal(sanitizeText("Team\n\n  Alpha"), "Team Alpha");
});

test("sanitizeText limits consecutive blank lines in multiline text", () => {
  assert.equal(sanitizeText("a\n\n\n\n\n\nb", { multiline: true }), "a\n\n\nb");
});

test("sanitizeText returns an empty string for non-strings", () => {
  assert.equal(sanitizeText({ $ne: null }), "");
  assert.equal(sanitizeText(undefined), "");
});

test("hasUnsafeKeys detects operator, dotted and prototype keys", () => {
  assert.equal(hasUnsafeKeys({ recipientId: { $ne: null } }), true);
  assert.equal(hasUnsafeKeys({ items: [{ "a.b": 1 }] }), true);
  assert.equal(hasUnsafeKeys(JSON.parse('{"__proto__":{"admin":true}}')), true);
  assert.equal(hasUnsafeKeys({ content: "$100 and a.b" }), false);
});

test("rejectUnsafePayload blocks NoSQL operator injection in JSON bodies", async () => {
  const app = express();
  app.use(express.json());
  app.use(rejectUnsafePayload);
  app.post("/", (_req, res) => res.sendStatus(204));

  const blocked = await request(app).post("/").send({ to: { $gt: "" } });
  assert.equal(blocked.status, 400);

  const allowed = await request(app).post("/").send({ content: "hello $world" });
  assert.equal(allowed.status, 204);
});
