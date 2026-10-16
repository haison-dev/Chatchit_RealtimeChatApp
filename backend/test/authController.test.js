import assert from "node:assert/strict";
import test from "node:test";
import User from "../src/models/User.js";
import { signIn, signUp } from "../src/controllers/authController.js";

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

test("signUp rejects invalid account data before querying MongoDB", async () => {
  const req = { body: { username: "x", password: "123", email: "invalid", firstName: "A", lastName: "B" } };
  const res = createResponse();

  await signUp(req, res);

  assert.equal(res.result.statusCode, 400);
});

test("signUp reports which normalized account field already exists", async () => {
  const originalFindOne = User.findOne;
  User.findOne = () => ({
    select: async () => ({ username: "existing", email: "existing@example.com" }),
  });

  try {
    const req = {
      body: {
        username: " Existing ",
        password: "secret12",
        email: "new@example.com",
        firstName: "Hai",
        lastName: "Son",
      },
    };
    const res = createResponse();

    await signUp(req, res);

    assert.equal(res.result.statusCode, 409);
    assert.equal(res.result.body.field, "username");
    assert.equal(res.result.body.code, "ACCOUNT_ALREADY_EXISTS");
  } finally {
    User.findOne = originalFindOne;
  }
});

test("signIn rejects missing credentials before querying MongoDB", async () => {
  const req = { body: { username: "", password: "" } };
  const res = createResponse();

  await signIn(req, res);

  assert.equal(res.result.statusCode, 400);
});
