const test = require("node:test");
const assert = require("node:assert/strict");

process.env.NODE_ENV = "test";
process.env.RATE_LIMIT_WINDOW_MS = "60000";
process.env.RATE_LIMIT_MAX_GLOBAL = "8";

const { server } = require("../server.cjs");

let baseUrl = "";

test.before(async () => {
  await new Promise((resolve) => server.listen(0, resolve));
  const addr = server.address();
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test("GET /api/health-public returns ok", async () => {
  const res = await fetch(`${baseUrl}/api/health-public`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.success, true);
  assert.equal(body.status, "ok");
});

test("GET /api/password-policy returns policy", async () => {
  const res = await fetch(`${baseUrl}/api/password-policy`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.success, true);
  assert.equal(body.policy.minLength, 8);
  assert.equal(body.policy.requiresSpecial, true);
});

test("GET /api/docs/openapi.json exposes key paths", async () => {
  const res = await fetch(`${baseUrl}/api/docs/openapi.json`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.openapi, "3.0.3");
  assert.ok(body.paths["/api/login"]);
  assert.ok(body.paths["/api/forgot-password"]);
});

test("global rate limiter throttles repeated API calls", async () => {
  const statuses = [];
  for (let i = 0; i < 12; i += 1) {
    const r = await fetch(`${baseUrl}/api/health-public`);
    statuses.push(r.status);
  }
  assert.ok(statuses.includes(200));
  assert.ok(statuses.includes(429));
});
