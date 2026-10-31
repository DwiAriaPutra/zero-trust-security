import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import express from "express";
import {
  createProtectedPolicyMiddleware,
  correlationIdMiddleware,
  safeErrorHandler
} from "../apps/api-gateway/src/middleware.js";
import { AuthService, hashPassword } from "../packages/auth/src/index.js";
import { migrate } from "../packages/database/src/migrate.js";
import { openDatabase } from "../packages/database/src/index.js";

const ACCESS_SECRET = "gateway-test-secret-with-at-least-32-bytes";
const USER_ID = "gateway-student-001";
const OTHER_USER_ID = "gateway-student-002";
const EMAIL = "gateway.student@zero-trust.local";
const PASSWORD = "Gateway-Test-Password-2026!";
const DEVICE_ID = "gateway-device-001";
const FOREIGN_DEVICE_ID = "gateway-device-002";
const NOW = new Date("2026-01-01T05:00:00.000Z");

interface GatewayFixture {
  database: ReturnType<typeof openDatabase>;
  auth: AuthService;
  accessToken: string;
  setTime: (time: number) => void;
  close: () => void;
}

async function createGatewayFixture(): Promise<GatewayFixture> {
  const directory = mkdtempSync(join(tmpdir(), "zero-trust-gateway-policy-"));
  const database = openDatabase(join(directory, "gateway.sqlite"));
  migrate(database);
  const passwordHash = await hashPassword(PASSWORD, 4);
  database
    .prepare("INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)")
    .run(USER_ID, EMAIL, passwordHash, "MAHASISWA");
  database
    .prepare("INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)")
    .run(OTHER_USER_ID, "other.gateway@zero-trust.local", passwordHash, "MAHASISWA");
  database.prepare("INSERT INTO devices (id, user_id) VALUES (?, ?)").run(DEVICE_ID, USER_ID);
  database
    .prepare("INSERT INTO devices (id, user_id) VALUES (?, ?)")
    .run(FOREIGN_DEVICE_ID, OTHER_USER_ID);

  let now = NOW.getTime();
  const auth = new AuthService(database, ACCESS_SECRET, {
    clock: () => now,
    bcryptRounds: 4
  });
  const session = await auth.login(EMAIL, PASSWORD, DEVICE_ID);
  return {
    database,
    auth,
    accessToken: session.accessToken,
    setTime: (time) => {
      now = time;
    },
    close: () => {
      database.close();
      rmSync(directory, { recursive: true, force: true });
    }
  };
}

async function withGateway<T>(
  run: (context: {
    fixture: GatewayFixture;
    request: (headers?: Record<string, string>) => Promise<Response>;
  }) => Promise<T>
): Promise<T> {
  const fixture = await createGatewayFixture();
  const app = express();
  app.use(correlationIdMiddleware);
  app.get(
    "/test-policy-probe",
    createProtectedPolicyMiddleware(
      fixture.auth,
      fixture.database,
      "grade:read",
      "grade",
      () => ({
        type: "ignored-by-middleware",
        id: "grade-0001",
        ownerId: fixture.auth.verifyAccessToken(fixture.accessToken).sub
      })
    ),
    (_request, response) => response.status(200).json({ allowed: true })
  );
  app.use(safeErrorHandler);
  const server = createServer(app);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    return await run({
      fixture,
      request: (headers = {}) => fetch(`${baseUrl}/test-policy-probe`, { headers })
    });
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
    fixture.close();
  }
}

test("Gateway policy middleware rejects a missing JWT and audits DENY", async () => {
  await withGateway(async ({ fixture, request }) => {
    const response = await request({ "x-device-id": DEVICE_ID });
    assert.equal(response.status, 401);
    const audit = fixture.database
      .prepare("SELECT decision, reason_code FROM audit_logs WHERE action = 'ACCESS_TOKEN_VALIDATE' ORDER BY rowid DESC LIMIT 1")
      .get() as { decision: string; reason_code: string };
    assert.deepEqual(audit, { decision: "DENY", reason_code: "INVALID_ACCESS_TOKEN" });
  });
});

test("Gateway policy middleware rejects invalid and expired JWTs", async () => {
  await withGateway(async ({ fixture, request }) => {
    const invalid = fixture.accessToken.slice(0, -1) + (fixture.accessToken.endsWith("A") ? "B" : "A");
    const invalidResponse = await request({
      authorization: `Bearer ${invalid}`,
      "x-device-id": DEVICE_ID
    });
    assert.equal(invalidResponse.status, 401);

    fixture.setTime(NOW.getTime() + 600_000);
    const expiredResponse = await request({
      authorization: `Bearer ${fixture.accessToken}`,
      "x-device-id": DEVICE_ID
    });
    assert.equal(expiredResponse.status, 401);
  });
});

test("Gateway policy middleware rejects a missing X-Device-ID", async () => {
  await withGateway(async ({ fixture, request }) => {
    const response = await request({ authorization: `Bearer ${fixture.accessToken}` });
    assert.equal(response.status, 401);
    const audit = fixture.database
      .prepare("SELECT decision, reason_code FROM audit_logs WHERE action = 'DEVICE_VERIFY' ORDER BY rowid DESC LIMIT 1")
      .get() as { decision: string; reason_code: string };
    assert.deepEqual(audit, { decision: "DENY", reason_code: "DEVICE_ID_REQUIRED" });
  });
});

test("Gateway policy middleware rejects a device belonging to another user", async () => {
  await withGateway(async ({ fixture, request }) => {
    const response = await request({
      authorization: `Bearer ${fixture.accessToken}`,
      "x-device-id": FOREIGN_DEVICE_ID
    });
    assert.equal(response.status, 401);
    const audit = fixture.database
      .prepare("SELECT decision, reason_code FROM audit_logs WHERE action = 'DEVICE_VERIFICATION' ORDER BY rowid DESC LIMIT 1")
      .get() as { decision: string; reason_code: string };
    assert.deepEqual(audit, { decision: "DENY", reason_code: "DEVICE_UNTRUSTED" });
  });
});

test("Gateway policy decision logs ALLOW and DENY with correlation and resource references", async () => {
  await withGateway(async ({ fixture, request }) => {
    const headers = {
      authorization: `Bearer ${fixture.accessToken}`,
      "x-device-id": DEVICE_ID
    };
    const allowed = await request(headers);
    assert.equal(allowed.status, 200);
    const correlationId = allowed.headers.get("x-correlation-id");
    assert.ok(correlationId);

    const allowedAudit = fixture.database
      .prepare("SELECT correlation_id, actor_id, action, resource, endpoint, device_id, decision, reason_code FROM audit_logs WHERE action = 'grade:read' ORDER BY rowid DESC LIMIT 1")
      .get() as {
      correlation_id: string;
      actor_id: string;
      action: string;
      resource: string;
      endpoint: string;
      device_id: string;
      decision: string;
      reason_code: string;
    };
    assert.equal(allowedAudit.correlation_id, correlationId);
    assert.equal(allowedAudit.actor_id, USER_ID);
    assert.equal(allowedAudit.action, "grade:read");
    assert.match(allowedAudit.resource, /^grade:[a-f0-9]{24}$/u);
    assert.equal(allowedAudit.endpoint, "/test-policy-probe");
    assert.equal(allowedAudit.device_id, DEVICE_ID);
    assert.equal(allowedAudit.decision, "ALLOW");
    assert.equal(allowedAudit.reason_code, "POLICY_ALLOW");

    // A second protected route is mounted with a mismatched owner to exercise policy DENY.
    const denyApp = express();
    denyApp.use(correlationIdMiddleware);
    denyApp.get(
      "/test-policy-probe",
      createProtectedPolicyMiddleware(
        fixture.auth,
        fixture.database,
        "grade:read",
        "grade",
        () => ({ type: "grade", id: "grade-0002", ownerId: OTHER_USER_ID })
      ),
      (_request, response) => response.status(200).end()
    );
    denyApp.use(safeErrorHandler);
    const denyServer = createServer(denyApp);
    await new Promise<void>((resolve, reject) => {
      denyServer.once("error", reject);
      denyServer.listen(0, "127.0.0.1", resolve);
    });
    try {
      const denyAddress = denyServer.address();
      assert.ok(denyAddress && typeof denyAddress !== "string");
      const denied = await fetch(`http://127.0.0.1:${denyAddress.port}/test-policy-probe`, { headers });
      assert.equal(denied.status, 403);
      const deniedAudit = fixture.database
        .prepare("SELECT decision, reason_code FROM audit_logs WHERE action = 'grade:read' AND resource LIKE 'grade:%' ORDER BY rowid DESC LIMIT 1")
        .get() as { decision: string; reason_code: string };
      assert.deepEqual(deniedAudit, { decision: "DENY", reason_code: "OWNERSHIP_MISMATCH" });
    } finally {
      await new Promise<void>((resolve, reject) => {
        denyServer.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });
});
