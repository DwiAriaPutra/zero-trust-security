import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createAuthApp } from "../apps/api-gateway/src/app.js";
import {
  ACCESS_TOKEN_LIFETIME_SECONDS,
  AuthError,
  AuthService,
  hashPassword,
  verifyAccessToken
} from "../packages/auth/src/index.js";
import { DEMO_ACCOUNTS, seedDemoAccounts } from "../packages/auth/src/seed.js";
import { migrate } from "../packages/database/src/migrate.js";
import { openDatabase } from "../packages/database/src/index.js";

const ACCESS_SECRET = "test-only-secret-with-at-least-32-bytes";
const USER_ID = "auth-test-user-001";
const EMAIL = "auth.test@zero-trust.local";
const PASSWORD = "Valid-Local-Password-2026!";
const DEVICE_ID = "auth-test-device-001";
const OTHER_DEVICE_ID = "auth-test-device-002";
const START_TIME = Date.UTC(2026, 0, 1, 12, 0, 0);

interface Fixture {
  database: ReturnType<typeof openDatabase>;
  auth: AuthService;
  now: () => number;
  setNow: (value: number) => void;
  close: () => void;
}

async function createFixture(): Promise<Fixture> {
  const directory = mkdtempSync(join(tmpdir(), "zero-trust-auth-"));
  const database = openDatabase(join(directory, "auth.sqlite"));
  migrate(database);
  const passwordHash = await hashPassword(PASSWORD, 4);
  database
    .prepare("INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)")
    .run(USER_ID, EMAIL, passwordHash, "MAHASISWA");
  database.prepare("INSERT INTO devices (id, user_id) VALUES (?, ?)").run(DEVICE_ID, USER_ID);

  let now = START_TIME;
  const auth = new AuthService(database, ACCESS_SECRET, {
    clock: () => now,
    bcryptRounds: 4
  });
  return {
    database,
    auth,
    now: () => now,
    setNow: (value) => {
      now = value;
    },
    close: () => {
      database.close();
      rmSync(directory, { recursive: true, force: true });
    }
  };
}

async function withFixture(run: (fixture: Fixture) => Promise<void>): Promise<void> {
  const fixture = await createFixture();
  try {
    await run(fixture);
  } finally {
    fixture.close();
  }
}

async function expectAuthError(operation: Promise<unknown> | (() => unknown), code: string): Promise<void> {
  const check = (error: unknown): boolean => error instanceof AuthError && error.code === code;
  if (typeof operation === "function") {
    assert.throws(operation, check);
  } else {
    await assert.rejects(operation, check);
  }
}

test("login succeeds with an active account, correct password, and registered device", async () => {
  await withFixture(async ({ auth, database }) => {
    const session = await auth.login(EMAIL.toUpperCase(), PASSWORD, DEVICE_ID);
    const claims = auth.verifyAccessToken(session.accessToken);
    const storedToken = database
      .prepare("SELECT token_hash FROM refresh_tokens WHERE user_id = ?")
      .get(USER_ID) as { token_hash: string };

    assert.equal(session.user.id, USER_ID);
    assert.equal(session.expiresIn, ACCESS_TOKEN_LIFETIME_SECONDS);
    assert.equal(claims.sub, USER_ID);
    assert.equal(claims.role, "MAHASISWA");
    assert.equal(claims.exp - claims.iat, 600);
    assert.notEqual(storedToken.token_hash, session.refreshToken);
    assert.equal(storedToken.token_hash.length, 64);
  });
});

test("login rejects an incorrect password", async () => {
  await withFixture(async ({ auth }) => {
    await expectAuthError(auth.login(EMAIL, "wrong-password-value", DEVICE_ID), "INVALID_CREDENTIALS_OR_DEVICE");
  });
});

test("login rejects a device that is not registered to the account", async () => {
  await withFixture(async ({ auth }) => {
    await expectAuthError(auth.login(EMAIL, PASSWORD, "unregistered-device-001"), "INVALID_CREDENTIALS_OR_DEVICE");
  });
});

test("login rejects an inactive account", async () => {
  await withFixture(async ({ auth, database }) => {
    database.prepare("UPDATE users SET is_active = 0 WHERE id = ?").run(USER_ID);
    await expectAuthError(auth.login(EMAIL, PASSWORD, DEVICE_ID), "INVALID_CREDENTIALS_OR_DEVICE");
  });
});

test("JWT validation rejects expired tokens and signatures that do not match", async () => {
  await withFixture(async ({ auth, now }) => {
    const session = await auth.login(EMAIL, PASSWORD, DEVICE_ID);
    await expectAuthError(
      () => verifyAccessToken(session.accessToken, ACCESS_SECRET, now() + 600_000),
      "INVALID_ACCESS_TOKEN"
    );
    const lastCharacter = session.accessToken.endsWith("A") ? "B" : "A";
    const altered = `${session.accessToken.slice(0, -1)}${lastCharacter}`;
    await expectAuthError(() => auth.verifyAccessToken(altered), "INVALID_ACCESS_TOKEN");
    const [, payload, signature] = session.accessToken.split(".");
    assert.ok(payload && signature);
    const unsupportedHeader = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    await expectAuthError(
      () => auth.verifyAccessToken(`${unsupportedHeader}.${payload}.${signature}`),
      "INVALID_ACCESS_TOKEN"
    );
  });
});

test("refresh rotates the old token and rejects reuse", async () => {
  await withFixture(async ({ auth }) => {
    const original = await auth.login(EMAIL, PASSWORD, DEVICE_ID);
    const rotated = await auth.refresh(original.refreshToken, DEVICE_ID);
    assert.notEqual(rotated.refreshToken, original.refreshToken);
    await expectAuthError(auth.refresh(original.refreshToken, DEVICE_ID), "INVALID_REFRESH_TOKEN");

    const secondRotation = await auth.refresh(rotated.refreshToken, DEVICE_ID);
    assert.notEqual(secondRotation.refreshToken, rotated.refreshToken);
  });
});

test("refresh rejects an expired token", async () => {
  await withFixture(async ({ auth, setNow }) => {
    const session = await auth.login(EMAIL, PASSWORD, DEVICE_ID);
    setNow(START_TIME + 24 * 60 * 60 * 1000);
    await expectAuthError(auth.refresh(session.refreshToken, DEVICE_ID), "INVALID_REFRESH_TOKEN");
  });
});

test("logout revokes the supplied refresh token", async () => {
  await withFixture(async ({ auth }) => {
    const session = await auth.login(EMAIL, PASSWORD, DEVICE_ID);
    auth.logout(DEVICE_ID, session.refreshToken);
    await expectAuthError(auth.refresh(session.refreshToken, DEVICE_ID), "INVALID_REFRESH_TOKEN");
  });
});

test("device enrollment requires a trusted session and revocation disables that device", async () => {
  await withFixture(async ({ auth, database }) => {
    await expectAuthError(
      auth.login(EMAIL, PASSWORD, OTHER_DEVICE_ID),
      "INVALID_CREDENTIALS_OR_DEVICE"
    );

    const original = await auth.login(EMAIL, PASSWORD, DEVICE_ID);
    const claims = auth.verifyAccessToken(original.accessToken);
    auth.assertTrustedDevice(claims.sub, DEVICE_ID);
    auth.registerDevice(claims.sub, OTHER_DEVICE_ID);
    const secondDeviceSession = await auth.login(EMAIL, PASSWORD, OTHER_DEVICE_ID);
    auth.revokeDevice(claims.sub, OTHER_DEVICE_ID);

    await expectAuthError(
      auth.login(EMAIL, PASSWORD, OTHER_DEVICE_ID),
      "INVALID_CREDENTIALS_OR_DEVICE"
    );
    await expectAuthError(
      auth.refresh(secondDeviceSession.refreshToken, OTHER_DEVICE_ID),
      "INVALID_REFRESH_TOKEN"
    );
    await expectAuthError(
      () => auth.revokeDevice(claims.sub, DEVICE_ID),
      "CANNOT_REVOKE_LAST_DEVICE"
    );
    const deniedDeviceRevoke = database
      .prepare("SELECT decision, reason_code FROM audit_logs WHERE action = 'DEVICE_REVOKE' ORDER BY rowid DESC LIMIT 1")
      .get() as { decision: string; reason_code: string };
    assert.deepEqual(deniedDeviceRevoke, { decision: "DENY", reason_code: "CANNOT_REVOKE_LAST_DEVICE" });
  });
});

test("auth HTTP endpoints login, list devices, and enroll through a trusted session", async () => {
  await withFixture(async ({ auth, database }) => {
    const server = createServer(createAuthApp(auth));
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });

    try {
      const address = server.address();
      assert.ok(address && typeof address !== "string");
      const baseUrl = `http://127.0.0.1:${address.port}`;
      const loginResponse = await fetch(`${baseUrl}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-device-id": DEVICE_ID },
        body: JSON.stringify({ email: EMAIL, password: PASSWORD })
      });
      assert.equal(loginResponse.status, 200);
      const loginCorrelationId = loginResponse.headers.get("x-correlation-id");
      assert.ok(loginCorrelationId);
      const loginAudit = database
        .prepare("SELECT correlation_id FROM audit_logs WHERE action = 'LOGIN' ORDER BY rowid DESC LIMIT 1")
        .get() as { correlation_id: string };
      assert.equal(loginAudit.correlation_id, loginCorrelationId);
      const session = (await loginResponse.json()) as { accessToken: string; refreshToken: string };
      const headers = {
        authorization: `Bearer ${session.accessToken}`,
        "content-type": "application/json",
        "x-device-id": DEVICE_ID
      };

      const listResponse = await fetch(`${baseUrl}/auth/devices`, { headers });
      assert.equal(listResponse.status, 200);
      const enrollResponse = await fetch(`${baseUrl}/auth/devices`, {
        method: "POST",
        headers,
        body: JSON.stringify({ deviceId: OTHER_DEVICE_ID })
      });
      assert.equal(enrollResponse.status, 201);

      const refreshResponse = await fetch(`${baseUrl}/auth/refresh`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-device-id": DEVICE_ID
        },
        body: JSON.stringify({ refreshToken: session.refreshToken })
      });
      assert.equal(refreshResponse.status, 200);
      const rotated = (await refreshResponse.json()) as { refreshToken: string };

      const logoutResponse = await fetch(`${baseUrl}/auth/logout`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-device-id": DEVICE_ID
        },
        body: JSON.stringify({ refreshToken: rotated.refreshToken })
      });
      assert.equal(logoutResponse.status, 204);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });
});

test("demo seeding creates six accounts and devices idempotently without storing plaintext passwords", async () => {
  const directory = mkdtempSync(join(tmpdir(), "zero-trust-seed-"));
  const database = openDatabase(join(directory, "seed.sqlite"));
  try {
    migrate(database);
    await seedDemoAccounts(database);
    database.prepare("UPDATE users SET nim = NULL WHERE id = ?").run("demo-student-001");
    database.prepare("UPDATE users SET nim = ? WHERE id = ?").run("student-nim-custom", "demo-student-002");
    await seedDemoAccounts(database);
    const counts = database
      .prepare(`
        SELECT (SELECT COUNT(*) FROM users) AS users,
               (SELECT COUNT(*) FROM devices) AS devices
      `)
      .get() as { users: number; devices: number };
    const plaintextMatches = database
      .prepare("SELECT COUNT(*) AS count FROM users WHERE password_hash IN (?, ?, ?, ?, ?, ?)")
      .get(...DEMO_ACCOUNTS.map((account) => account.password)) as { count: number };
    const demoNims = database.prepare("SELECT id, nim FROM users WHERE role = 'MAHASISWA' ORDER BY id")
      .all() as Array<{ id: string; nim: string }>;

    assert.deepEqual(counts, { users: 6, devices: 6 });
    assert.equal(plaintextMatches.count, 0);
    assert.deepEqual(demoNims, [
      { id: "demo-student-001", nim: "demo-student-001" },
      { id: "demo-student-002", nim: "student-nim-custom" },
      { id: "demo-student-003", nim: "demo-student-003" }
    ]);
  } finally {
    database.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
