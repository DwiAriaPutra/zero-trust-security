import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createAuthApp } from "../apps/api-gateway/src/app.js";
import { createTranscriptApp } from "../apps/service-transkrip/src/app.js";
import { createNilaiApp } from "../apps/service-nilai/src/app.js";
import { createTranscriptSyncClient } from "../apps/service-nilai/src/transcript-sync-client.js";
import { AuthService, hashPassword, signServiceToken, verifyServiceToken } from "../packages/auth/src/index.js";
import { migrate } from "../packages/database/src/migrate.js";
import { openDatabase } from "../packages/database/src/index.js";

const JWT_SECRET = "fase-enam-test-jwt-secret-32-bytes-minimum";
const GATEWAY_SECRET = "fase-enam-test-gateway-secret-32-bytes-minimum";
const SERVICE_SECRET = "fase-enam-test-service-token-secret-32-bytes";
const CLIENT_ID = "service-nilai-test";
const CLIENT_SECRET = "fase-enam-service-client-secret-32-bytes";
const PASSWORD = "Integration-Test-Password-2026!";
const USERS = {
  admin: { id: "test-admin", email: "admin@phase6.test", role: "ADMIN", device: "device-admin-001" },
  lecturer: { id: "test-lecturer", email: "lecturer@phase6.test", role: "DOSEN", device: "device-lecturer-1" },
  student1: { id: "test-student-1", email: "student1@phase6.test", role: "MAHASISWA", device: "device-student-001", nim: "202600001" },
  student2: { id: "test-student-2", email: "student2@phase6.test", role: "MAHASISWA", device: "device-student-002", nim: "202600002" }
} as const;
type Actor = keyof typeof USERS;

interface TestServer {
  url: string;
  close(): Promise<void>;
}

async function listen(app: import("express").Express): Promise<TestServer> {
  const server: Server = createServer(app);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  };
}

async function fixture(): Promise<{
  database: ReturnType<typeof openDatabase>;
  auth: AuthService;
  tokens: Record<Actor, string>;
  devices: Record<Actor, string>;
  nim: Record<"student1" | "student2", string>;
  transcript: TestServer;
  cleanup(): Promise<void>;
}> {
  const directory = mkdtempSync(join(tmpdir(), "zero-trust-transcript-"));
  const database = openDatabase(join(directory, "transcripts.sqlite"));
  migrate(database);
  database.prepare("UPDATE access_policies SET start_time = '00:00', end_time = '23:59' WHERE id = 1").run();
  const passwordHash = await hashPassword(PASSWORD, 4);
  for (const user of Object.values(USERS)) {
    database.prepare("INSERT INTO users (id, email, password_hash, role, nim) VALUES (?, ?, ?, ?, ?)")
      .run(user.id, user.email, passwordHash, user.role, "nim" in user ? user.nim : null);
    database.prepare("INSERT INTO devices (id, user_id) VALUES (?, ?)").run(user.device, user.id);
  }
  database.prepare("INSERT INTO classes (id, name, lecturer_id, term) VALUES (?, ?, ?, ?)")
    .run("phase6-class-1", "Keamanan Informasi", USERS.lecturer.id, "2026-Ganjil");
  const enrollment = database.prepare("INSERT INTO enrollments (class_id, student_id) VALUES (?, ?)");
  enrollment.run("phase6-class-1", USERS.student1.id);
  enrollment.run("phase6-class-1", USERS.student2.id);
  const grade = database.prepare("INSERT INTO grades (class_id, student_id, score) VALUES (?, ?, ?)");
  grade.run("phase6-class-1", USERS.student1.id, 87);
  grade.run("phase6-class-1", USERS.student2.id, 92);

  const auth = new AuthService(database, JWT_SECRET, { bcryptRounds: 4 });
  const tokens = {} as Record<Actor, string>;
  for (const [actor, user] of Object.entries(USERS) as Array<[Actor, (typeof USERS)[Actor]]>) {
    tokens[actor] = (await auth.login(user.email, PASSWORD, user.device)).accessToken;
  }
  const transcript = await listen(createTranscriptApp(database, auth, GATEWAY_SECRET, SERVICE_SECRET));
  return {
    database, auth, tokens,
    devices: Object.fromEntries(Object.entries(USERS).map(([key, value]) => [key, value.device])) as Record<Actor, string>,
    nim: { student1: USERS.student1.nim, student2: USERS.student2.nim },
    transcript,
    async cleanup() {
      await transcript.close();
      database.close();
      rmSync(directory, { recursive: true, force: true });
    }
  };
}

async function withFixture(run: (state: Awaited<ReturnType<typeof fixture>>) => Promise<void>): Promise<void> {
  const state = await fixture();
  try { await run(state); } finally { await state.cleanup(); }
}

function gatewayFor(state: Awaited<ReturnType<typeof fixture>>, nilaiUrl?: string): Promise<TestServer> {
  return listen(createAuthApp(state.auth, {
    database: state.database,
    gatewaySecret: GATEWAY_SECRET,
    transcriptBaseUrl: state.transcript.url,
    serviceTokenSecret: SERVICE_SECRET,
    serviceNilaiClientId: CLIENT_ID,
    serviceNilaiClientSecret: CLIENT_SECRET,
    ...(nilaiUrl ? { nilaiBaseUrl: nilaiUrl } : {})
  }));
}

function userHeaders(token: string, deviceId: string, secret = GATEWAY_SECRET): Record<string, string> {
  return { authorization: `Bearer ${token}`, "x-device-id": deviceId, "x-gateway-secret": secret };
}

function manualToken(payload: Record<string, unknown>, secret = SERVICE_SECRET): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signed = `${header}.${body}`;
  return `${signed}.${createHmac("sha256", secret).update(signed).digest("base64url")}`;
}

test("Gateway service-token endpoint rejects bad credentials and issues a five-minute typed service token", async () => {
  await withFixture(async (state) => {
    const gateway = await gatewayFor(state);
    try {
      const bad = await fetch(`${gateway.url}/auth/service`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_id: CLIENT_ID, client_secret: `${CLIENT_SECRET}wrong` })
      });
      assert.equal(bad.status, 401);
      const good = await fetch(`${gateway.url}/auth/service`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET })
      });
      assert.equal(good.status, 200);
      const result = await good.json() as { accessToken: string; expiresIn: number; tokenType: string };
      assert.equal(result.expiresIn, 300);
      assert.equal(result.tokenType, "Bearer");
      const claims = verifyServiceToken(result.accessToken, SERVICE_SECRET);
      assert.equal(claims.sub, "service-nilai");
      assert.equal(claims.role, "service");
      const audit = state.database.prepare("SELECT decision, reason_code FROM audit_logs WHERE action = 'SERVICE_TOKEN_ISSUE' ORDER BY rowid").all();
      assert.deepEqual(audit, [
        { decision: "DENY", reason_code: "INVALID_SERVICE_CREDENTIALS" },
        { decision: "ALLOW", reason_code: "SERVICE_AUTHENTICATED" }
      ]);
      const auditText = JSON.stringify(state.database.prepare("SELECT * FROM audit_logs").all());
      assert.equal(auditText.includes(CLIENT_SECRET), false);
      assert.equal(auditText.includes(result.accessToken), false);
    } finally { await gateway.close(); }
  });
});

test("service-token verifier rejects expiry, user token shape, wrong role, and wrong service identity", async () => {
  await withFixture(async (state) => {
    const now = Date.now();
    const good = signServiceToken("service-nilai", SERVICE_SECRET, now);
    assert.equal(verifyServiceToken(good, SERVICE_SECRET, "service-nilai", now).aud, "service-transkrip");
    assert.throws(() => verifyServiceToken(good, SERVICE_SECRET, "service-nilai", now + 300_001), /INVALID_SERVICE_TOKEN/u);
    const wrong = manualToken({
      sub: "test-admin", role: "ADMIN", token_use: "user", service: "service-nilai",
      aud: "service-transkrip", iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 100
    });
    assert.throws(() => verifyServiceToken(wrong, SERVICE_SECRET), /INVALID_SERVICE_TOKEN/u);
    const wrongRole = manualToken({
      sub: "service-nilai", role: "ADMIN", token_use: "service", service: "service-nilai",
      aud: "service-transkrip", iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 100
    });
    assert.throws(() => verifyServiceToken(wrongRole, SERVICE_SECRET), /INVALID_SERVICE_TOKEN/u);
    assert.throws(() => verifyServiceToken(good, SERVICE_SECRET, "service-other"), /INVALID_SERVICE_TOKEN/u);
  });
});

test("Gateway and Service Transkrip enforce owner, admin, role, device, secret, and local-only access over HTTP", async () => {
  await withFixture(async (state) => {
    state.database.prepare(`
      INSERT INTO transcripts (id, class_id, student_id, snapshot_json, source_version)
      VALUES (?, ?, ?, ?, ?)
    `).run(randomUUID(), "phase6-class-1", USERS.student2.id, JSON.stringify({
      classId: "phase6-class-1", className: "Keamanan Informasi", term: "2026-Ganjil",
      studentId: USERS.student2.id, score: 92
    }), 0);
    const gateway = await gatewayFor(state);
    try {
      const own = await fetch(`${gateway.url}/transkrip/${state.nim.student1}`, {
        headers: userHeaders(state.tokens.student1, state.devices.student1)
      });
      assert.equal(own.status, 200);
      const otherStudent = await fetch(`${gateway.url}/transkrip/${state.nim.student2}`, {
        headers: userHeaders(state.tokens.student1, state.devices.student1)
      });
      assert.equal(otherStudent.status, 403);
      const admin = await fetch(`${gateway.url}/transkrip/${state.nim.student2}`, {
        headers: userHeaders(state.tokens.admin, state.devices.admin)
      });
      assert.equal(admin.status, 200);
      const adminResult = await admin.json() as { transcripts: Array<{ score: number }> };
      assert.equal(adminResult.transcripts[0]?.score, 92);
      const adminAudit = state.database.prepare(`
        SELECT endpoint, device_id FROM audit_logs
        WHERE action = 'transcript:read' AND actor_id = ? ORDER BY rowid DESC LIMIT 1
      `).get(USERS.admin.id) as { endpoint: string; device_id: string };
      assert.deepEqual(adminAudit, { endpoint: "/transkrip/:nim", device_id: USERS.admin.device });
      const lecturer = await fetch(`${gateway.url}/transkrip/${state.nim.student1}`, {
        headers: userHeaders(state.tokens.lecturer, state.devices.lecturer)
      });
      assert.equal(lecturer.status, 403);

      const missingDevice = await fetch(`${state.transcript.url}/transkrip/${state.nim.student1}`, {
        headers: { "x-gateway-secret": GATEWAY_SECRET, authorization: `Bearer ${state.tokens.student1}` }
      });
      assert.equal(missingDevice.status, 401);
      const wrongDevice = await fetch(`${state.transcript.url}/transkrip/${state.nim.student1}`, {
        headers: userHeaders(state.tokens.student1, state.devices.student2)
      });
      assert.equal(wrongDevice.status, 401);
      const missingSecret = await fetch(`${state.transcript.url}/transkrip/${state.nim.student1}`, {
        headers: { authorization: `Bearer ${state.tokens.student1}`, "x-device-id": state.devices.student1 }
      });
      assert.equal(missingSecret.status, 401);
      const wrongSecret = await fetch(`${state.transcript.url}/transkrip/${state.nim.student1}`, {
        headers: userHeaders(state.tokens.student1, state.devices.student1, "incorrect-gateway-secret")
      });
      assert.equal(wrongSecret.status, 401);
    } finally { await gateway.close(); }
  });
});

test("transcript synchronization accepts only service tokens and remains idempotent", async () => {
  await withFixture(async (state) => {
    state.database.prepare("UPDATE classes SET finalization_status = 'FINALIZING' WHERE id = ?").run("phase6-class-1");
    const gateway = await gatewayFor(state);
    try {
      const body = {
        classId: "phase6-class-1", sourceVersion: 0,
        grades: [
          { studentId: USERS.student1.id, score: 87 },
          { studentId: USERS.student2.id, score: 92 }
        ]
      };
      const serviceToken = signServiceToken("service-nilai", SERVICE_SECRET);
      const sync = () => fetch(`${gateway.url}/transkrip/sinkron`, {
        method: "POST", headers: { authorization: `Bearer ${serviceToken}`, "content-type": "application/json" },
        body: JSON.stringify(body)
      });
      const first = await sync();
      assert.equal(first.status, 200);
      const second = await sync();
      assert.equal(second.status, 200);
      const count = state.database.prepare("SELECT COUNT(*) AS count FROM transcripts").get() as { count: number };
      assert.equal(count.count, 2);
      const userToken = await fetch(`${gateway.url}/transkrip/sinkron`, {
        method: "POST", headers: { authorization: `Bearer ${state.tokens.admin}`, "content-type": "application/json" },
        body: JSON.stringify(body)
      });
      assert.equal(userToken.status, 401);
      const expiredToken = signServiceToken("service-nilai", SERVICE_SECRET, Date.now() - 301_000);
      const expired = await fetch(`${gateway.url}/transkrip/sinkron`, {
        method: "POST", headers: { authorization: `Bearer ${expiredToken}`, "content-type": "application/json" },
        body: JSON.stringify(body)
      });
      assert.equal(expired.status, 401);
      const invalidPayload = await fetch(`${gateway.url}/transkrip/sinkron`, {
        method: "POST", headers: { authorization: `Bearer ${serviceToken}`, "content-type": "application/json" },
        body: JSON.stringify({ ...body, unexpected: "field" })
      });
      assert.equal(invalidPayload.status, 400);
      const directWithoutSecret = await fetch(`${state.transcript.url}/transkrip/sinkron`, {
        method: "POST", headers: { authorization: `Bearer ${serviceToken}`, "content-type": "application/json" },
        body: JSON.stringify(body)
      });
      assert.equal(directWithoutSecret.status, 401);
      const audits = state.database.prepare("SELECT decision, reason_code FROM audit_logs WHERE action = 'transcript:sync'").all() as Array<{ decision: string; reason_code: string }>;
      assert.ok(audits.some((entry) => entry.decision === "ALLOW" && entry.reason_code === "TRANSCRIPT_SYNCED"));
      assert.ok(audits.some((entry) => entry.decision === "DENY"));
      const auditText = JSON.stringify(state.database.prepare("SELECT * FROM audit_logs").all());
      assert.equal(auditText.includes(serviceToken), false);
      assert.equal(auditText.includes(SERVICE_SECRET), false);
      assert.equal(auditText.includes(GATEWAY_SECRET), false);
    } finally { await gateway.close(); }
  });
});

test("finalization syncs through the Gateway and only then marks the class finalized", async () => {
  await withFixture(async (state) => {
    let gatewayUrl = "";
    let syncCalls = 0;
    let releaseSyncs!: () => void;
    const bothSyncRequests = new Promise<void>((resolve) => { releaseSyncs = resolve; });
    const syncClient = (payload: Parameters<ReturnType<typeof createTranscriptSyncClient>>[0]) =>
      createTranscriptSyncClient({ gatewayBaseUrl: gatewayUrl, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET })(payload);
    const nilai = await listen(createNilaiApp(state.database, state.auth, GATEWAY_SECRET, {
      transcriptSync: async (payload) => {
        syncCalls += 1;
        if (syncCalls === 2) releaseSyncs();
        await bothSyncRequests;
        await syncClient(payload);
      }
    }));
    const gateway = await gatewayFor(state, nilai.url);
    gatewayUrl = gateway.url;
    try {
      const health = await fetch(`${gateway.url}/health`);
      assert.equal(health.status, 200);
      const healthBody = await health.json() as { status: string; services: Record<string, string> };
      assert.equal(healthBody.status, "ok");
      assert.deepEqual(healthBody.services, { nilai: "ok", transkrip: "ok" });
      const finalize = () => fetch(`${gateway.url}/kelas/phase6-class-1/finalisasi`, {
        method: "POST", headers: userHeaders(state.tokens.lecturer, state.devices.lecturer)
      });
      const concurrent = await Promise.all([finalize(), finalize()]);
      assert.deepEqual(concurrent.map((response) => response.status), [200, 200]);
      for (const response of concurrent) {
        const result = await response.json() as { classId: string; status: string; sourceVersion: number };
        assert.deepEqual(result, { classId: "phase6-class-1", status: "FINALIZED", sourceVersion: 0 });
      }
      assert.equal(syncCalls, 2);
      const status = state.database.prepare("SELECT finalization_status FROM classes WHERE id = ?")
        .get("phase6-class-1") as { finalization_status: string };
      const transcriptCount = state.database.prepare("SELECT COUNT(*) AS count FROM transcripts").get() as { count: number };
      assert.equal(status.finalization_status, "FINALIZED");
      assert.equal(transcriptCount.count, 2);
      const repeated = await finalize();
      assert.equal(repeated.status, 200);
      assert.equal(syncCalls, 2);
      const read = await fetch(`${gateway.url}/transkrip/${state.nim.student1}`, {
        headers: userHeaders(state.tokens.student1, state.devices.student1)
      });
      assert.equal(read.status, 200);
      const resultBody = await read.json() as { transcripts: Array<{ score: number }> };
      assert.equal(resultBody.transcripts[0]?.score, 87);
    } finally {
      await gateway.close();
      await nilai.close();
    }
  });
});

test("failed transcript synchronization keeps the class locked in FINALIZING and permits an idempotent retry", async () => {
  await withFixture(async (state) => {
    let available = false;
    const nilai = await listen(createNilaiApp(state.database, state.auth, GATEWAY_SECRET, {
      transcriptSync: async () => {
        if (!available) throw new DOMException("upstream timed out", "TimeoutError");
        const storedGrades = state.database.prepare("SELECT student_id AS studentId, score FROM grades WHERE class_id = ?")
          .all("phase6-class-1") as Array<{ studentId: string; score: number }>;
        const storeSnapshot = state.database.prepare(`
          INSERT INTO transcripts (id, class_id, student_id, snapshot_json, source_version)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(class_id, student_id) DO UPDATE SET
            snapshot_json = excluded.snapshot_json, source_version = excluded.source_version
        `);
        for (const grade of storedGrades) {
          storeSnapshot.run(randomUUID(), "phase6-class-1", grade.studentId, JSON.stringify(grade), 0);
        }
      }
    }));
    try {
      const headers = userHeaders(state.tokens.lecturer, state.devices.lecturer);
      const finalize = () => fetch(`${nilai.url}/nilai/kelas/phase6-class-1/finalisasi`, {
        method: "POST", headers
      });
      const first = await finalize();
      assert.equal(first.status, 503);
      assert.deepEqual(await first.json(), { error: "TRANSCRIPT_SYNC_PENDING", classId: "phase6-class-1" });
      const pending = state.database.prepare("SELECT finalization_status FROM classes WHERE id = ?")
        .get("phase6-class-1") as { finalization_status: string };
      assert.equal(pending.finalization_status, "FINALIZING");
      const noPartialTranscript = state.database.prepare("SELECT COUNT(*) AS count FROM transcripts")
        .get() as { count: number };
      assert.equal(noPartialTranscript.count, 0);
      const update = await fetch(`${nilai.url}/nilai/kelas/phase6-class-1/mahasiswa/${USERS.student1.id}`, {
        method: "PATCH", headers: { ...headers, "content-type": "application/json" },
        body: JSON.stringify({ score: 99 })
      });
      assert.equal(update.status, 403);

      available = true;
      const retry = await finalize();
      assert.equal(retry.status, 200);
      const done = state.database.prepare("SELECT finalization_status FROM classes WHERE id = ?")
        .get("phase6-class-1") as { finalization_status: string };
      assert.equal(done.finalization_status, "FINALIZED");
      const retriedTranscriptCount = state.database.prepare("SELECT COUNT(*) AS count FROM transcripts")
        .get() as { count: number };
      assert.equal(retriedTranscriptCount.count, 2);
    } finally { await nilai.close(); }
  });
});

