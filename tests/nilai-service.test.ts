import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createAuthApp } from "../apps/api-gateway/src/app.js";
import { AuthService, hashPassword, type AuthSession } from "../packages/auth/src/index.js";
import { migrate } from "../packages/database/src/migrate.js";
import { openDatabase } from "../packages/database/src/index.js";
import { seedNilaiDemoData } from "../apps/service-nilai/src/seed.js";
import { createNilaiApp } from "../apps/service-nilai/src/app.js";

const ACCESS_SECRET = "fase-lima-test-access-secret-at-least-32-bytes";
const GATEWAY_SECRET = "fase-lima-test-gateway-secret-at-least-32-bytes";
const PASSWORD = "Local-Test-Password-2026!";
const START = Date.UTC(2026, 0, 1, 13, 59, 0); // 20:59 Asia/Jakarta
const USERS = {
  lecturer1: { id: "nilai-lecturer-001", email: "lecturer1@nilai.test", role: "DOSEN", device: "nilai-device-lecturer-1" },
  lecturer2: { id: "nilai-lecturer-002", email: "lecturer2@nilai.test", role: "DOSEN", device: "nilai-device-lecturer-2" },
  student1: { id: "nilai-student-001", email: "student1@nilai.test", role: "MAHASISWA", device: "nilai-device-student-1" },
  student2: { id: "nilai-student-002", email: "student2@nilai.test", role: "MAHASISWA", device: "nilai-device-student-2" },
  student3: { id: "nilai-student-003", email: "student3@nilai.test", role: "MAHASISWA", device: "nilai-device-student-3" },
  admin: { id: "nilai-admin-001", email: "admin@nilai.test", role: "ADMIN", device: "nilai-device-admin-1" }
} as const;

type Actor = keyof typeof USERS;

interface HttpServer {
  server: Server;
  url: string;
  close: () => Promise<void>;
}

interface Fixture {
  database: ReturnType<typeof openDatabase>;
  auth: AuthService;
  sessions: Record<Actor, AuthSession>;
  getNow: () => Date;
  setNow: (value: number) => void;
  service: HttpServer;
  close: () => Promise<void>;
}

async function listen(app: import("express").Express): Promise<HttpServer> {
  const server = createServer(app);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return {
    server,
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    })
  };
}

async function createFixture(): Promise<Fixture> {
  const directory = mkdtempSync(join(tmpdir(), "zero-trust-service-nilai-"));
  const database = openDatabase(join(directory, "nilai.sqlite"));
  migrate(database);
  const passwordHash = await hashPassword(PASSWORD, 4);
  for (const user of Object.values(USERS)) {
    database
      .prepare("INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)")
      .run(user.id, user.email, passwordHash, user.role);
    database.prepare("INSERT INTO devices (id, user_id) VALUES (?, ?)").run(user.device, user.id);
  }

  database.prepare("INSERT INTO classes (id, name, lecturer_id, term) VALUES (?, ?, ?, ?)")
    .run("nilai-class-101", "Matematika Diskrit", USERS.lecturer1.id, "2026-Ganjil");
  database.prepare("INSERT INTO classes (id, name, lecturer_id, term) VALUES (?, ?, ?, ?)")
    .run("nilai-class-202", "Keamanan Informasi", USERS.lecturer2.id, "2026-Ganjil");

  const enrollment = database.prepare("INSERT INTO enrollments (class_id, student_id) VALUES (?, ?)");
  enrollment.run("nilai-class-101", USERS.student1.id);
  enrollment.run("nilai-class-101", USERS.student2.id);
  enrollment.run("nilai-class-202", USERS.student1.id);
  const insertGrade = database.prepare("INSERT INTO grades (class_id, student_id, score) VALUES (?, ?, ?)");
  insertGrade.run("nilai-class-101", USERS.student1.id, 80);
  insertGrade.run("nilai-class-101", USERS.student2.id, 75);
  insertGrade.run("nilai-class-202", USERS.student1.id, 90);

  let now = START;
  const auth = new AuthService(database, ACCESS_SECRET, { clock: () => now, bcryptRounds: 4 });
  const sessions = {} as Record<Actor, AuthSession>;
  for (const actor of Object.keys(USERS) as Actor[]) {
    const user = USERS[actor];
    sessions[actor] = await auth.login(user.email, PASSWORD, user.device);
  }
  const service = await listen(createNilaiApp(
    database,
    new AuthService(database, ACCESS_SECRET, { clock: () => now, bcryptRounds: 4 }),
    GATEWAY_SECRET,
    { clock: () => new Date(now) }
  ));

  return {
    database,
    auth,
    sessions,
    getNow: () => new Date(now),
    setNow: (value) => { now = value; },
    service,
    close: async () => {
      await service.close();
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
    await fixture.close();
  }
}

function serviceRequest(
  fixture: Fixture,
  actor: Actor,
  path: string,
  options: {
    method?: string;
    body?: unknown;
    gatewaySecret?: string | null;
    token?: string | null;
    deviceId?: string | null;
    headers?: Record<string, string>;
  } = {}
): Promise<Response> {
  const user = USERS[actor];
  const headers: Record<string, string> = {
    "x-correlation-id": "00000000-0000-4000-8000-000000000001",
    ...(options.gatewaySecret === null ? {} : {
      "x-gateway-secret": options.gatewaySecret ?? GATEWAY_SECRET
    }),
    ...(options.token === null ? {} : {
      authorization: `Bearer ${options.token ?? fixture.sessions[actor].accessToken}`
    }),
    ...(options.deviceId === null ? {} : {
      "x-device-id": options.deviceId ?? user.device
    }),
    ...(options.body === undefined ? {} : { "content-type": "application/json" }),
    ...options.headers
  };
  return fetch(`${fixture.service.url}${path}`, {
    method: options.method ?? "GET",
    headers,
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) })
  });
}

test("Service Nilai returns only the student's grades and filters class reads by role", async () => {
  await withFixture(async (fixture) => {
    const own = await serviceRequest(fixture, "student1", "/nilai/saya");
    assert.equal(own.status, 200);
    const ownBody = await own.json() as { grades: Array<{ classId: string; score: number; studentId?: string }> };
    assert.equal(ownBody.grades.length, 2);
    assert.ok(ownBody.grades.every((grade) => !grade.studentId || grade.studentId === USERS.student1.id));

    const lecturerRead = await serviceRequest(fixture, "lecturer1", "/nilai/kelas/nilai-class-101");
    assert.equal(lecturerRead.status, 200);
    const lecturerBody = await lecturerRead.json() as { grades: Array<{ studentId: string }> };
    assert.deepEqual(lecturerBody.grades.map((grade) => grade.studentId).sort(), [
      USERS.student1.id,
      USERS.student2.id
    ]);

    const studentRead = await serviceRequest(fixture, "student1", "/nilai/kelas/nilai-class-101");
    assert.equal(studentRead.status, 200);
    const studentBody = await studentRead.json() as { grades: Array<{ studentId: string }> };
    assert.deepEqual(studentBody.grades.map((grade) => grade.studentId), [USERS.student1.id]);
  });
});

test("students and admins cannot update or finalize grades", async () => {
  await withFixture(async (fixture) => {
    const patch = await serviceRequest(
      fixture,
      "student1",
      `/nilai/kelas/nilai-class-101/mahasiswa/${USERS.student1.id}`,
      { method: "PATCH", body: { score: 99 } }
    );
    assert.equal(patch.status, 403);

    const finalize = await serviceRequest(fixture, "student1", "/nilai/kelas/nilai-class-101/finalisasi", {
      method: "POST"
    });
    assert.equal(finalize.status, 403);

    const adminPatch = await serviceRequest(
      fixture,
      "admin",
      `/nilai/kelas/nilai-class-101/mahasiswa/${USERS.student1.id}`,
      { method: "PATCH", body: { score: 99 } }
    );
    assert.equal(adminPatch.status, 403);
    const score = fixture.database
      .prepare("SELECT score FROM grades WHERE class_id = ? AND student_id = ?")
      .get("nilai-class-101", USERS.student1.id) as { score: number };
    assert.equal(score.score, 80);
  });
});

test("assigned lecturer can update an enrolled student's grade and audit the successful write", async () => {
  await withFixture(async (fixture) => {
    const response = await serviceRequest(
      fixture,
      "lecturer1",
      `/nilai/kelas/nilai-class-101/mahasiswa/${USERS.student1.id}`,
      { method: "PATCH", body: { score: 96.5 } }
    );
    assert.equal(response.status, 200);
    const body = await response.json() as { grade: { score: number; studentId: string } };
    assert.equal(body.grade.score, 96.5);
    assert.equal(body.grade.studentId, USERS.student1.id);

    const audit = fixture.database
      .prepare("SELECT correlation_id, actor_id, action, decision, reason_code FROM audit_logs WHERE action = 'grade:update' AND decision = 'ALLOW' ORDER BY rowid DESC LIMIT 1")
      .get() as { correlation_id: string; actor_id: string; action: string; decision: string; reason_code: string };
    assert.equal(audit.correlation_id, "00000000-0000-4000-8000-000000000001");
    assert.equal(audit.actor_id, USERS.lecturer1.id);
    assert.equal(audit.decision, "ALLOW");
    assert.equal(audit.reason_code, "POLICY_ALLOW");
  });
});

test("non-assigned lecturer, invalid enrollment, and finalized grades are denied without a write", async () => {
  await withFixture(async (fixture) => {
    const wrongLecturer = await serviceRequest(
      fixture,
      "lecturer2",
      `/nilai/kelas/nilai-class-101/mahasiswa/${USERS.student1.id}`,
      { method: "PATCH", body: { score: 99 } }
    );
    assert.equal(wrongLecturer.status, 403);

    const noEnrollment = await serviceRequest(
      fixture,
      "lecturer1",
      `/nilai/kelas/nilai-class-101/mahasiswa/${USERS.student3.id}`,
      { method: "PATCH", body: { score: 99 } }
    );
    assert.equal(noEnrollment.status, 403);

    fixture.database
      .prepare("UPDATE classes SET finalization_status = 'FINALIZED', finalized_at = CURRENT_TIMESTAMP WHERE id = ?")
      .run("nilai-class-101");
    const finalGrade = await serviceRequest(
      fixture,
      "lecturer1",
      `/nilai/kelas/nilai-class-101/mahasiswa/${USERS.student1.id}`,
      { method: "PATCH", body: { score: 99 } }
    );
    assert.equal(finalGrade.status, 403);

    const score = fixture.database
      .prepare("SELECT score FROM grades WHERE class_id = ? AND student_id = ?")
      .get("nilai-class-101", USERS.student1.id) as { score: number };
    assert.equal(score.score, 80);
    const denials = fixture.database
      .prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE action = 'grade:update' AND decision = 'DENY'")
      .get() as { count: number };
    assert.equal(denials.count, 3);
  });
});

test("Service Nilai denies a request at 21:00 Asia/Jakarta", async () => {
  await withFixture(async (fixture) => {
    fixture.setNow(Date.UTC(2026, 0, 1, 14, 0, 0));
    const response = await serviceRequest(
      fixture,
      "lecturer1",
      `/nilai/kelas/nilai-class-101/mahasiswa/${USERS.student1.id}`,
      { method: "PATCH", body: { score: 96 } }
    );
    assert.equal(response.status, 403);
    const audit = fixture.database
      .prepare("SELECT decision, reason_code FROM audit_logs WHERE action = 'grade:update' ORDER BY rowid DESC LIMIT 1")
      .get() as { decision: string; reason_code: string };
    assert.deepEqual(audit, { decision: "DENY", reason_code: "OUTSIDE_ACCESS_HOURS" });
  });
});

test("Service Nilai independently rejects a missing/wrong gateway secret, invalid/expired JWT, and invalid device", async () => {
  await withFixture(async (fixture) => {
    const noSecret = await serviceRequest(fixture, "student1", "/nilai/saya", { gatewaySecret: null });
    assert.equal(noSecret.status, 401);
    const wrongSecret = await serviceRequest(fixture, "student1", "/nilai/saya", {
      gatewaySecret: "wrong-gateway-secret-value-that-is-long-enough"
    });
    assert.equal(wrongSecret.status, 401);
    const noToken = await serviceRequest(fixture, "student1", "/nilai/saya", { token: null });
    assert.equal(noToken.status, 401);
    const tampered = fixture.sessions.student1.accessToken.slice(0, -1) + "A";
    const invalidJwt = await serviceRequest(fixture, "student1", "/nilai/saya", { token: tampered });
    assert.equal(invalidJwt.status, 401);
    const noDevice = await serviceRequest(fixture, "student1", "/nilai/saya", { deviceId: null });
    assert.equal(noDevice.status, 401);
    const otherDevice = await serviceRequest(fixture, "student1", "/nilai/saya", {
      deviceId: USERS.student2.device
    });
    assert.equal(otherDevice.status, 401);

    fixture.setNow(START + 600_001);
    const expiredJwt = await serviceRequest(fixture, "student1", "/nilai/saya");
    assert.equal(expiredJwt.status, 401);

    const gatewayDenials = fixture.database
      .prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE action = 'GATEWAY_SECRET_VALIDATE' AND decision = 'DENY'")
      .get() as { count: number };
    assert.equal(gatewayDenials.count, 2);
  });
});

test("finalization does not claim success or change class state while transcript sync is unavailable", async () => {
  await withFixture(async (fixture) => {
    const response = await serviceRequest(fixture, "lecturer1", "/nilai/kelas/nilai-class-101/finalisasi", {
      method: "POST"
    });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "TRANSCRIPT_SYNC_UNAVAILABLE" });
    const row = fixture.database
      .prepare("SELECT finalization_status FROM classes WHERE id = ?")
      .get("nilai-class-101") as { finalization_status: string };
    assert.equal(row.finalization_status, "OPEN");
    const audit = fixture.database
      .prepare("SELECT decision, reason_code FROM audit_logs WHERE action = 'class:finalize' ORDER BY rowid DESC LIMIT 1")
      .get() as { decision: string; reason_code: string };
    assert.deepEqual(audit, { decision: "DENY", reason_code: "TRANSCRIPT_SYNC_UNAVAILABLE" });
  });
});

test("Gateway and Service Nilai integrate over HTTP while service rejects direct callers without gateway secret", async () => {
  await withFixture(async (fixture) => {
    fixture.database.prepare("UPDATE access_policies SET start_time = '00:00', end_time = '23:59' WHERE id = 1").run();
    const gateway = await listen(createAuthApp(fixture.auth, {
      database: fixture.database,
      gatewaySecret: GATEWAY_SECRET,
      nilaiBaseUrl: fixture.service.url
    }));
    try {
      const login = await fetch(`${gateway.url}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-device-id": USERS.student1.device },
        body: JSON.stringify({ email: USERS.student1.email, password: PASSWORD })
      });
      assert.equal(login.status, 200);
      const studentSession = await login.json() as { accessToken: string };
      const studentHeaders = {
        authorization: `Bearer ${studentSession.accessToken}`,
        "x-device-id": USERS.student1.device,
        "x-user-id": USERS.student2.id
      };

      const throughGateway = await fetch(`${gateway.url}/nilai/saya`, { headers: studentHeaders });
      assert.equal(throughGateway.status, 200);
      const own = await throughGateway.json() as { grades: Array<{ score: number }> };
      assert.equal(own.grades.length, 2);
      const pdfEndpoint = await fetch(`${gateway.url}/nilai`, { headers: studentHeaders });
      assert.equal(pdfEndpoint.status, 200);
      const listed = await pdfEndpoint.json() as { grades: Array<{ id: string }> };
      assert.equal(listed.grades.length, 2);
      assert.ok(listed.grades.every((grade) => typeof grade.id === "string"));

      const directWithoutSecret = await fetch(`${fixture.service.url}/nilai/saya`, {
        headers: {
          authorization: `Bearer ${studentSession.accessToken}`,
          "x-device-id": USERS.student1.device
        }
      });
      assert.equal(directWithoutSecret.status, 401);

      const lecturerLogin = await fetch(`${gateway.url}/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-device-id": USERS.lecturer1.device },
        body: JSON.stringify({ email: USERS.lecturer1.email, password: PASSWORD })
      });
      assert.equal(lecturerLogin.status, 200);
      const lecturerSession = await lecturerLogin.json() as { accessToken: string };
      const lecturerHeaders = {
        authorization: `Bearer ${lecturerSession.accessToken}`,
        "x-device-id": USERS.lecturer1.device
      };
      const lecturerList = await fetch(`${gateway.url}/nilai`, { headers: lecturerHeaders });
      assert.equal(lecturerList.status, 200);
      const lecturerGrades = await lecturerList.json() as { grades: Array<{ classId: string }> };
      assert.ok(lecturerGrades.grades.length > 0);
      assert.ok(lecturerGrades.grades.every((grade) => grade.classId === "nilai-class-101"));
      const gradeId = Buffer.from(JSON.stringify(["nilai-class-101", USERS.student1.id]), "utf8").toString("base64url");
      const legacyPut = await fetch(`${gateway.url}/nilai/${gradeId}`, {
        method: "PUT",
        headers: { ...lecturerHeaders, "content-type": "application/json" },
        body: JSON.stringify({ score: 89 })
      });
      const legacyPutBody = await legacyPut.text();
      assert.equal(legacyPut.status, 200, legacyPutBody);
      const update = await fetch(
        `${gateway.url}/nilai/kelas/nilai-class-101/mahasiswa/${USERS.student1.id}`,
        {
          method: "PATCH",
          headers: {
            authorization: `Bearer ${lecturerSession.accessToken}`,
            "x-device-id": USERS.lecturer1.device,
            "content-type": "application/json",
            "x-user-id": USERS.student1.id
          },
          body: JSON.stringify({ score: 93 })
        }
      );
      assert.equal(update.status, 200);
      const result = await update.json() as { grade: { score: number } };
      assert.equal(result.grade.score, 93);

      const directAudits = fixture.database
        .prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE action = 'GATEWAY_SECRET_VALIDATE' AND decision = 'DENY'")
        .get() as { count: number };
      assert.equal(directAudits.count, 1);
    } finally {
      await gateway.close();
    }
  });
});

test("Nilai demo seed is idempotent and does not overwrite existing grade data", () => {
  const directory = mkdtempSync(join(tmpdir(), "zero-trust-nilai-seed-"));
  const database = openDatabase(join(directory, "seed.sqlite"));
  try {
    migrate(database);
    for (const user of Object.values(USERS)) {
      database
        .prepare("INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)")
        .run(user.id, user.email, "test-hash", user.role);
    }
    const insertDemoUser = database.prepare("INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)");
    insertDemoUser.run("demo-lecturer-001", "demo-lecturer-001@seed.test", "test-hash", "DOSEN");
    insertDemoUser.run("demo-lecturer-002", "demo-lecturer-002@seed.test", "test-hash", "DOSEN");
    for (const [index, id] of ["demo-student-001", "demo-student-002", "demo-student-003"].entries()) {
      insertDemoUser.run(id, `demo-student-${index + 1}@seed.test`, "test-hash", "MAHASISWA");
    }    seedNilaiDemoData(database);
    database
      .prepare("UPDATE grades SET score = 62 WHERE class_id = ? AND student_id = ?")
      .run("demo-class-algoritma-2026", "demo-student-001");
    seedNilaiDemoData(database);

    const counts = database.prepare(`
      SELECT (SELECT COUNT(*) FROM classes) AS classes,
             (SELECT COUNT(*) FROM enrollments) AS enrollments,
             (SELECT COUNT(*) FROM grades) AS grades
    `).get() as { classes: number; enrollments: number; grades: number };
    const preserved = database
      .prepare("SELECT score FROM grades WHERE class_id = ? AND student_id = ?")
      .get("demo-class-algoritma-2026", "demo-student-001") as { score: number };
    assert.deepEqual(counts, { classes: 2, enrollments: 6, grades: 6 });
    assert.equal(preserved.score, 62);
  } finally {
    database.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

