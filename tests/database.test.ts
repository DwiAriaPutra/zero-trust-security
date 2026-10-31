import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { migrate } from "../packages/database/src/migrate.js";
import { openDatabase } from "../packages/database/src/index.js";

test("migration upgrades v1 without removing data and is safe to rerun", () => {
  const directory = mkdtempSync(join(tmpdir(), "zero-trust-db-"));
  const path = join(directory, "test.sqlite");
  const database = openDatabase(path);

  try {
    database.exec(`
      CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);
    const initialMigration = readFileSync(
      fileURLToPath(new URL("../packages/database/src/migrations/001_initial.sql", import.meta.url)),
      "utf8"
    );
    database.exec(initialMigration);
    database.prepare("INSERT INTO schema_migrations (version) VALUES (1)").run();
    database
      .prepare("INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)")
      .run("existing-user", "existing@example.local", "existing-hash", "MAHASISWA");
    database
      .prepare(`
        INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
        VALUES (?, ?, ?, ?)
      `)
      .run("existing-refresh", "existing-user", "existing-token-hash", "2030-01-01T00:00:00.000Z");
    database.prepare(`
      INSERT INTO audit_logs
        (id, correlation_id, actor_id, actor_type, action, resource, decision, reason_code)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run("existing-audit", "existing-correlation", "existing-user", "USER", "LOGIN", "/auth/login", "ALLOW", "AUTHENTICATED");

    migrate(database);
    migrate(database);

    const versions = database
      .prepare("SELECT version FROM schema_migrations ORDER BY version")
      .all() as Array<{ version: number }>;
    const user = database
      .prepare("SELECT id, email FROM users WHERE id = ?")
      .get("existing-user") as { id: string; email: string };
    const refresh = database
      .prepare("SELECT id, token_hash, device_id FROM refresh_tokens WHERE id = ?")
      .get("existing-refresh") as { id: string; token_hash: string; device_id: string | null };
    const policy = database
      .prepare("SELECT start_time, end_time, timezone FROM access_policies WHERE id = 1")
      .get() as { start_time: string; end_time: string; timezone: string };
    const audit = database.prepare("SELECT endpoint, device_id FROM audit_logs WHERE id = ?")
      .get("existing-audit") as { endpoint: string; device_id: string | null };

    const migratedStudent = database
      .prepare("SELECT nim FROM users WHERE id = ?")
      .get("existing-user") as { nim: string };
    assert.deepEqual(versions, [{ version: 1 }, { version: 2 }, { version: 3 }, { version: 4 }]);
    assert.deepEqual(user, { id: "existing-user", email: "existing@example.local" });
    assert.equal(migratedStudent.nim, "existing-user");
    assert.deepEqual(refresh, {
      id: "existing-refresh",
      token_hash: "existing-token-hash",
      device_id: null
    });
    assert.deepEqual(policy, {
      start_time: "07:00",
      end_time: "21:00",
      timezone: "Asia/Jakarta"
    });
    assert.deepEqual(audit, { endpoint: "/auth/login", device_id: null });
  } finally {
    database.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
