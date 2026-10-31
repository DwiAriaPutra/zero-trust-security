import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type Database from "better-sqlite3";
import { openDatabase } from "./index.js";

const migrationsDirectory = fileURLToPath(new URL("./migrations/", import.meta.url));

interface Migration {
  version: number;
  filename: string;
}

function discoverMigrations(): Migration[] {
  const migrations = readdirSync(migrationsDirectory)
    .map((filename) => {
      const match = /^(\d+)_.*\.sql$/u.exec(filename);
      return match ? { filename, version: Number(match[1]) } : null;
    })
    .filter((migration): migration is Migration => migration !== null)
    .sort((left, right) => left.version - right.version);

  for (let index = 1; index < migrations.length; index += 1) {
    if (migrations[index]?.version === migrations[index - 1]?.version) {
      throw new Error("Duplicate migration version detected.");
    }
  }

  return migrations;
}

export function migrate(database: Database.Database): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const appliedRows = database
    .prepare("SELECT version FROM schema_migrations ORDER BY version")
    .all() as Array<{ version: number }>;
  const appliedVersions = new Set(appliedRows.map((row) => row.version));

  for (const migration of discoverMigrations()) {
    if (appliedVersions.has(migration.version)) continue;

    const sql = readFileSync(`${migrationsDirectory}${migration.filename}`, "utf8");
    const applyMigration = database.transaction(() => {
      database.exec(sql);
      database
        .prepare("INSERT INTO schema_migrations (version) VALUES (?)")
        .run(migration.version);
    });
    applyMigration();
  }
}

export function migrateDefaultDatabase(): void {
  const database = openDatabase();
  try {
    migrate(database);
  } finally {
    database.close();
  }
}
