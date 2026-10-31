import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export type SqliteDatabase = Database.Database;

const projectRoot = resolve(fileURLToPath(new URL("../../../", import.meta.url)));

export function getDatabasePath(configuredPath = process.env.DATABASE_PATH): string {
  const path = configuredPath ?? "./data/zero-trust.sqlite";
  return isAbsolute(path) ? path : resolve(projectRoot, path);
}

export function openDatabase(path = getDatabasePath()): Database.Database {
  mkdirSync(dirname(path), { recursive: true });
  const database = new Database(path);
  database.pragma("foreign_keys = ON");
  database.pragma("journal_mode = WAL");
  database.pragma("busy_timeout = 5000");
  return database;
}
