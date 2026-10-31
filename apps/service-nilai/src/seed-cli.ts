import { openDatabase } from "@zero-trust/database";
import { migrate } from "../../../packages/database/src/migrate.js";
import { seedNilaiDemoData } from "./seed.js";

if (process.env.NODE_ENV === "production") {
  throw new Error("Nilai demo seeding is disabled when NODE_ENV=production.");
}
if (process.env.ALLOW_DEMO_SEED !== "true") {
  throw new Error("Set ALLOW_DEMO_SEED=true to explicitly seed local nilai demo data.");
}

const database = openDatabase();
try {
  migrate(database);
  seedNilaiDemoData(database);
  console.info("Nilai demo classes, enrollments, and grades are present.");
} finally {
  database.close();
}
