import { openDatabase } from "@zero-trust/database";
import { migrate } from "../../database/src/migrate.js";
import { seedDemoAccounts } from "./seed.js";

if (process.env.NODE_ENV === "production") {
  throw new Error("Demo seeding is disabled when NODE_ENV=production.");
}
if (process.env.ALLOW_DEMO_SEED !== "true") {
  throw new Error("Set ALLOW_DEMO_SEED=true to explicitly seed local demo accounts.");
}

const database = openDatabase();
try {
  migrate(database);
  await seedDemoAccounts(database);
  console.info("Local demo accounts and devices are present.");
} finally {
  database.close();
}
