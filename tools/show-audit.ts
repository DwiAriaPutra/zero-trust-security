import { openDatabase } from "@zero-trust/database";

const database = openDatabase();
try {
  const rows = database.prepare(`
    SELECT occurred_at AS occurredAt,
           correlation_id AS correlationId,
           actor_type AS actorType,
           actor_id AS actorId,
           action,
           endpoint,
           device_id AS deviceId,
           decision,
           reason_code AS reasonCode
    FROM audit_logs
    ORDER BY occurred_at DESC, rowid DESC
    LIMIT 30
  `).all();
  process.stdout.write(`${JSON.stringify(rows, null, 2)}\n`);
} finally {
  database.close();
}
