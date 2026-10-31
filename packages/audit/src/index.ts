import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "@zero-trust/database";

export interface AuditEvent {
  correlationId?: string;
  actorId: string | null;
  actorType: "USER" | "SERVICE" | "ANONYMOUS";
  action: string;
  resource: string;
  endpoint?: string;
  deviceId?: string | null;
  decision: "ALLOW" | "DENY";
  reasonCode: string;
  occurredAt?: Date;
}

const SAFE_CODE = /^[A-Za-z][A-Za-z0-9:._/-]{0,127}$/u;
const SAFE_ID = /^[A-Za-z0-9/][A-Za-z0-9/._:-]{0,127}$/u;
const SAFE_ENDPOINT = /^\/[A-Za-z0-9/._:%-]{0,511}$/u;
const SAFE_DEVICE_ID = /^[A-Za-z0-9._:-]{8,128}$/u;

function safeField(value: string, pattern: RegExp, field: string): string {
  if (!pattern.test(value) || value.split(".").length === 3) {
    throw new Error(`Unsafe ${field} value for audit event.`);
  }
  return value;
}

export function writeAuditLog(database: SqliteDatabase, event: AuditEvent): string {
  const correlationId = event.correlationId ?? randomUUID();
  const action = safeField(event.action, SAFE_CODE, "action");
  const resource = safeField(event.resource, SAFE_ID, "resource");
  const endpointCandidate = event.endpoint ?? (event.resource.startsWith("/") ? event.resource : "/unknown");
  let endpoint = "/invalid";
  if (SAFE_ENDPOINT.test(endpointCandidate) && endpointCandidate.split(".").length !== 3) {
    endpoint = endpointCandidate;
  }
  const reasonCode = safeField(event.reasonCode, SAFE_CODE, "reason code");
  const deviceId = event.deviceId && SAFE_DEVICE_ID.test(event.deviceId) && event.deviceId.split(".").length !== 3
    ? event.deviceId
    : null;
  const occurredAt = (event.occurredAt ?? new Date()).toISOString();

  database
    .prepare(`
      INSERT INTO audit_logs
        (id, correlation_id, actor_id, actor_type, action, resource, endpoint, device_id,
         decision, reason_code, occurred_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      randomUUID(),
      correlationId,
      event.actorId,
      event.actorType,
      action,
      resource,
      endpoint,
      deviceId,
      event.decision,
      reasonCode,
      occurredAt
    );
  return correlationId;
}
