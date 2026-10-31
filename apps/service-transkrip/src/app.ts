import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import express, { type NextFunction, type Request, type RequestHandler, type Response } from "express";
import { writeAuditLog } from "@zero-trust/audit";
import {
  AuthError,
  AuthService,
  verifyServiceToken,
  type AccessClaims
} from "@zero-trust/auth";
import type { SqliteDatabase } from "@zero-trust/database";

interface TranscriptAppOptions {
  clock?: () => Date;
}

interface TranscriptLocals {
  correlationId?: string;
  claims?: AccessClaims;
}

interface GradeInput {
  studentId: string;
  score: number;
}

interface SyncInput {
  classId: string;
  sourceVersion: number;
  grades: GradeInput[];
}

const ID_PATTERN = /^[A-Za-z0-9._:-]{1,64}$/u;
const CORRELATION_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function requestCorrelationId(request: Request, response: Response): string {
  const locals = response.locals as TranscriptLocals;
  if (locals.correlationId) return locals.correlationId;
  const incoming = request.header("x-correlation-id");
  const id = incoming && CORRELATION_PATTERN.test(incoming) ? incoming : randomUUID();
  locals.correlationId = id;
  response.setHeader("X-Correlation-ID", id);
  return id;
}

function resource(type: string, id: string): string {
  return `${type}:${createHash("sha256").update(id, "utf8").digest("hex").slice(0, 24)}`;
}

function audit(
  database: SqliteDatabase,
  request: Request,
  response: Response,
  actorId: string | null,
  actorType: "USER" | "SERVICE" | "ANONYMOUS",
  action: string,
  resourceId: string,
  decision: "ALLOW" | "DENY",
  reasonCode: string,
  now = new Date()
): void {
  writeAuditLog(database, {
    correlationId: requestCorrelationId(request, response),
    endpoint: typeof request.route?.path === "string" ? request.route.path : "/transkrip",
    ...(request.header("x-device-id") ? { deviceId: request.header("x-device-id")! } : {}),
    actorId,
    actorType,
    action,
    resource: resourceId,
    decision,
    reasonCode,
    occurredAt: now
  });
}

function secretMatches(provided: string | undefined, expected: string): boolean {
  if (provided === undefined) return false;
  const left = createHash("sha256").update(provided, "utf8").digest();
  const right = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(left, right);
}

function safeErrorHandler(error: unknown, _request: Request, response: Response, _next: NextFunction): void {
  if (error instanceof AuthError) {
    response.status(error.status).json({ error: error.code });
    return;
  }
  if (typeof error === "object" && error !== null && "type" in error) {
    const type = (error as { type?: unknown }).type;
    if (type === "entity.parse.failed") {
      response.status(400).json({ error: "INVALID_REQUEST_BODY" });
      return;
    }
    if (type === "entity.too.large") {
      response.status(413).json({ error: "REQUEST_BODY_TOO_LARGE" });
      return;
    }
  }
  response.status(500).json({ error: "INTERNAL_ERROR" });
}

function internalGuard(
  database: SqliteDatabase,
  gatewaySecret: string,
  clock: () => Date
): RequestHandler {
  return (request, response, next) => {
    requestCorrelationId(request, response);
    if (!secretMatches(request.header("x-gateway-secret"), gatewaySecret)) {
      audit(database, request, response, null, "ANONYMOUS", "GATEWAY_SECRET_VALIDATE", "service-transkrip", "DENY", "GATEWAY_SECRET_INVALID", clock());
      next(new AuthError(401, "GATEWAY_AUTHENTICATION_REQUIRED"));
      return;
    }
    next();
  };
}

function parseSyncInput(body: unknown): SyncInput | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const value = body as Record<string, unknown>;
  if (
    Object.keys(value).length !== 3 ||
    !Object.hasOwn(value, "classId") || !Object.hasOwn(value, "sourceVersion") || !Object.hasOwn(value, "grades") ||
    typeof value.classId !== "string" || !ID_PATTERN.test(value.classId) ||
    typeof value.sourceVersion !== "number" || !Number.isSafeInteger(value.sourceVersion) || value.sourceVersion < 0 ||
    !Array.isArray(value.grades) || value.grades.length < 1 || value.grades.length > 1000
  ) return null;

  const seen = new Set<string>();
  const grades: GradeInput[] = [];
  for (const entry of value.grades) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) return null;
    const grade = entry as Record<string, unknown>;
    if (
      Object.keys(grade).length !== 2 || !Object.hasOwn(grade, "studentId") || !Object.hasOwn(grade, "score") ||
      typeof grade.studentId !== "string" || !ID_PATTERN.test(grade.studentId) || seen.has(grade.studentId) ||
      typeof grade.score !== "number" || !Number.isFinite(grade.score) || grade.score < 0 || grade.score > 100
    ) return null;
    seen.add(grade.studentId);
    grades.push({ studentId: grade.studentId, score: grade.score });
  }
  grades.sort((left, right) => left.studentId.localeCompare(right.studentId));
  return { classId: value.classId, sourceVersion: value.sourceVersion, grades };
}

export function createTranscriptApp(
  database: SqliteDatabase,
  auth: AuthService,
  gatewaySecret: string,
  serviceTokenSecret: string,
  options: TranscriptAppOptions = {}
): express.Express {
  if (Buffer.byteLength(gatewaySecret, "utf8") < 32 || Buffer.byteLength(serviceTokenSecret, "utf8") < 32) {
    throw new Error("Gateway and service token secrets must each contain at least 32 UTF-8 bytes.");
  }
  const app = express();
  app.set("json spaces", 2);
  const clock = options.clock ?? (() => new Date());
  app.disable("x-powered-by");
  app.get("/health", (_request, response) => {
    database.prepare("SELECT 1").get();
    response.status(200).json({ status: "ok", database: "ok", service: "transkrip" });
  });
  app.use("/transkrip", internalGuard(database, gatewaySecret, clock));
  app.use(express.json({ limit: "128kb", strict: true }));

  app.get("/transkrip/:nim", (request, response, next) => {
    const requestedNim = request.params.nim;
    const correlation = requestCorrelationId(request, response);
    const bearer = request.header("authorization")?.match(/^Bearer ([^\s]+)$/u)?.[1];
    if (!bearer) {
      audit(database, request, response, null, "ANONYMOUS", "transcript:read", "transcript", "DENY", "INVALID_ACCESS_TOKEN", clock());
      next(new AuthError(401, "INVALID_ACCESS_TOKEN"));
      return;
    }
    let claims: AccessClaims;
    try {
      claims = auth.verifyAccessToken(bearer);
    } catch {
      audit(database, request, response, null, "ANONYMOUS", "transcript:read", "transcript", "DENY", "INVALID_ACCESS_TOKEN", clock());
      next(new AuthError(401, "INVALID_ACCESS_TOKEN"));
      return;
    }
    try {
      const deviceId = request.header("x-device-id");
      auth.assertActiveUser(claims.sub, correlation, deviceId, "/transkrip");
      if (!deviceId) {
        auth.auditAuthenticationFailure("DEVICE_VERIFY", "DEVICE_ID_REQUIRED", correlation, undefined, "/transkrip");
        throw new AuthError(401, "DEVICE_ID_REQUIRED");
      }
      auth.assertTrustedDevice(claims.sub, deviceId, correlation, "/transkrip");
      const target = database.prepare(
        "SELECT id FROM users WHERE nim = ? AND role = 'MAHASISWA'"
      ).get(typeof requestedNim === "string" ? requestedNim : "") as { id: string } | undefined;
      if (!target) {
        audit(database, request, response, claims.sub, "USER", "transcript:read", resource("nim", String(requestedNim)), "DENY", "TRANSCRIPT_NOT_FOUND", clock());
        next(new AuthError(404, "TRANSCRIPT_NOT_FOUND"));
        return;
      }
      if (claims.role === "MAHASISWA" && claims.sub !== target.id) {
        audit(database, request, response, claims.sub, "USER", "transcript:read", resource("nim", requestedNim as string), "DENY", "OWNERSHIP_MISMATCH", clock());
        next(new AuthError(403, "OWNERSHIP_MISMATCH"));
        return;
      }
      if (claims.role !== "MAHASISWA" && claims.role !== "ADMIN") {
        audit(database, request, response, claims.sub, "USER", "transcript:read", resource("nim", requestedNim as string), "DENY", "ROLE_NOT_ALLOWED", clock());
        next(new AuthError(403, "ROLE_NOT_ALLOWED"));
        return;
      }
      const entries = database.prepare(`
        SELECT class_id AS classId, snapshot_json AS snapshot, source_version AS sourceVersion,
               synced_at AS syncedAt
        FROM transcripts WHERE student_id = ? ORDER BY class_id
      `).all(target.id) as Array<{ classId: string; snapshot: string; sourceVersion: number; syncedAt: string }>;
      audit(database, request, response, claims.sub, "USER", "transcript:read", resource("nim", requestedNim as string), "ALLOW", "POLICY_ALLOW", clock());
      response.status(200).json({ nim: requestedNim, transcripts: entries.map((entry) => ({
        ...JSON.parse(entry.snapshot) as Record<string, unknown>,
        sourceVersion: entry.sourceVersion,
        syncedAt: entry.syncedAt
      })) });
    } catch (error) {
      next(error);
    }
  });

  app.post("/transkrip/sinkron", (request, response, next) => {
    const correlation = requestCorrelationId(request, response);
    const bearer = request.header("authorization")?.match(/^Bearer ([^\s]+)$/u)?.[1];
    if (!bearer) {
      audit(database, request, response, null, "ANONYMOUS", "transcript:sync", "service-transkrip", "DENY", "INVALID_SERVICE_TOKEN", clock());
      next(new AuthError(401, "INVALID_SERVICE_TOKEN"));
      return;
    }
    let verifiedServiceId: string | null = null;
    try {
      const claims = verifyServiceToken(bearer, serviceTokenSecret, "service-nilai", clock().getTime());
      verifiedServiceId = claims.sub;
      const input = parseSyncInput(request.body);
      if (!input) {
        audit(database, request, response, claims.sub, "SERVICE", "transcript:sync", "service-transkrip", "DENY", "INVALID_SYNC_PAYLOAD", clock());
        next(new AuthError(400, "INVALID_SYNC_PAYLOAD"));
        return;
      }
      const course = database.prepare(`
        SELECT id, name, term, finalization_status AS finalizationStatus,
               grade_version AS gradeVersion
        FROM classes WHERE id = ?
      `).get(input.classId) as {
        id: string; name: string; term: string; finalizationStatus: string; gradeVersion: number
      } | undefined;
      if (!course || course.finalizationStatus !== "FINALIZING" || course.gradeVersion !== input.sourceVersion) {
        audit(database, request, response, claims.sub, "SERVICE", "transcript:sync", resource("class", input.classId), "DENY", "CLASS_STATE_OR_VERSION_MISMATCH", clock());
        next(new AuthError(409, "CLASS_STATE_OR_VERSION_MISMATCH"));
        return;
      }
      const currentGrades = database.prepare(`
        SELECT student_id AS studentId, score FROM grades WHERE class_id = ? ORDER BY student_id
      `).all(input.classId) as GradeInput[];
      currentGrades.sort((left, right) => left.studentId.localeCompare(right.studentId));
      if (
        currentGrades.length === 0 || currentGrades.length !== input.grades.length ||
        currentGrades.some((grade, index) => grade.studentId !== input.grades[index]?.studentId || grade.score !== input.grades[index]?.score)
      ) {
        audit(database, request, response, claims.sub, "SERVICE", "transcript:sync", resource("class", input.classId), "DENY", "GRADE_SNAPSHOT_MISMATCH", clock());
        next(new AuthError(409, "GRADE_SNAPSHOT_MISMATCH"));
        return;
      }
      const newestTranscript = database.prepare(`
        SELECT MAX(source_version) AS sourceVersion FROM transcripts WHERE class_id = ?
      `).get(input.classId) as { sourceVersion: number | null };
      if (newestTranscript.sourceVersion !== null && newestTranscript.sourceVersion > input.sourceVersion) {
        audit(database, request, response, claims.sub, "SERVICE", "transcript:sync", resource("class", input.classId), "DENY", "STALE_SOURCE_VERSION", clock());
        next(new AuthError(409, "STALE_SOURCE_VERSION"));
        return;
      }

      const sync = database.transaction(() => {
        const insert = database.prepare(`
          INSERT INTO transcripts (id, class_id, student_id, snapshot_json, source_version)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(class_id, student_id) DO UPDATE SET
            snapshot_json = excluded.snapshot_json,
            source_version = excluded.source_version,
            synced_at = CURRENT_TIMESTAMP
          WHERE excluded.source_version >= transcripts.source_version
        `);
        for (const grade of currentGrades) {
          const snapshot = JSON.stringify({
            classId: course.id,
            className: course.name,
            term: course.term,
            studentId: grade.studentId,
            score: grade.score
          });
          insert.run(randomUUID(), course.id, grade.studentId, snapshot, input.sourceVersion);
        }
        audit(database, request, response, claims.sub, "SERVICE", "transcript:sync", resource("class", input.classId), "ALLOW", "TRANSCRIPT_SYNCED", clock());
      });
      sync.immediate();
      response.status(200).json({ synced: true, classId: input.classId, sourceVersion: input.sourceVersion, count: currentGrades.length });
    } catch (error) {
      audit(
        database, request, response,
        verifiedServiceId,
        verifiedServiceId ? "SERVICE" : "ANONYMOUS",
        "transcript:sync",
        "service-transkrip",
        "DENY",
        error instanceof AuthError ? error.code : "SYNC_WRITE_FAILED",
        clock()
      );
      next(error);
    }
  });

  app.use(safeErrorHandler);
  return app;
}

export function getTranscriptPort(): number {
  const port = Number(process.env.TRANSKRIP_PORT ?? 3002);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("TRANSKRIP_PORT must be a valid TCP port.");
  return port;
}
