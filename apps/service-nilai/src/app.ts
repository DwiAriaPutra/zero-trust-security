import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import express, { type NextFunction, type Request, type RequestHandler, type Response } from "express";
import { writeAuditLog } from "@zero-trust/audit";
import { AuthError, AuthService, type AccessClaims } from "@zero-trust/auth";
import type { SqliteDatabase } from "@zero-trust/database";
import {
  DEFAULT_ACCESS_WINDOW,
  evaluatePolicy,
  type PolicyResource
} from "@zero-trust/policy-engine";

const CORRELATION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const RESOURCE_ID_PATTERN = /^[A-Za-z0-9._:-]{1,64}$/u;

interface NilaiLocals {
  claims?: AccessClaims;
  deviceId?: string;
  correlationId?: string;
}

interface ClassRow {
  id: string;
  name: string;
  lecturer_id: string;
  term: string;
  finalization_status: "OPEN" | "FINALIZING" | "FINALIZED";
  grade_version: number;
}

interface NilaiAppOptions {
  clock?: () => Date;
  transcriptSync?: (payload: {
    classId: string;
    sourceVersion: number;
    grades: Array<{ studentId: string; score: number }>;
  }) => Promise<void>;
}

function correlationId(request: Request, response: Response): string {
  const current = (response.locals as NilaiLocals).correlationId;
  if (current) return current;
  const provided = request.header("x-correlation-id");
  const value = provided && CORRELATION_ID_PATTERN.test(provided) ? provided : randomUUID();
  (response.locals as NilaiLocals).correlationId = value;
  response.setHeader("X-Correlation-ID", value);
  return value;
}

function safeSecretMatch(provided: string | undefined, expected: string): boolean {
  if (!provided) return false;
  const providedDigest = createHash("sha256").update(provided, "utf8").digest();
  const expectedDigest = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(providedDigest, expectedDigest);
}

function resourceReference(type: string, id: string): string {
  const digest = createHash("sha256").update(`${type}:${id}`, "utf8").digest("hex").slice(0, 24);
  return `${type}:${digest}`;
}

function audit(
  database: SqliteDatabase,
  request: Request,
  response: Response,
  event: {
    actorId: string | null;
    action: string;
    resource: string;
    decision: "ALLOW" | "DENY";
    reasonCode: string;
    occurredAt?: Date;
  }
): void {
  writeAuditLog(database, {
    correlationId: correlationId(request, response),
    endpoint: typeof request.route?.path === "string" ? request.route.path : "/nilai",
    ...(request.header("x-device-id") ? { deviceId: request.header("x-device-id")! } : {}),
    actorId: event.actorId,
    actorType: event.actorId ? "USER" : "ANONYMOUS",
    action: event.action,
    resource: event.resource,
    decision: event.decision,
    reasonCode: event.reasonCode,
    ...(event.occurredAt ? { occurredAt: event.occurredAt } : {})
  });
}

function safeErrorHandler(
  error: unknown,
  _request: Request,
  response: Response,
  _next: NextFunction
): void {
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

function classFor(database: SqliteDatabase, classId: string): ClassRow | undefined {
  return database
    .prepare(`
      SELECT id, name, lecturer_id, term, finalization_status, grade_version
      FROM classes WHERE id = ?
    `)
    .get(classId) as ClassRow | undefined;
}

function isEnrolled(database: SqliteDatabase, classId: string, studentId: string): boolean {
  return Boolean(
    database
      .prepare("SELECT 1 FROM enrollments WHERE class_id = ? AND student_id = ?")
      .get(classId, studentId)
  );
}

function accessWindow(database: SqliteDatabase): {
  startTime: string;
  endTime: string;
  timezone: string;
} {
  const row = database
    .prepare("SELECT start_time, end_time, timezone FROM access_policies WHERE id = 1")
    .get() as { start_time: string; end_time: string; timezone: string } | undefined;
  return row
    ? { startTime: row.start_time, endTime: row.end_time, timezone: row.timezone }
    : DEFAULT_ACCESS_WINDOW;
}

function makePolicyMiddleware(
  database: SqliteDatabase,
  action: string,
  resourceType: string,
  resolve: (request: Request, claims: AccessClaims) => PolicyResource,
  clock: () => Date
): RequestHandler {
  return (request, response, next) => {
    const locals = response.locals as NilaiLocals;
    const claims = locals.claims;
    const deviceId = locals.deviceId;
    if (!claims || !deviceId) {
      audit(database, request, response, {
        actorId: null,
        action,
        resource: resourceType,
        decision: "DENY",
        reasonCode: "AUTHENTICATION_REQUIRED"
      });
      next(new AuthError(401, "AUTHENTICATION_REQUIRED"));
      return;
    }

    try {
      const now = clock();
      const resolved = resolve(request, claims);
      const resource = { ...resolved, type: resourceType };
      const decision = evaluatePolicy({
        subject: { id: claims.sub, role: claims.role, accountActive: true },
        device: { id: deviceId, userId: claims.sub, active: true },
        action,
        resource,
        context: { currentTime: now, accessWindow: accessWindow(database) }
      });
      if (decision.decision === "DENY") {
        audit(database, request, response, {
          actorId: claims.sub,
          action,
          resource: resourceReference(resourceType, resource.id),
          decision: "DENY",
          reasonCode: decision.reasonCode,
          occurredAt: now
        });
        next(new AuthError(403, decision.reasonCode));
        return;
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}

function internalAuthentication(
  database: SqliteDatabase,
  auth: AuthService,
  gatewaySecret: string
): RequestHandler {
  return (request, response, next) => {
    const requestId = correlationId(request, response);
    const providedGatewaySecret = request.header("x-gateway-secret");
    if (!safeSecretMatch(providedGatewaySecret, gatewaySecret)) {
      audit(database, request, response, {
        actorId: null,
        action: "GATEWAY_SECRET_VALIDATE",
        resource: "service-nilai",
        decision: "DENY",
        reasonCode: "GATEWAY_SECRET_INVALID"
      });
      next(new AuthError(401, "GATEWAY_AUTHENTICATION_REQUIRED"));
      return;
    }

    const authorization = request.header("authorization");
    const match = authorization?.match(/^Bearer ([^\s]+)$/u);
    if (!match?.[1]) {
      audit(database, request, response, {
        actorId: null,
        action: "ACCESS_TOKEN_VALIDATE",
        resource: "service-nilai",
        decision: "DENY",
        reasonCode: "INVALID_ACCESS_TOKEN"
      });
      next(new AuthError(401, "INVALID_ACCESS_TOKEN"));
      return;
    }

    let claims: AccessClaims;
    try {
      claims = auth.verifyAccessToken(match[1]);
    } catch {
      audit(database, request, response, {
        actorId: null,
        action: "ACCESS_TOKEN_VALIDATE",
        resource: "service-nilai",
        decision: "DENY",
        reasonCode: "INVALID_ACCESS_TOKEN"
      });
      next(new AuthError(401, "INVALID_ACCESS_TOKEN"));
      return;
    }

    try {
      const deviceId = request.header("x-device-id");
      auth.assertActiveUser(claims.sub, requestId, deviceId, "/nilai");
      if (!deviceId) {
        auth.auditAuthenticationFailure("DEVICE_VERIFY", "DEVICE_ID_REQUIRED", requestId, undefined, "/nilai");
        next(new AuthError(401, "DEVICE_ID_REQUIRED"));
        return;
      }
      auth.assertTrustedDevice(claims.sub, deviceId, requestId, "/nilai");
      const locals = response.locals as NilaiLocals;
      locals.claims = claims;
      locals.deviceId = deviceId;
      next();
    } catch (error) {
      next(error);
    }
  };
}

function validateResourceId(
  database: SqliteDatabase,
  action: string,
  parameter: "kelasId" | "mahasiswaId"
): RequestHandler {
  return (request, response, next) => {
    const value = request.params[parameter];
    if (typeof value === "string" && RESOURCE_ID_PATTERN.test(value)) {
      next();
      return;
    }
    const claims = (response.locals as NilaiLocals).claims;
    audit(database, request, response, {
      actorId: claims?.sub ?? null,
      action,
      resource: "nilai",
      decision: "DENY",
      reasonCode: parameter === "kelasId" ? "INVALID_CLASS_ID" : "INVALID_STUDENT_ID"
    });
    next(new AuthError(400, parameter === "kelasId" ? "INVALID_CLASS_ID" : "INVALID_STUDENT_ID"));
  };
}

function validateScore(database: SqliteDatabase): RequestHandler {
  return (request, response, next) => {
    const body = request.body as Record<string, unknown> | undefined;
    const validKeys = body && Object.keys(body).length === 1 && Object.hasOwn(body, "score");
    const validScore = typeof body?.score === "number" &&
      Number.isFinite(body.score) && body.score >= 0 && body.score <= 100;
    if (validKeys && validScore) {
      next();
      return;
    }
    const locals = response.locals as NilaiLocals;
    const classId = typeof request.params.kelasId === "string" ? request.params.kelasId : "unknown";
    audit(database, request, response, {
      actorId: locals.claims?.sub ?? null,
      action: "grade:update",
      resource: resourceReference("class", classId),
      decision: "DENY",
      reasonCode: "INVALID_SCORE_PAYLOAD"
    });
    next(new AuthError(400, "INVALID_SCORE_PAYLOAD"));
  };
}

export function createNilaiApp(
  database: SqliteDatabase,
  auth: AuthService,
  gatewaySecret: string,
  options: NilaiAppOptions = {}
): express.Express {
  if (Buffer.byteLength(gatewaySecret, "utf8") < 32) {
    throw new Error("GATEWAY_SECRET must contain at least 32 UTF-8 bytes.");
  }
  const app = express();
  app.set("json spaces", 2);
  const clock = options.clock ?? (() => new Date());
  app.disable("x-powered-by");
  app.get("/health", (_request, response) => {
    database.prepare("SELECT 1").get();
    response.status(200).json({ status: "ok", database: "ok", service: "nilai" });
  });
  app.use("/nilai", internalAuthentication(database, auth, gatewaySecret));
  app.use(express.json({ limit: "32kb", strict: true }));

  app.get(
    "/nilai",
    makePolicyMiddleware(database, "grade:list", "grade-list", (_request, claims) => {
      if (claims.role === "MAHASISWA") {
        return { type: "grade-list", id: claims.sub, ownerId: claims.sub };
      }
      const assignment = database.prepare("SELECT 1 FROM classes WHERE lecturer_id = ? LIMIT 1")
        .get(claims.sub);
      return {
        type: "grade-list",
        id: `lecturer:${claims.sub}`,
        classId: assignment ? "assigned-classes" : "",
        ...(assignment ? { teacherId: claims.sub } : {})
      };
    }, clock),
    (request, response, next) => {
      const claims = (response.locals as NilaiLocals).claims;
      if (!claims) {
        next(new AuthError(401, "AUTHENTICATION_REQUIRED"));
        return;
      }
      try {
        const rows = claims.role === "MAHASISWA"
          ? database.prepare(`
              SELECT c.id AS classId, c.name AS className, c.term,
                     g.score, g.updated_at AS updatedAt
              FROM grades AS g JOIN classes AS c ON c.id = g.class_id
              JOIN enrollments AS e ON e.class_id = g.class_id AND e.student_id = g.student_id
              WHERE g.student_id = ? ORDER BY c.term, c.name
            `).all(claims.sub)
          : database.prepare(`
              SELECT c.id AS classId, c.name AS className, c.term,
                     g.student_id AS studentId, g.score, g.updated_at AS updatedAt
              FROM grades AS g JOIN classes AS c ON c.id = g.class_id
              JOIN enrollments AS e ON e.class_id = g.class_id AND e.student_id = g.student_id
              WHERE c.lecturer_id = ? ORDER BY c.term, c.name, g.student_id
            `).all(claims.sub);
        const grades = (rows as Array<{ classId: string; studentId?: string }>).map((row) => ({
          ...row,
          id: Buffer.from(JSON.stringify([row.classId, row.studentId ?? claims.sub]), "utf8").toString("base64url")
        }));
        audit(database, request, response, {
          actorId: claims.sub,
          action: "grade:list",
          resource: resourceReference("grade-list", claims.sub),
          decision: "ALLOW",
          reasonCode: "POLICY_ALLOW",
          occurredAt: clock()
        });
        response.status(200).json({ grades });
      } catch (error) {
        next(error);
      }
    }
  );

  app.get(
    "/nilai/saya",
    makePolicyMiddleware(database, "grade:read", "grade", (_request, claims) => ({
      type: "grade",
      id: `student:${claims.sub}`,
      ownerId: claims.sub
    }), clock),
    (request, response, next) => {
      const locals = response.locals as NilaiLocals;
      const claims = locals.claims;
      if (!claims) {
        next(new AuthError(401, "AUTHENTICATION_REQUIRED"));
        return;
      }
      try {
        const rows = database
          .prepare(`
            SELECT c.id AS classId, c.name AS className, c.term, g.score, g.updated_at AS updatedAt
            FROM grades AS g
            JOIN classes AS c ON c.id = g.class_id
            JOIN enrollments AS e ON e.class_id = g.class_id AND e.student_id = g.student_id
            WHERE g.student_id = ?
            ORDER BY c.term, c.name
          `)
          .all(claims.sub);
        audit(database, request, response, {
          actorId: claims.sub,
          action: "grade:read",
          resource: resourceReference("student", claims.sub),
          decision: "ALLOW",
          reasonCode: "POLICY_ALLOW",
          occurredAt: clock()
        });
        response.status(200).json({ grades: rows });
      } catch (error) {
        next(error);
      }
    }
  );

  app.get(
    "/nilai/kelas/:kelasId",
    validateResourceId(database, "grade:read", "kelasId"),
    makePolicyMiddleware(database, "grade:read", "grade", (request, claims) => {
      const classId = typeof request.params.kelasId === "string" ? request.params.kelasId : "";
      const row = typeof classId === "string" ? classFor(database, classId) : undefined;
      const enrolled = claims.role === "MAHASISWA" && typeof classId === "string"
        ? isEnrolled(database, classId, claims.sub)
        : true;
      return {
        type: "grade",
        id: classId || "unknown",
        classId,
        ownerId: claims.sub,
        ...(row ? { teacherId: row.lecturer_id } : {}),
        enrolled,
        classFinalized: row ? row.finalization_status !== "OPEN" : true
      };
    }, clock),
    (request, response, next) => {
      const locals = response.locals as NilaiLocals;
      const claims = locals.claims;
      const classId = typeof request.params.kelasId === "string" ? request.params.kelasId : "";
      if (!claims || typeof classId !== "string") {
        next(new AuthError(400, "INVALID_CLASS_ID"));
        return;
      }
      try {
        const gradeQuery = claims.role === "MAHASISWA"
          ? database.prepare(`
              SELECT c.id AS classId, c.name AS className, c.term,
                     g.student_id AS studentId, g.score, g.updated_at AS updatedAt
              FROM grades AS g JOIN classes AS c ON c.id = g.class_id
              JOIN enrollments AS e ON e.class_id = g.class_id AND e.student_id = g.student_id
              WHERE g.class_id = ? AND g.student_id = ?
            `).all(classId, claims.sub)
          : database.prepare(`
              SELECT c.id AS classId, c.name AS className, c.term,
                     g.student_id AS studentId, g.score, g.updated_at AS updatedAt
              FROM grades AS g JOIN classes AS c ON c.id = g.class_id
              JOIN enrollments AS e ON e.class_id = g.class_id AND e.student_id = g.student_id
              WHERE g.class_id = ? ORDER BY g.student_id
            `).all(classId);
        audit(database, request, response, {
          actorId: claims.sub,
          action: "grade:read",
          resource: resourceReference("class", classId),
          decision: "ALLOW",
          reasonCode: "POLICY_ALLOW",
          occurredAt: clock()
        });
        response.status(200).json({ grades: gradeQuery });
      } catch (error) {
        next(error);
      }
    }
  );

  app.patch(
    "/nilai/kelas/:kelasId/mahasiswa/:mahasiswaId",
    validateResourceId(database, "grade:update", "kelasId"),
    validateResourceId(database, "grade:update", "mahasiswaId"),
    validateScore(database),
    makePolicyMiddleware(database, "grade:update", "grade", (request, _claims) => {
      const classId = typeof request.params.kelasId === "string" ? request.params.kelasId : "";
      const studentId = typeof request.params.mahasiswaId === "string" ? request.params.mahasiswaId : "";
      const row = typeof classId === "string" ? classFor(database, classId) : undefined;
      return {
        type: "grade",
        id: `${classId || "unknown"}:${studentId || "unknown"}`,
        classId,
        ...(row ? { teacherId: row.lecturer_id } : {}),
        enrolled: typeof classId === "string" && typeof studentId === "string"
          ? isEnrolled(database, classId, studentId)
          : false,
        classFinalized: row ? row.finalization_status !== "OPEN" : true
      };
    }, clock),
    (request, response, next) => {
      const locals = response.locals as NilaiLocals;
      const claims = locals.claims;
      const classId = typeof request.params.kelasId === "string" ? request.params.kelasId : "";
      const studentId = typeof request.params.mahasiswaId === "string" ? request.params.mahasiswaId : "";
      const score = (request.body as { score: number }).score;
      if (!claims || typeof classId !== "string" || typeof studentId !== "string") {
        next(new AuthError(400, "INVALID_RESOURCE_ID"));
        return;
      }
      try {
        const update = database.transaction(() => {
          const currentClass = classFor(database, classId);
          const currentDeviceId = locals.deviceId;
          const currentTime = clock();
          if (!currentDeviceId) throw new AuthError(401, "DEVICE_ID_REQUIRED");
          const decision = evaluatePolicy({
            subject: { id: claims.sub, role: claims.role, accountActive: true },
            device: { id: currentDeviceId, userId: claims.sub, active: true },
            action: "grade:update",
            resource: {
              type: "grade",
              id: `${classId}:${studentId}`,
              classId,
              ...(currentClass ? { teacherId: currentClass.lecturer_id } : {}),
              enrolled: isEnrolled(database, classId, studentId),
              classFinalized: currentClass ? currentClass.finalization_status !== "OPEN" : true
            },
            context: { currentTime, accessWindow: accessWindow(database) }
          });
          if (decision.decision === "DENY") throw new AuthError(403, decision.reasonCode);
          database.prepare(`
            INSERT INTO grades (class_id, student_id, score)
            VALUES (?, ?, ?)
            ON CONFLICT (class_id, student_id)
            DO UPDATE SET score = excluded.score, updated_at = CURRENT_TIMESTAMP
          `).run(classId, studentId, score);
          database.prepare("UPDATE classes SET grade_version = grade_version + 1 WHERE id = ?")
            .run(classId);
          audit(database, request, response, {
            actorId: claims.sub,
            action: "grade:update",
            resource: resourceReference("grade", `${classId}:${studentId}`),
            decision: "ALLOW",
            reasonCode: "POLICY_ALLOW",
            occurredAt: clock()
          });
        });
        update.immediate();
        const result = database
          .prepare("SELECT class_id AS classId, student_id AS studentId, score, updated_at AS updatedAt FROM grades WHERE class_id = ? AND student_id = ?")
          .get(classId, studentId);
        response.status(200).json({ grade: result });
      } catch (error) {
        audit(database, request, response, {
          actorId: claims.sub,
          action: "grade:update",
          resource: resourceReference("grade", `${classId}:${studentId}`),
          decision: "DENY",
          reasonCode: error instanceof AuthError ? error.code : "GRADE_WRITE_FAILED",
          occurredAt: clock()
        });
        next(error);
      }
    }
  );

  app.post(
    "/nilai/kelas/:kelasId/finalisasi",
    validateResourceId(database, "class:finalize", "kelasId"),
    makePolicyMiddleware(database, "class:finalize", "class", (request) => {
      const classId = typeof request.params.kelasId === "string" ? request.params.kelasId : "";
      const row = typeof classId === "string" ? classFor(database, classId) : undefined;
      return {
        type: "class",
        id: classId || "unknown",
        classId,
        ...(row ? { teacherId: row.lecturer_id } : {}),
        classFinalized: row ? row.finalization_status === "FINALIZED" : true,
        finalizationPending: row?.finalization_status === "FINALIZING",
        finalizationComplete: row?.finalization_status === "FINALIZED"
      };
    }, clock),
    async (request, response) => {
      const locals = response.locals as NilaiLocals;
      const claims = locals.claims;
      const classId = typeof request.params.kelasId === "string" ? request.params.kelasId : "";
      if (!claims || typeof classId !== "string") throw new AuthError(400, "INVALID_CLASS_ID");
      const course = classFor(database, classId);
      if (!course) throw new AuthError(404, "CLASS_NOT_FOUND");
      if (course.finalization_status === "FINALIZED") {
        audit(database, request, response, {
          actorId: claims.sub,
          action: "class:finalize",
          resource: resourceReference("class", classId),
          decision: "ALLOW",
          reasonCode: "ALREADY_FINALIZED",
          occurredAt: clock()
        });
        response.status(200).json({ classId, status: "FINALIZED", sourceVersion: course.grade_version });
        return;
      }
      if (!options.transcriptSync) {
        audit(database, request, response, {
          actorId: claims.sub,
          action: "class:finalize",
          resource: resourceReference("class", classId),
          decision: "DENY",
          reasonCode: "TRANSCRIPT_SYNC_UNAVAILABLE",
          occurredAt: clock()
        });
        response.status(503).json({ error: "TRANSCRIPT_SYNC_UNAVAILABLE" });
        return;
      }

      try {
        const startFinalization = database.transaction(() => {
          const current = classFor(database, classId);
          if (!current) throw new AuthError(404, "CLASS_NOT_FOUND");
          const grades = database.prepare(`
            SELECT student_id AS studentId, score
            FROM grades WHERE class_id = ? ORDER BY student_id
          `).all(classId) as Array<{ studentId: string; score: number }>;
          if (current.finalization_status === "FINALIZED") {
            return { sourceVersion: current.grade_version, alreadyFinalized: true, noGrades: false, grades };
          }
          if (grades.length === 0) {
            return { sourceVersion: current.grade_version, alreadyFinalized: false, noGrades: true, grades };
          }
          if (current.finalization_status === "OPEN") {
            const changed = database.prepare(`
              UPDATE classes SET finalization_status = 'FINALIZING'
              WHERE id = ? AND finalization_status = 'OPEN' AND grade_version = ?
            `).run(classId, current.grade_version);
            if (changed.changes !== 1) throw new AuthError(409, "CLASS_STATE_CHANGED");
          }
          return { sourceVersion: current.grade_version, alreadyFinalized: false, noGrades: false, grades };
        });
        const { sourceVersion, alreadyFinalized, noGrades, grades } = startFinalization.immediate();
        if (noGrades) {
          audit(database, request, response, {
            actorId: claims.sub,
            action: "class:finalize",
            resource: resourceReference("class", classId),
            decision: "DENY",
            reasonCode: "CLASS_HAS_NO_GRADES",
            occurredAt: clock()
          });
          response.status(409).json({ error: "CLASS_HAS_NO_GRADES" });
          return;
        }
        if (alreadyFinalized) {
          audit(database, request, response, {
            actorId: claims.sub,
            action: "class:finalize",
            resource: resourceReference("class", classId),
            decision: "ALLOW",
            reasonCode: "ALREADY_FINALIZED",
            occurredAt: clock()
          });
          response.status(200).json({ classId, status: "FINALIZED", sourceVersion });
          return;
        }
        await options.transcriptSync({ classId, sourceVersion, grades });

        const finalize = database.transaction(() => {
          const current = classFor(database, classId);
          if (current?.finalization_status === "FINALIZED" && current.grade_version === sourceVersion) {
            return false;
          }
          const changed = database.prepare(`
            UPDATE classes
            SET finalization_status = 'FINALIZED', finalized_at = CURRENT_TIMESTAMP
            WHERE id = ? AND finalization_status = 'FINALIZING' AND grade_version = ?
          `).run(classId, sourceVersion);
          if (changed.changes !== 1) throw new AuthError(409, "FINALIZATION_STATE_CHANGED");
          audit(database, request, response, {
            actorId: claims.sub,
            action: "class:finalize",
            resource: resourceReference("class", classId),
            decision: "ALLOW",
            reasonCode: changed.changes === 1 ? "TRANSCRIPT_SYNCED_AND_FINALIZED" : "ALREADY_FINALIZED",
            occurredAt: clock()
          });
          return changed.changes === 1;
        });
        const didFinalize = finalize.immediate();
        if (!didFinalize) {
          audit(database, request, response, {
            actorId: claims.sub,
            action: "class:finalize",
            resource: resourceReference("class", classId),
            decision: "ALLOW",
            reasonCode: "ALREADY_FINALIZED",
            occurredAt: clock()
          });
        }
        response.status(200).json({ classId, status: "FINALIZED", sourceVersion });
      } catch {
        // Leave FINALIZING in place after an ambiguous inter-service failure. It locks grade changes
        // and a later retry is safe because transcript synchronization is idempotent.
        audit(database, request, response, {
          actorId: claims.sub,
          action: "class:finalize",
          resource: resourceReference("class", classId),
          decision: "DENY",
          reasonCode: "TRANSCRIPT_SYNC_PENDING",
          occurredAt: clock()
        });
        response.status(503).json({ error: "TRANSCRIPT_SYNC_PENDING", classId });
      }
    }
  );

  app.use(safeErrorHandler);
  return app;
}

export function getNilaiPort(): number {
  const port = Number(process.env.NILAI_PORT ?? 3001);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("NILAI_PORT must be a valid TCP port.");
  }
  return port;
}

