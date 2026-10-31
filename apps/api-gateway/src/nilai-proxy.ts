import type { Express, Request, RequestHandler } from "express";
import { writeAuditLog } from "@zero-trust/audit";
import { AuthError, AuthService, type AccessClaims } from "@zero-trust/auth";
import type { SqliteDatabase } from "@zero-trust/database";
import { createProtectedPolicyMiddleware, type GatewayLocals } from "./middleware.js";

interface ClassRow {
  id: string;
  lecturer_id: string;
  finalization_status: "OPEN" | "FINALIZING" | "FINALIZED";
}

function findClass(database: SqliteDatabase, classId: string): ClassRow | undefined {
  return database
    .prepare("SELECT id, lecturer_id, finalization_status FROM classes WHERE id = ?")
    .get(classId) as ClassRow | undefined;
}

function enrolled(database: SqliteDatabase, classId: string, studentId: string): boolean {
  return Boolean(
    database
      .prepare("SELECT 1 FROM enrollments WHERE class_id = ? AND student_id = ?")
      .get(classId, studentId)
  );
}

function classGradeResource(
  database: SqliteDatabase,
  request: Request,
  claims: AccessClaims,
  mutationStudentId?: string
) {
  const classId = typeof request.params.kelasId === "string" ? request.params.kelasId : "";
  const row = classId ? findClass(database, classId) : undefined;
  const studentId = mutationStudentId ?? claims.sub;
  return {
    type: "grade",
    id: mutationStudentId ? `${classId}:${mutationStudentId}` : classId || "unknown",
    classId: classId || "",
    ownerId: claims.sub,
    ...(row ? { teacherId: row.lecturer_id } : {}),
    enrolled: claims.role === "MAHASISWA"
      ? Boolean(row && enrolled(database, classId, claims.sub))
      : mutationStudentId
        ? Boolean(row && enrolled(database, classId, studentId))
        : true,
    classFinalized: row ? row.finalization_status !== "OPEN" : true
  };
}

function classResource(database: SqliteDatabase, request: Request) {
  const classId = typeof request.params.kelasId === "string" ? request.params.kelasId : "";
  const row = classId ? findClass(database, classId) : undefined;
  return {
    type: "class",
    id: classId || "unknown",
    classId: classId || "",
    ...(row ? { teacherId: row.lecturer_id } : {}),
    classFinalized: row ? row.finalization_status === "FINALIZED" : true,
    finalizationPending: row?.finalization_status === "FINALIZING",
    finalizationComplete: row?.finalization_status === "FINALIZED"
  };
}

function gradeIdParts(value: string): { classId: string; studentId: string } | undefined {
  try {
    const decoded = Buffer.from(value, "base64url").toString("utf8");
    const parts = JSON.parse(decoded) as unknown;
    if (
      !Array.isArray(parts) || parts.length !== 2 ||
      typeof parts[0] !== "string" || typeof parts[1] !== "string" ||
      Buffer.from(JSON.stringify(parts), "utf8").toString("base64url") !== value
    ) return undefined;
    return { classId: parts[0], studentId: parts[1] };
  } catch {
    return undefined;
  }
}

function findGradeByPublicId(database: SqliteDatabase, value: string): {
  classId: string; lecturerId: string; finalizationStatus: "OPEN" | "FINALIZING" | "FINALIZED";
  studentId: string
} | undefined {
  const parts = gradeIdParts(value);
  if (!parts) return undefined;
  return database.prepare(`
    SELECT c.id AS classId, c.lecturer_id AS lecturerId,
           c.finalization_status AS finalizationStatus, e.student_id AS studentId
    FROM classes AS c
    JOIN enrollments AS e ON e.class_id = c.id
    WHERE c.id = ? AND e.student_id = ?
  `).get(parts.classId, parts.studentId) as {
    classId: string; lecturerId: string; finalizationStatus: "OPEN" | "FINALIZING" | "FINALIZED";
    studentId: string
  } | undefined;
}

function compositeGradeResource(database: SqliteDatabase, request: Request) {
  const gradeId = typeof request.params.id === "string" ? request.params.id : "";
  const row = findGradeByPublicId(database, gradeId);
  return {
    type: "grade",
    id: gradeId || "unknown",
    classId: row?.classId ?? "",
    ownerId: row?.studentId ?? "unknown",
    ...(row ? { teacherId: row.lecturerId } : {}),
    enrolled: Boolean(row),
    classFinalized: row ? row.finalizationStatus !== "OPEN" : true
  };
}

function proxyToNilai(
  database: SqliteDatabase,
  baseUrl: string,
  gatewaySecret: string,
  path: (request: Request) => string,
  upstreamMethod?: "GET" | "POST" | "PATCH"
): RequestHandler {
  return async (request, response, next) => {
    try {
      const target = new URL(path(request), baseUrl);
      const headers = new Headers();
      const authorization = request.header("authorization");
      const deviceId = request.header("x-device-id");
      const correlationId = response.getHeader("X-Correlation-ID");
      const contentType = request.header("content-type");
      const method = upstreamMethod ?? request.method as "GET" | "POST" | "PATCH";
      if (authorization) headers.set("authorization", authorization);
      if (deviceId) headers.set("x-device-id", deviceId);
      if (typeof correlationId === "string") headers.set("x-correlation-id", correlationId);
      if (contentType) headers.set("content-type", contentType);
      headers.set("x-gateway-secret", gatewaySecret);

      const upstream = await fetch(target, {
        method,
        headers,
        ...(method === "GET" ? {} : { body: JSON.stringify(request.body ?? {}) }),
        signal: AbortSignal.timeout(5000)
      });
      const upstreamBody = Buffer.from(await upstream.arrayBuffer());
      const upstreamContentType = upstream.headers.get("content-type");
      if (upstreamContentType) response.setHeader("content-type", upstreamContentType);
      response.status(upstream.status).send(upstreamBody);
    } catch {
      const locals = response.locals as GatewayLocals;
      writeAuditLog(database, {
        ...(locals.correlationId ? { correlationId: locals.correlationId } : {}),
        endpoint: typeof request.route?.path === "string" ? request.route.path : "/nilai",
        ...(locals.deviceId ? { deviceId: locals.deviceId } : {}),
        actorId: locals.claims?.sub ?? null,
        actorType: locals.claims ? "USER" : "ANONYMOUS",
        action: "SERVICE_NILAI_PROXY",
        resource: "service-nilai",
        decision: "DENY",
        reasonCode: "SERVICE_NILAI_UNAVAILABLE"
      });
      next(new AuthError(502, "SERVICE_NILAI_UNAVAILABLE"));
    }
  };
}

export interface NilaiProxyOptions {
  database: SqliteDatabase;
  auth: AuthService;
  gatewaySecret: string;
  serviceBaseUrl?: string;
}

export function mountNilaiProxyRoutes(app: Express, options: NilaiProxyOptions): void {
  const baseUrl = options.serviceBaseUrl ?? "http://127.0.0.1:3001";
  const parsedBaseUrl = new URL(baseUrl);
  if (
    parsedBaseUrl.protocol !== "http:" ||
    parsedBaseUrl.hostname !== "127.0.0.1" ||
    parsedBaseUrl.username ||
    parsedBaseUrl.password
  ) {
    throw new Error("Service Nilai proxy must target a local 127.0.0.1 HTTP address.");
  }
  if (Buffer.byteLength(options.gatewaySecret, "utf8") < 32) {
    throw new Error("GATEWAY_SECRET must contain at least 32 UTF-8 bytes.");
  }

  app.get(
    "/nilai",
    createProtectedPolicyMiddleware(
      options.auth,
      options.database,
      "grade:list",
      "grade-list",
      (_request, claims) => {
        if (claims.role === "MAHASISWA") {
          return { type: "grade-list", id: claims.sub, ownerId: claims.sub };
        }
        const assignment = options.database.prepare("SELECT 1 FROM classes WHERE lecturer_id = ? LIMIT 1")
          .get(claims.sub);
        return {
          type: "grade-list",
          id: `lecturer:${claims.sub}`,
          classId: assignment ? "assigned-classes" : "",
          ...(assignment ? { teacherId: claims.sub } : {})
        };
      }
    ),
    proxyToNilai(options.database, baseUrl, options.gatewaySecret, () => "/nilai")
  );

  app.get(
    "/nilai/saya",
    createProtectedPolicyMiddleware(
      options.auth,
      options.database,
      "grade:read",
      "grade",
      (_request, claims) => ({
        type: "grade",
        id: `student:${claims.sub}`,
        ownerId: claims.sub
      })
    ),
    proxyToNilai(options.database, baseUrl, options.gatewaySecret, () => "/nilai/saya")
  );

  app.get(
    "/nilai/kelas/:kelasId",
    createProtectedPolicyMiddleware(
      options.auth,
      options.database,
      "grade:read",
      "grade",
      (request, claims) => classGradeResource(options.database, request, claims)
    ),
    proxyToNilai(options.database, baseUrl, options.gatewaySecret, (request) =>
      `/nilai/kelas/${encodeURIComponent(String(request.params.kelasId ?? ""))}`
    )
  );

  app.patch(
    "/nilai/kelas/:kelasId/mahasiswa/:mahasiswaId",
    createProtectedPolicyMiddleware(
      options.auth,
      options.database,
      "grade:update",
      "grade",
      (request, claims) => classGradeResource(
        options.database,
        request,
        claims,
        typeof request.params.mahasiswaId === "string" ? request.params.mahasiswaId : ""
      )
    ),
    proxyToNilai(options.database, baseUrl, options.gatewaySecret, (request) =>
      `/nilai/kelas/${encodeURIComponent(String(request.params.kelasId ?? ""))}` +
      `/mahasiswa/${encodeURIComponent(String(request.params.mahasiswaId ?? ""))}`
    )
  );

  app.put(
    "/nilai/:id",
    createProtectedPolicyMiddleware(
      options.auth,
      options.database,
      "grade:update",
      "grade",
      (request) => compositeGradeResource(options.database, request)
    ),
    proxyToNilai(options.database, baseUrl, options.gatewaySecret, (request) => {
      const gradeId = typeof request.params.id === "string" ? request.params.id : "";
      const row = findGradeByPublicId(options.database, gradeId);
      if (!row) throw new AuthError(404, "GRADE_NOT_FOUND");
      return `/nilai/kelas/${encodeURIComponent(row.classId)}/mahasiswa/${encodeURIComponent(row.studentId)}`;
    }, "PATCH")
  );

  app.post(
    "/nilai/kelas/:kelasId/finalisasi",
    createProtectedPolicyMiddleware(
      options.auth,
      options.database,
      "class:finalize",
      "class",
      (request) => classResource(options.database, request)
    ),
    proxyToNilai(options.database, baseUrl, options.gatewaySecret, (request) =>
      `/nilai/kelas/${encodeURIComponent(String(request.params.kelasId ?? ""))}/finalisasi`
    )
  );

  app.post(
    "/kelas/:kelasId/finalisasi",
    createProtectedPolicyMiddleware(
      options.auth,
      options.database,
      "class:finalize",
      "class",
      (request) => classResource(options.database, request)
    ),
    proxyToNilai(options.database, baseUrl, options.gatewaySecret, (request) =>
      `/nilai/kelas/${encodeURIComponent(String(request.params.kelasId ?? ""))}/finalisasi`)
  );
}

