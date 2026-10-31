import type { Express, Request, RequestHandler } from "express";
import { randomUUID } from "node:crypto";
import { writeAuditLog } from "@zero-trust/audit";
import { AuthError, AuthService, verifyServiceToken } from "@zero-trust/auth";
import type { SqliteDatabase } from "@zero-trust/database";
import { createProtectedPolicyMiddleware, type GatewayLocals } from "./middleware.js";

interface TranscriptProxyOptions {
  database: SqliteDatabase;
  auth: AuthService;
  gatewaySecret: string;
  serviceTokenSecret?: string;
  serviceBaseUrl?: string;
}

function safeBaseUrl(value: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== "http:" || parsed.hostname !== "127.0.0.1" || parsed.username || parsed.password) {
    throw new Error("Service Transkrip proxy must target a local 127.0.0.1 HTTP address.");
  }
  return value;
}

function proxy(
  database: SqliteDatabase,
  baseUrl: string,
  gatewaySecret: string,
  makePath: (request: Request) => string,
  method: "GET" | "POST",
  serviceActor = false
): RequestHandler {
  return async (request, response, next) => {
    try {
      const target = new URL(makePath(request), baseUrl);
      const headers = new Headers({ "x-gateway-secret": gatewaySecret });
      const authorization = request.header("authorization");
      const deviceId = request.header("x-device-id");
      const correlationId = response.getHeader("X-Correlation-ID");
      if (authorization) headers.set("authorization", authorization);
      if (deviceId) headers.set("x-device-id", deviceId);
      if (typeof correlationId === "string") headers.set("x-correlation-id", correlationId);
      if (method === "POST") headers.set("content-type", "application/json");
      const upstream = await fetch(target, {
        method,
        headers,
        ...(method === "POST" ? { body: JSON.stringify(request.body ?? {}) } : {}),
        signal: AbortSignal.timeout(5000)
      });
      const payload = Buffer.from(await upstream.arrayBuffer());
      const contentType = upstream.headers.get("content-type");
      if (contentType) response.setHeader("content-type", contentType);
      response.status(upstream.status).send(payload);
    } catch {
      const locals = response.locals as GatewayLocals;
      writeAuditLog(database, {
        ...(locals.correlationId ? { correlationId: locals.correlationId } : {}),
        endpoint: typeof request.route?.path === "string" ? request.route.path : "/transkrip",
        ...(locals.deviceId ? { deviceId: locals.deviceId } : {}),
        actorId: serviceActor ? "service-nilai" : locals.claims?.sub ?? null,
        actorType: serviceActor ? "SERVICE" : locals.claims ? "USER" : "ANONYMOUS",
        action: "SERVICE_TRANSKRIP_PROXY",
        resource: "service-transkrip",
        decision: "DENY",
        reasonCode: "SERVICE_TRANSKRIP_UNAVAILABLE"
      });
      next(new AuthError(502, "SERVICE_TRANSKRIP_UNAVAILABLE"));
    }
  };
}

export function mountTranscriptRoutes(app: Express, options: TranscriptProxyOptions): void {
  const baseUrl = safeBaseUrl(options.serviceBaseUrl ?? "http://127.0.0.1:3002");
  app.get(
    "/transkrip/:nim",
    createProtectedPolicyMiddleware(
      options.auth,
      options.database,
      "transcript:read",
      "transcript",
      (request, claims) => {
        const nim = typeof request.params.nim === "string" ? request.params.nim : "";
        const row = options.database.prepare("SELECT id FROM users WHERE nim = ? AND role = 'MAHASISWA'").get(nim) as
          | { id: string }
          | undefined;
        return { type: "transcript", id: nim || "unknown", ownerId: row?.id ?? "unknown" };
      }
    ),
    proxy(options.database, baseUrl, options.gatewaySecret, (request) =>
      `/transkrip/${encodeURIComponent(String(request.params.nim ?? ""))}`, "GET")
  );

  app.post(["/internal/transkrip/sinkron", "/transkrip/sinkron"], async (request, response, next) => {
    const correlationId = typeof response.getHeader("X-Correlation-ID") === "string"
      ? String(response.getHeader("X-Correlation-ID"))
      : randomUUID();
    const match = request.header("authorization")?.match(/^Bearer ([^\s]+)$/u);
    let valid = false;
    if (match?.[1] && options.serviceTokenSecret) {
      try {
        verifyServiceToken(match[1], options.serviceTokenSecret, "service-nilai");
        valid = true;
      } catch {
        valid = false;
      }
    }
    writeAuditLog(options.database, {
      correlationId,
      endpoint: typeof request.route?.path === "string" ? request.route.path : "/internal/transkrip/sinkron",
      actorId: valid ? "service-nilai" : null,
      actorType: valid ? "SERVICE" : "ANONYMOUS",
      action: "TRANSCRIPT_SYNC_PROXY",
      resource: "service-transkrip",
      decision: valid ? "ALLOW" : "DENY",
      reasonCode: valid ? "SERVICE_TOKEN_VALID" : "INVALID_SERVICE_TOKEN"
    });
    if (!valid) {
      next(new AuthError(options.serviceTokenSecret ? 401 : 503,
        options.serviceTokenSecret ? "INVALID_SERVICE_TOKEN" : "SERVICE_TOKEN_NOT_CONFIGURED"));
      return;
    }
    const relay = proxy(options.database, baseUrl, options.gatewaySecret, () => "/transkrip/sinkron", "POST", true);
    relay(request, response, next);
  });
}
