import { createHash, timingSafeEqual } from "node:crypto";
import express, { type Request, type Response } from "express";
import { AuthError, AuthService, signServiceToken, SERVICE_TOKEN_LIFETIME_SECONDS, type AccessClaims } from "@zero-trust/auth";
import { writeAuditLog } from "@zero-trust/audit";
import type { SqliteDatabase } from "@zero-trust/database";
import {
  createAccessAuthenticationMiddleware,
  correlationIdMiddleware,
  safeErrorHandler,
  type GatewayLocals
} from "./middleware.js";
import { mountNilaiProxyRoutes } from "./nilai-proxy.js";
import { mountTranscriptRoutes } from "./transcript-proxy.js";

export interface GatewayAppOptions {
  database: SqliteDatabase;
  gatewaySecret: string;
  nilaiBaseUrl?: string;
  transcriptBaseUrl?: string;
  serviceTokenSecret?: string;
  serviceNilaiClientId?: string;
  serviceNilaiClientSecret?: string;
}

interface AuthenticatedLocals {
  claims: AccessClaims;
  deviceId: string;
}

function requiredString(value: unknown, code: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new AuthError(400, code);
  }
  return value.trim();
}

function requestBody(request: Request): Record<string, unknown> {
  if (typeof request.body !== "object" || request.body === null || Array.isArray(request.body)) {
    throw new AuthError(400, "INVALID_REQUEST_BODY");
  }
  return request.body as Record<string, unknown>;
}

function requestCorrelationId(response: Response): string | undefined {
  return (response.locals as GatewayLocals).correlationId;
}

export function createAuthApp(auth: AuthService, options?: GatewayAppOptions): express.Express {
  if (options && Buffer.byteLength(options.gatewaySecret, "utf8") < 32) {
    throw new Error("GATEWAY_SECRET must contain at least 32 UTF-8 bytes.");
  }
  if (options?.serviceTokenSecret && Buffer.byteLength(options.serviceTokenSecret, "utf8") < 32) {
    throw new Error("SERVICE_TOKEN_SECRET must contain at least 32 UTF-8 bytes.");
  }
  if (options?.serviceNilaiClientSecret && Buffer.byteLength(options.serviceNilaiClientSecret, "utf8") < 32) {
    throw new Error("SERVICE_NILAI_CLIENT_SECRET must contain at least 32 UTF-8 bytes.");
  }
  const app = express();
  app.set("json spaces", 2);
  app.disable("x-powered-by");
  app.use(correlationIdMiddleware);
  app.use(express.json({ limit: "32kb", strict: true }));
  const authenticate = createAccessAuthenticationMiddleware(auth);

  app.get("/health", async (_request, response) => {
    options?.database.prepare("SELECT 1").get();
    if (!options) {
      response.status(200).json({ status: "ok", database: "ok" });
      return;
    }
    const services = await Promise.all([
      ["nilai", options.nilaiBaseUrl ?? "http://127.0.0.1:3001"],
      ["transkrip", options.transcriptBaseUrl ?? "http://127.0.0.1:3002"]
    ].map(async ([name, baseUrl]) => {
      try {
        const result = await fetch(new URL("/health", baseUrl), { signal: AbortSignal.timeout(1000) });
        return [name, result.ok ? "ok" : "unavailable"] as const;
      } catch {
        return [name, "unavailable"] as const;
      }
    }));
    const healthy = services.every(([, state]) => state === "ok");
    response.status(healthy ? 200 : 503).json({
      status: healthy ? "ok" : "degraded",
      database: "ok",
      services: Object.fromEntries(services)
    });
  });

  app.post("/auth/login", async (request, response) => {
    const body = requestBody(request);
    const email = requiredString(body.email, "EMAIL_REQUIRED");
    const password = requiredString(body.password, "PASSWORD_REQUIRED");
    const deviceId = request.header("x-device-id");
    if (!deviceId) {
      auth.auditAuthenticationFailure("LOGIN", "DEVICE_ID_REQUIRED", requestCorrelationId(response), undefined, "/auth/login");
      throw new AuthError(401, "DEVICE_ID_REQUIRED");
    }
    response.status(200).json(await auth.login(email, password, deviceId, requestCorrelationId(response)));
  });

  app.post("/auth/refresh", async (request, response) => {
    const body = requestBody(request);
    const refreshToken = requiredString(body.refreshToken, "REFRESH_TOKEN_REQUIRED");
    const deviceId = request.header("x-device-id");
    if (!deviceId) {
      auth.auditAuthenticationFailure("REFRESH", "DEVICE_ID_REQUIRED", requestCorrelationId(response), undefined, "/auth/refresh");
      throw new AuthError(401, "DEVICE_ID_REQUIRED");
    }
    response.status(200).json(await auth.refresh(refreshToken, deviceId, requestCorrelationId(response)));
  });

  app.post("/auth/logout", (request, response) => {
    const body = requestBody(request);
    const refreshToken = requiredString(body.refreshToken, "REFRESH_TOKEN_REQUIRED");
    const deviceId = request.header("x-device-id");
    if (!deviceId) {
      auth.auditAuthenticationFailure("LOGOUT", "DEVICE_ID_REQUIRED", requestCorrelationId(response), undefined, "/auth/logout");
      throw new AuthError(401, "DEVICE_ID_REQUIRED");
    }
    auth.logout(deviceId, refreshToken, requestCorrelationId(response));
    response.status(204).end();
  });

  app.post("/auth/service", (request, response) => {
    const correlationId = requestCorrelationId(response);
    const body = requestBody(request);
    const validShape = Object.keys(body).length === 2 &&
      Object.hasOwn(body, "client_id") && Object.hasOwn(body, "client_secret");
    const clientId = body.client_id;
    const clientSecret = body.client_secret;
    const configured = options?.serviceTokenSecret && options.serviceNilaiClientId && options.serviceNilaiClientSecret;
    const secretMatches = typeof clientSecret === "string" && Boolean(options?.serviceNilaiClientSecret) &&
      timingSafeEqual(
        createHash("sha256").update(clientSecret, "utf8").digest(),
        createHash("sha256").update(options!.serviceNilaiClientSecret!, "utf8").digest()
      );
    if (
      !configured || !validShape || typeof clientId !== "string" ||
      clientId !== options?.serviceNilaiClientId || !secretMatches
    ) {
      if (options) writeAuditLog(options.database, {
          ...(correlationId ? { correlationId } : {}),
          endpoint: typeof request.route?.path === "string" ? request.route.path : "/auth/service",
          actorId: null,
          actorType: "ANONYMOUS",
          action: "SERVICE_TOKEN_ISSUE",
          resource: "service-nilai",
          decision: "DENY",
          reasonCode: configured ? "INVALID_SERVICE_CREDENTIALS" : "SERVICE_AUTH_NOT_CONFIGURED"
        });
      throw new AuthError(configured ? 401 : 503, configured ? "INVALID_SERVICE_CREDENTIALS" : "SERVICE_AUTH_NOT_CONFIGURED");
    }
    const token = signServiceToken("service-nilai", options!.serviceTokenSecret!);
    writeAuditLog(options!.database, {
      ...(correlationId ? { correlationId } : {}),
      endpoint: typeof request.route?.path === "string" ? request.route.path : "/auth/service",
      actorId: "service-nilai",
      actorType: "SERVICE",
      action: "SERVICE_TOKEN_ISSUE",
      resource: "service-transkrip",
      decision: "ALLOW",
      reasonCode: "SERVICE_AUTHENTICATED"
    });
    response.status(200).json({ accessToken: token, tokenType: "Bearer", expiresIn: SERVICE_TOKEN_LIFETIME_SECONDS });
  });

  app.get("/auth/devices", authenticate, (_request, response) => {
    const locals = response.locals as AuthenticatedLocals;
    response.status(200).json({
      devices: auth.listDevices(locals.claims.sub, requestCorrelationId(response), locals.deviceId)
    });
  });

  app.post("/auth/devices", authenticate, (request, response) => {
    const body = requestBody(request);
    const deviceId = requiredString(body.deviceId, "DEVICE_ID_REQUIRED");
    const locals = response.locals as AuthenticatedLocals;
    auth.registerDevice(locals.claims.sub, deviceId, requestCorrelationId(response), locals.deviceId);
    response.status(201).json({ deviceId, registered: true });
  });

  app.delete("/auth/devices/:deviceId", authenticate, (request, response) => {
    const locals = response.locals as AuthenticatedLocals;
    const requestedDeviceId = request.params.deviceId;
    auth.revokeDevice(
      locals.claims.sub,
      typeof requestedDeviceId === "string" ? requestedDeviceId : "",
      requestCorrelationId(response),
      locals.deviceId
    );
    response.status(204).end();
  });

  if (options) {
    mountNilaiProxyRoutes(app, {
      database: options.database,
      auth,
      gatewaySecret: options.gatewaySecret,
      ...(options.nilaiBaseUrl ? { serviceBaseUrl: options.nilaiBaseUrl } : {})
    });
    mountTranscriptRoutes(app, {
      database: options.database,
      auth,
      gatewaySecret: options.gatewaySecret,
      ...(options.transcriptBaseUrl ? { serviceBaseUrl: options.transcriptBaseUrl } : {}),
      ...(options.serviceTokenSecret ? { serviceTokenSecret: options.serviceTokenSecret } : {})
    });
  }

  app.use(safeErrorHandler);

  return app;
}

