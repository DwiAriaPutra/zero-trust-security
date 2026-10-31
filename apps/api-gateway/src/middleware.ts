import { createHash, randomUUID } from "node:crypto";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import { writeAuditLog } from "@zero-trust/audit";
import { AuthError, AuthService, type AccessClaims } from "@zero-trust/auth";
import type { SqliteDatabase } from "@zero-trust/database";
import {
  DEFAULT_ACCESS_WINDOW,
  evaluatePolicy,
  type PolicyResource
} from "@zero-trust/policy-engine";

export interface GatewayLocals {
  claims?: AccessClaims;
  deviceId?: string;
  correlationId?: string;
}

export interface PolicyMiddlewareOptions {
  clock?: () => Date;
}

export const correlationIdMiddleware: RequestHandler = (_request, response, next) => {
  const correlationId = randomUUID();
  (response.locals as GatewayLocals).correlationId = correlationId;
  response.setHeader("X-Correlation-ID", correlationId);
  next();
};

export function createAccessAuthenticationMiddleware(auth: AuthService): RequestHandler {
  return (request: Request, response: Response, next: NextFunction): void => {
    const deviceId = request.header("x-device-id");
    try {
      const correlationId = (response.locals as GatewayLocals).correlationId;
      const endpoint = typeof request.route?.path === "string" ? request.route.path : request.path;
      const authorization = request.header("authorization");
      const match = authorization?.match(/^Bearer ([^\s]+)$/u);
      if (!match?.[1]) {
        auth.auditAuthenticationFailure("ACCESS_TOKEN_VALIDATE", "INVALID_ACCESS_TOKEN", correlationId, deviceId, endpoint);
        throw new AuthError(401, "INVALID_ACCESS_TOKEN");
      }

      let claims: AccessClaims;
      try {
        claims = auth.verifyAccessToken(match[1]);
      } catch (error) {
        auth.auditAuthenticationFailure("ACCESS_TOKEN_VALIDATE", "INVALID_ACCESS_TOKEN", correlationId, deviceId, endpoint);
        throw error;
      }

      auth.assertActiveUser(claims.sub, correlationId, deviceId, endpoint);
      if (!deviceId) {
        auth.auditAuthenticationFailure("DEVICE_VERIFY", "DEVICE_ID_REQUIRED", correlationId, deviceId, endpoint);
        throw new AuthError(401, "DEVICE_ID_REQUIRED");
      }
      auth.assertTrustedDevice(claims.sub, deviceId, correlationId, endpoint);

      const locals = response.locals as GatewayLocals;
      locals.claims = claims;
      locals.deviceId = deviceId;
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function createPolicyAuthorizationMiddleware(
  database: SqliteDatabase,
  action: string,
  resourceType: string,
  resolveResource: (request: Request, claims: AccessClaims) => PolicyResource,
  options: PolicyMiddlewareOptions = {}
): RequestHandler {
  return (request, response, next) => {
    try {
      const locals = response.locals as GatewayLocals;
      const claims = locals.claims;
      const deviceId = locals.deviceId;
      if (!claims || !deviceId) {
        writeAuditLog(database, {
          correlationId: locals.correlationId ?? randomUUID(),
          endpoint: typeof request.route?.path === "string" ? request.route.path : "/unknown",
          ...(request.header("x-device-id") ? { deviceId: request.header("x-device-id")! } : {}),
          actorId: null,
          actorType: "ANONYMOUS",
          action,
          resource: resourceType,
          decision: "DENY",
          reasonCode: "AUTHENTICATION_REQUIRED"
        });
        next(new AuthError(401, "AUTHENTICATION_REQUIRED"));
        return;
      }

      const resolved = resolveResource(request, claims);
      const resource = { ...resolved, type: resourceType };
      const accessWindow = database
        .prepare("SELECT start_time, end_time, timezone FROM access_policies WHERE id = 1")
        .get() as { start_time: string; end_time: string; timezone: string } | undefined;
      const now = options.clock?.() ?? new Date();
      const decision = evaluatePolicy({
        subject: { id: claims.sub, role: claims.role, accountActive: true },
        device: { id: deviceId, userId: claims.sub, active: true },
        action,
        resource,
        context: {
          currentTime: now,
          accessWindow: accessWindow
            ? {
                startTime: accessWindow.start_time,
                endTime: accessWindow.end_time,
                timezone: accessWindow.timezone
              }
            : DEFAULT_ACCESS_WINDOW
        }
      });
      const resourceDigest = createHash("sha256")
        .update(`${resourceType}:${resource.id}`, "utf8")
        .digest("hex")
        .slice(0, 24);
      writeAuditLog(database, {
        correlationId: locals.correlationId ?? randomUUID(),
        endpoint: typeof request.route?.path === "string" ? request.route.path : "/unknown",
        deviceId,
        actorId: claims.sub,
        actorType: "USER",
        action,
        resource: `${resourceType}:${resourceDigest}`,
        decision: decision.decision,
        reasonCode: decision.reasonCode,
        occurredAt: now
      });

      if (decision.decision === "DENY") {
        next(new AuthError(403, decision.reasonCode));
        return;
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function createProtectedPolicyMiddleware(
  auth: AuthService,
  database: SqliteDatabase,
  action: string,
  resourceType: string,
  resolveResource: (request: Request, claims: AccessClaims) => PolicyResource,
  options: PolicyMiddlewareOptions = {}
): RequestHandler {
  const authenticate = createAccessAuthenticationMiddleware(auth);
  const authorize = createPolicyAuthorizationMiddleware(
    database,
    action,
    resourceType,
    resolveResource,
    options
  );

  return (request: Request, response: Response, next: NextFunction): void => {
    authenticate(request, response, (error?: unknown) => {
      if (error) {
        next(error);
        return;
      }
      authorize(request, response, next);
    });
  };
}

export function safeErrorHandler(
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
