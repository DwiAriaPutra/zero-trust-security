import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { writeAuditLog } from "@zero-trust/audit";
import type Database from "better-sqlite3";
import bcrypt from "bcryptjs";

export const ACCESS_TOKEN_LIFETIME_SECONDS = 10 * 60;
export const REFRESH_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60;
export const SERVICE_TOKEN_LIFETIME_SECONDS = 5 * 60;
const DUMMY_PASSWORD_HASH = "$2b$12$EKIScVQJMTk5.qMTIjVDhesfg0hHkHu/ZT4Zro1dMWKOj6jqBsriq";
const VALID_ROLES = new Set(["ADMIN", "DOSEN", "MAHASISWA"]);

export type UserRole = "ADMIN" | "DOSEN" | "MAHASISWA";

export interface AccessClaims {
  sub: string;
  role: UserRole;
  iat: number;
  exp: number;
}

export interface ServiceClaims {
  sub: string;
  role: "service";
  token_use: "service";
  service: string;
  aud: "service-transkrip";
  iat: number;
  exp: number;
}

export interface AuthSession {
  accessToken: string;
  refreshToken: string;
  tokenType: "Bearer";
  expiresIn: number;
  refreshExpiresIn: number;
  user: { id: string; email: string; role: UserRole };
}

export interface AuthOptions {
  clock?: () => number;
  bcryptRounds?: number;
}

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  role: UserRole;
  is_active: number;
}

interface RefreshRow {
  id: string;
  user_id: string;
  device_id: string | null;
  expires_at: string;
  revoked_at: string | null;
  replaced_by_id: string | null;
  is_active: number;
  is_revoked: number;
}

export class AuthError extends Error {
  constructor(
    readonly status: number,
    readonly code: string
  ) {
    super(code);
    this.name = "AuthError";
  }
}

function requireSecret(secret: string): void {
  if (Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error("JWT access secret must contain at least 32 UTF-8 bytes.");
  }
}

function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

function signAccessToken(claims: AccessClaims, secret: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const unsignedToken = `${header}.${payload}`;
  const signature = createHmac("sha256", secret).update(unsignedToken).digest("base64url");
  return `${unsignedToken}.${signature}`;
}

export function signServiceToken(
  service: string,
  secret: string,
  nowMilliseconds = Date.now()
): string {
  requireSecret(secret);
  if (!/^[a-z][a-z0-9-]{2,63}$/u.test(service)) {
    throw new Error("Invalid service identity.");
  }
  const issuedAt = Math.floor(nowMilliseconds / 1000);
  const claims: ServiceClaims = {
    sub: service,
    role: "service",
    token_use: "service",
    service,
    aud: "service-transkrip",
    iat: issuedAt,
    exp: issuedAt + SERVICE_TOKEN_LIFETIME_SECONDS
  };
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const unsignedToken = `${header}.${payload}`;
  const signature = createHmac("sha256", secret).update(unsignedToken).digest("base64url");
  return `${unsignedToken}.${signature}`;
}

export function verifyServiceToken(
  token: string,
  secret: string,
  expectedService = "service-nilai",
  nowMilliseconds = Date.now()
): ServiceClaims {
  requireSecret(secret);
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) {
    throw new AuthError(401, "INVALID_SERVICE_TOKEN");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(Buffer.from(encodedHeader!, "base64url").toString("utf8")) as unknown;
    payload = JSON.parse(Buffer.from(encodedPayload!, "base64url").toString("utf8")) as unknown;
  } catch {
    throw new AuthError(401, "INVALID_SERVICE_TOKEN");
  }
  if (
    typeof header !== "object" || header === null ||
    (header as Record<string, unknown>).alg !== "HS256" ||
    (header as Record<string, unknown>).typ !== "JWT"
  ) throw new AuthError(401, "INVALID_SERVICE_TOKEN");

  const expectedSignature = createHmac("sha256", secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest();
  const suppliedSignature = Buffer.from(encodedSignature!, "base64url");
  if (
    suppliedSignature.length !== expectedSignature.length ||
    !timingSafeEqual(suppliedSignature, expectedSignature)
  ) throw new AuthError(401, "INVALID_SERVICE_TOKEN");

  if (typeof payload !== "object" || payload === null) {
    throw new AuthError(401, "INVALID_SERVICE_TOKEN");
  }
  const candidate = payload as Record<string, unknown>;
  const nowSeconds = Math.floor(nowMilliseconds / 1000);
  if (
    candidate.sub !== expectedService || candidate.service !== expectedService ||
    candidate.role !== "service" || candidate.token_use !== "service" ||
    candidate.aud !== "service-transkrip" ||
    typeof candidate.iat !== "number" || !Number.isInteger(candidate.iat) ||
    typeof candidate.exp !== "number" || !Number.isInteger(candidate.exp) ||
    candidate.iat > nowSeconds || candidate.exp <= nowSeconds ||
    candidate.exp <= candidate.iat ||
    candidate.exp - candidate.iat > SERVICE_TOKEN_LIFETIME_SECONDS
  ) throw new AuthError(401, "INVALID_SERVICE_TOKEN");

  return candidate as unknown as ServiceClaims;
}

export function verifyAccessToken(
  token: string,
  secret: string,
  nowMilliseconds = Date.now()
): AccessClaims {
  requireSecret(secret);
  const parts = token.split(".");
  if (parts.length !== 3) throw new AuthError(401, "INVALID_ACCESS_TOKEN");

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (!encodedHeader || !encodedPayload || !encodedSignature) {
    throw new AuthError(401, "INVALID_ACCESS_TOKEN");
  }

  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8")) as unknown;
    payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as unknown;
  } catch {
    throw new AuthError(401, "INVALID_ACCESS_TOKEN");
  }

  if (
    typeof header !== "object" ||
    header === null ||
    (header as Record<string, unknown>).alg !== "HS256" ||
    (header as Record<string, unknown>).typ !== "JWT"
  ) {
    throw new AuthError(401, "INVALID_ACCESS_TOKEN");
  }

  const expected = createHmac("sha256", secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest();
  const supplied = Buffer.from(encodedSignature, "base64url");
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new AuthError(401, "INVALID_ACCESS_TOKEN");
  }

  if (typeof payload !== "object" || payload === null) {
    throw new AuthError(401, "INVALID_ACCESS_TOKEN");
  }
  const candidate = payload as Record<string, unknown>;
  const nowSeconds = Math.floor(nowMilliseconds / 1000);
  if (
    typeof candidate.sub !== "string" ||
    candidate.sub.length === 0 ||
    typeof candidate.role !== "string" ||
    !VALID_ROLES.has(candidate.role) ||
    typeof candidate.iat !== "number" ||
    !Number.isInteger(candidate.iat) ||
    typeof candidate.exp !== "number" ||
    !Number.isInteger(candidate.exp) ||
    candidate.iat > nowSeconds ||
    candidate.exp <= nowSeconds ||
    candidate.exp <= candidate.iat ||
    candidate.exp - candidate.iat > ACCESS_TOKEN_LIFETIME_SECONDS
  ) {
    throw new AuthError(401, "INVALID_ACCESS_TOKEN");
  }

  return {
    sub: candidate.sub,
    role: candidate.role as UserRole,
    iat: candidate.iat,
    exp: candidate.exp
  };
}

function isValidDeviceId(deviceId: string): boolean {
  return /^[A-Za-z0-9._:-]{8,128}$/u.test(deviceId);
}

export class AuthService {
  private readonly clock: () => number;
  private readonly bcryptRounds: number;

  constructor(
    private readonly database: Database.Database,
    private readonly accessSecret: string,
    options: AuthOptions = {}
  ) {
    requireSecret(accessSecret);
    this.clock = options.clock ?? Date.now;
    this.bcryptRounds = options.bcryptRounds ?? 12;
  }

  private now(): Date {
    return new Date(this.clock());
  }

  private accessToken(user: Pick<UserRow, "id" | "role">): string {
    const issuedAt = Math.floor(this.clock() / 1000);
    return signAccessToken(
      {
        sub: user.id,
        role: user.role,
        iat: issuedAt,
        exp: issuedAt + ACCESS_TOKEN_LIFETIME_SECONDS
      },
      this.accessSecret
    );
  }

  private recordAudit(
    actorId: string | null,
    actorType: "USER" | "SERVICE" | "ANONYMOUS",
    action: string,
    resource: string,
    decision: "ALLOW" | "DENY",
    reasonCode: string,
    correlationId?: string,
    deviceId?: string | null,
    endpoint?: string
  ): void {
    writeAuditLog(this.database, {
      ...(correlationId ? { correlationId } : {}),
      actorId,
      actorType,
      action,
      resource,
      endpoint: endpoint ?? (resource.startsWith("/") ? resource : "/auth"),
      ...(deviceId ? { deviceId } : {}),
      decision,
      reasonCode,
      occurredAt: this.now()
    });
  }

  auditAuthenticationFailure(
    action: string,
    reasonCode = "INVALID_ACCESS_TOKEN",
    correlationId?: string,
    deviceId?: string,
    endpoint = "/auth"
  ): void {
    this.recordAudit(null, "ANONYMOUS", action, "/auth", "DENY", reasonCode, correlationId, deviceId, endpoint);
  }

  async login(
    email: string,
    password: string,
    deviceId: string,
    correlationId?: string
  ): Promise<AuthSession> {
    const normalizedEmail = email.trim().toLowerCase();
    const user = this.database
      .prepare("SELECT id, email, password_hash, role, is_active FROM users WHERE email = ?")
      .get(normalizedEmail) as UserRow | undefined;
    const device = this.database
      .prepare("SELECT user_id, is_revoked FROM devices WHERE id = ?")
      .get(deviceId) as { user_id: string; is_revoked: number } | undefined;

    let passwordMatches = false;
    try {
      passwordMatches = await bcrypt.compare(password, user?.password_hash ?? DUMMY_PASSWORD_HASH);
    } catch {
      passwordMatches = false;
    }

    const deviceMatches = Boolean(
      user && device && device.user_id === user.id && device.is_revoked === 0
    );
    if (!user || user.is_active !== 1 || !passwordMatches || !deviceMatches) {
      this.recordAudit(
        user?.id ?? null,
        user ? "USER" : "ANONYMOUS",
        "LOGIN",
        "/auth/login",
        "DENY",
        "INVALID_CREDENTIALS_OR_DEVICE",
        correlationId,
        deviceId
      );
      throw new AuthError(401, "INVALID_CREDENTIALS_OR_DEVICE");
    }

    const now = this.now();
    const refreshToken = randomBytes(32).toString("base64url");
    this.database
      .prepare(`
        INSERT INTO refresh_tokens (id, user_id, device_id, token_hash, expires_at)
        VALUES (?, ?, ?, ?, ?)
      `)
      .run(
        randomUUID(),
        user.id,
        deviceId,
        hashRefreshToken(refreshToken),
        new Date(now.getTime() + REFRESH_TOKEN_LIFETIME_SECONDS * 1000).toISOString()
      );

    this.recordAudit(user.id, "USER", "LOGIN", "/auth/login", "ALLOW", "AUTHENTICATED", correlationId, deviceId);
    return {
      accessToken: this.accessToken(user),
      refreshToken,
      tokenType: "Bearer",
      expiresIn: ACCESS_TOKEN_LIFETIME_SECONDS,
      refreshExpiresIn: REFRESH_TOKEN_LIFETIME_SECONDS,
      user: { id: user.id, email: user.email, role: user.role }
    };
  }

  verifyAccessToken(token: string): AccessClaims {
    return verifyAccessToken(token, this.accessSecret, this.clock());
  }

  assertTrustedDevice(userId: string, deviceId: string, correlationId?: string, endpoint = "/auth/device"): void {
    const device = this.database
      .prepare("SELECT user_id, is_revoked FROM devices WHERE id = ?")
      .get(deviceId) as { user_id: string; is_revoked: number } | undefined;
    const trusted = Boolean(
      device && device.user_id === userId && device.is_revoked === 0
    );
    this.recordAudit(
      userId,
      "USER",
      "DEVICE_VERIFICATION",
      "/auth/device",
      trusted ? "ALLOW" : "DENY",
      trusted ? "DEVICE_TRUSTED" : "DEVICE_UNTRUSTED",
      correlationId,
      deviceId,
      endpoint
    );
    if (!trusted) throw new AuthError(401, "UNTRUSTED_DEVICE");
  }

  assertActiveUser(userId: string, correlationId?: string, deviceId?: string, endpoint = "/auth"): void {
    const user = this.database
      .prepare("SELECT is_active FROM users WHERE id = ?")
      .get(userId) as { is_active: number } | undefined;
    const active = user?.is_active === 1;
    this.recordAudit(
      userId,
      "USER",
      "ACCOUNT_STATUS_CHECK",
      "/auth",
      active ? "ALLOW" : "DENY",
      active ? "ACCOUNT_ACTIVE" : "ACCOUNT_INACTIVE",
      correlationId,
      deviceId,
      endpoint
    );
    if (!active) throw new AuthError(401, "INACTIVE_ACCOUNT");
  }

  async refresh(
    refreshToken: string,
    deviceId: string,
    correlationId?: string
  ): Promise<AuthSession> {
    const newToken = randomBytes(32).toString("base64url");
    const newTokenId = randomUUID();
    const now = this.now();
    const newExpiresAt = new Date(
      now.getTime() + REFRESH_TOKEN_LIFETIME_SECONDS * 1000
    ).toISOString();

    const rotate = this.database.transaction(() => {
      const oldToken = this.database
        .prepare(`
          SELECT r.id, r.user_id, r.device_id, r.expires_at, r.revoked_at,
                 r.replaced_by_id, u.email, u.role, u.is_active,
                 d.is_revoked
          FROM refresh_tokens AS r
          JOIN users AS u ON u.id = r.user_id
          LEFT JOIN devices AS d ON d.id = r.device_id
          WHERE r.token_hash = ?
        `)
        .get(hashRefreshToken(refreshToken)) as
        | (RefreshRow & { email: string; role: UserRole })
        | undefined;

      const valid = Boolean(
        oldToken &&
          oldToken.revoked_at === null &&
          oldToken.expires_at > now.toISOString() &&
          oldToken.device_id === deviceId &&
          oldToken.is_active === 1 &&
          oldToken.is_revoked === 0
      );
      if (!oldToken || !valid) return null;

      this.database
        .prepare(`
          INSERT INTO refresh_tokens (id, user_id, device_id, token_hash, expires_at)
          VALUES (?, ?, ?, ?, ?)
        `)
        .run(newTokenId, oldToken.user_id, deviceId, hashRefreshToken(newToken), newExpiresAt);
      const updated = this.database
        .prepare(`
          UPDATE refresh_tokens
          SET revoked_at = ?, replaced_by_id = ?
          WHERE id = ? AND revoked_at IS NULL
        `)
        .run(now.toISOString(), newTokenId, oldToken.id);
      if (updated.changes !== 1) throw new Error("Refresh token rotation lost an update race.");

      return {
        user: { id: oldToken.user_id, email: oldToken.email, role: oldToken.role }
      };
    });

    const result = rotate.immediate();
    if (!result) {
      this.recordAudit(null, "ANONYMOUS", "REFRESH", "/auth/refresh", "DENY", "INVALID_REFRESH", correlationId, deviceId);
      throw new AuthError(401, "INVALID_REFRESH_TOKEN");
    }

    this.recordAudit(result.user.id, "USER", "REFRESH", "/auth/refresh", "ALLOW", "ROTATED", correlationId, deviceId);
    return {
      accessToken: this.accessToken(result.user),
      refreshToken: newToken,
      tokenType: "Bearer",
      expiresIn: ACCESS_TOKEN_LIFETIME_SECONDS,
      refreshExpiresIn: REFRESH_TOKEN_LIFETIME_SECONDS,
      user: result.user
    };
  }

  logout(deviceId: string, refreshToken: string, correlationId?: string): void {
    const now = this.now().toISOString();
    const revoke = this.database.transaction(() => {
      const stored = this.database
        .prepare(`
          SELECT r.id, r.user_id
          FROM refresh_tokens AS r
          JOIN devices AS d ON d.id = r.device_id
          JOIN users AS u ON u.id = r.user_id
          WHERE r.token_hash = ? AND r.device_id = ? AND r.revoked_at IS NULL
            AND d.is_revoked = 0 AND u.is_active = 1
        `)
        .get(hashRefreshToken(refreshToken), deviceId) as
        | { id: string; user_id: string }
        | undefined;
      if (!stored) return null;

      const result = this.database
        .prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
        .run(now, stored.id);
      return result.changes === 1 ? stored.user_id : null;
    });

    const userId = revoke();
    if (!userId) {
      this.recordAudit(null, "ANONYMOUS", "LOGOUT", "/auth/logout", "DENY", "REFRESH_NOT_FOUND", correlationId, deviceId);
      throw new AuthError(401, "INVALID_REFRESH_TOKEN");
    }
    this.recordAudit(userId, "USER", "LOGOUT", "/auth/logout", "ALLOW", "REVOKED", correlationId, deviceId);
  }

  registerDevice(userId: string, deviceId: string, correlationId?: string, requestDeviceId?: string): void {
    if (!isValidDeviceId(deviceId)) {
      this.recordAudit(userId, "USER", "DEVICE_REGISTER", "/auth/devices", "DENY", "INVALID_DEVICE_ID", correlationId, requestDeviceId);
      throw new AuthError(400, "INVALID_DEVICE_ID");
    }

    const user = this.database
      .prepare("SELECT is_active FROM users WHERE id = ?")
      .get(userId) as { is_active: number } | undefined;
    if (!user || user.is_active !== 1) {
      this.recordAudit(userId, "USER", "DEVICE_REGISTER", "/auth/devices", "DENY", "INACTIVE_ACCOUNT", correlationId, requestDeviceId);
      throw new AuthError(401, "INACTIVE_ACCOUNT");
    }

    const existing = this.database
      .prepare("SELECT user_id FROM devices WHERE id = ?")
      .get(deviceId) as { user_id: string } | undefined;
    if (existing) {
      this.recordAudit(userId, "USER", "DEVICE_REGISTER", "/auth/devices", "DENY", "DEVICE_ID_EXISTS", correlationId, requestDeviceId);
      throw new AuthError(409, "DEVICE_ID_ALREADY_EXISTS");
    }

    this.database
      .prepare("INSERT INTO devices (id, user_id) VALUES (?, ?)")
      .run(deviceId, userId);
    this.recordAudit(userId, "USER", "DEVICE_REGISTER", "/auth/devices", "ALLOW", "DEVICE_REGISTERED", correlationId, requestDeviceId);
  }

  listDevices(
    userId: string,
    correlationId?: string,
    requestDeviceId?: string
  ): Array<{ id: string; registeredAt: string; revoked: boolean }> {
    const devices = this.database
      .prepare(`
        SELECT id, registered_at
        FROM devices
        WHERE user_id = ? AND is_revoked = 0
        ORDER BY registered_at, id
      `)
      .all(userId) as Array<{ id: string; registered_at: string }>;
    this.recordAudit(userId, "USER", "DEVICE_LIST", "/auth/devices", "ALLOW", "LISTED", correlationId, requestDeviceId);
    return devices.map((device) => ({
      id: device.id,
      registeredAt: device.registered_at,
      revoked: false
    }));
  }

  revokeDevice(userId: string, deviceId: string, correlationId?: string, requestDeviceId?: string): void {
    let revoked: boolean;
    try {
      revoked = this.database.transaction(() => {
        const target = this.database
          .prepare("SELECT user_id, is_revoked FROM devices WHERE id = ?")
          .get(deviceId) as { user_id: string; is_revoked: number } | undefined;
        if (!target || target.user_id !== userId || target.is_revoked !== 0) return false;

        const activeDeviceCount = this.database
          .prepare("SELECT COUNT(*) AS count FROM devices WHERE user_id = ? AND is_revoked = 0")
          .get(userId) as { count: number };
        if (activeDeviceCount.count <= 1) throw new AuthError(409, "CANNOT_REVOKE_LAST_DEVICE");

        const now = this.now().toISOString();
        this.database
          .prepare("UPDATE devices SET is_revoked = 1, revoked_at = ? WHERE id = ?")
          .run(now, deviceId);
        this.database
          .prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL")
          .run(now, deviceId);
        return true;
      })();
    } catch (error) {
      if (error instanceof AuthError && error.code === "CANNOT_REVOKE_LAST_DEVICE") {
        this.recordAudit(userId, "USER", "DEVICE_REVOKE", "/auth/devices", "DENY", error.code, correlationId, requestDeviceId);
      }
      throw error;
    }

    if (!revoked) {
      this.recordAudit(userId, "USER", "DEVICE_REVOKE", "/auth/devices", "DENY", "DEVICE_NOT_OWNED_OR_ACTIVE", correlationId, requestDeviceId);
      throw new AuthError(404, "DEVICE_NOT_FOUND");
    }
    this.recordAudit(userId, "USER", "DEVICE_REVOKE", "/auth/devices", "ALLOW", "DEVICE_REVOKED", correlationId, requestDeviceId);
  }
}

export async function hashPassword(password: string, rounds = 12): Promise<string> {
  if (Buffer.byteLength(password, "utf8") < 12 || Buffer.byteLength(password, "utf8") > 72) {
    throw new AuthError(400, "PASSWORD_LENGTH_INVALID");
  }
  return bcrypt.hash(password, rounds);
}
