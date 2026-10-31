import { AuthService } from "@zero-trust/auth";
import { openDatabase } from "@zero-trust/database";
import { createAuthApp } from "./app.js";

const accessSecret = process.env.JWT_ACCESS_SECRET;
if (!accessSecret) {
  throw new Error("JWT_ACCESS_SECRET is required. Copy .env.example to .env and set a random secret.");
}
const gatewaySecret = process.env.GATEWAY_SECRET;
if (!gatewaySecret) {
  throw new Error("GATEWAY_SECRET is required. Copy .env.example to .env and set a random secret.");
}
const serviceTokenSecret = process.env.SERVICE_TOKEN_SECRET;
if (!serviceTokenSecret || Buffer.byteLength(serviceTokenSecret, "utf8") < 32) {
  throw new Error("SERVICE_TOKEN_SECRET with at least 32 UTF-8 bytes is required for service token signing.");
}
const serviceNilaiClientId = process.env.SERVICE_NILAI_CLIENT_ID;
const serviceNilaiClientSecret = process.env.SERVICE_NILAI_CLIENT_SECRET;
if (!serviceNilaiClientId || !serviceNilaiClientSecret || Buffer.byteLength(serviceNilaiClientSecret, "utf8") < 32) {
  throw new Error("SERVICE_NILAI_CLIENT_ID and a SERVICE_NILAI_CLIENT_SECRET of at least 32 bytes are required.");
}

const port = Number(process.env.GATEWAY_PORT ?? 3000);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("GATEWAY_PORT must be a valid TCP port.");
}

const database = openDatabase();
const nilaiPort = Number(process.env.NILAI_PORT ?? 3001);
if (!Number.isInteger(nilaiPort) || nilaiPort < 1 || nilaiPort > 65535) {
  throw new Error("NILAI_PORT must be a valid TCP port.");
}
const transcriptPort = Number(process.env.TRANSKRIP_PORT ?? 3002);
if (!Number.isInteger(transcriptPort) || transcriptPort < 1 || transcriptPort > 65535) {
  throw new Error("TRANSKRIP_PORT must be a valid TCP port.");
}
const app = createAuthApp(new AuthService(database, accessSecret), {
  database,
  gatewaySecret,
  nilaiBaseUrl: `http://127.0.0.1:${nilaiPort}`,
  transcriptBaseUrl: `http://127.0.0.1:${transcriptPort}`,
  serviceTokenSecret,
  serviceNilaiClientId,
  serviceNilaiClientSecret
});
const server = app.listen(port, "127.0.0.1", () => {
  console.info(`Authentication API listening on http://127.0.0.1:${port}`);
});

function shutdown(): void {
  server.close(() => {
    database.close();
    process.exit(0);
  });
}

process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
