import { AuthService } from "@zero-trust/auth";
import { openDatabase } from "@zero-trust/database";
import { createTranscriptApp, getTranscriptPort } from "./app.js";

const accessSecret = process.env.JWT_ACCESS_SECRET;
const gatewaySecret = process.env.GATEWAY_SECRET;
const serviceTokenSecret = process.env.SERVICE_TOKEN_SECRET;
if (!accessSecret) throw new Error("JWT_ACCESS_SECRET is required for Service Transkrip.");
if (!gatewaySecret) throw new Error("GATEWAY_SECRET is required for Service Transkrip.");
if (!serviceTokenSecret) throw new Error("SERVICE_TOKEN_SECRET is required for Service Transkrip.");

const database = openDatabase();
const app = createTranscriptApp(database, new AuthService(database, accessSecret), gatewaySecret, serviceTokenSecret);
const port = getTranscriptPort();
const server = app.listen(port, "127.0.0.1", () => {
  console.info(`Service Transkrip listening on http://127.0.0.1:${port}`);
});

function shutdown(): void {
  server.close(() => {
    database.close();
    process.exit(0);
  });
}

process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
