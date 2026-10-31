import { AuthService } from "@zero-trust/auth";
import { openDatabase } from "@zero-trust/database";
import { createNilaiApp, getNilaiPort } from "./app.js";
import { createTranscriptSyncClient } from "./transcript-sync-client.js";

const accessSecret = process.env.JWT_ACCESS_SECRET;
if (!accessSecret) throw new Error("JWT_ACCESS_SECRET is required for Service Nilai.");
const gatewaySecret = process.env.GATEWAY_SECRET;
if (!gatewaySecret) throw new Error("GATEWAY_SECRET is required for Service Nilai.");
const serviceClientId = process.env.SERVICE_NILAI_CLIENT_ID;
const serviceClientSecret = process.env.SERVICE_NILAI_CLIENT_SECRET;
if (!serviceClientId || !serviceClientSecret) {
  throw new Error("SERVICE_NILAI_CLIENT_ID and SERVICE_NILAI_CLIENT_SECRET are required for transcript synchronization.");
}

const database = openDatabase();
const app = createNilaiApp(database, new AuthService(database, accessSecret), gatewaySecret, {
  transcriptSync: createTranscriptSyncClient({
    gatewayBaseUrl: process.env.GATEWAY_BASE_URL ?? "http://127.0.0.1:3000",
    clientId: serviceClientId,
    clientSecret: serviceClientSecret
  })
});
const port = getNilaiPort();
const server = app.listen(port, "127.0.0.1", () => {
  console.info(`Service Nilai listening on http://127.0.0.1:${port}`);
});

function shutdown(): void {
  server.close(() => {
    database.close();
    process.exit(0);
  });
}

process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
