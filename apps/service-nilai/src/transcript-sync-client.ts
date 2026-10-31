interface SyncPayload {
  classId: string;
  sourceVersion: number;
  grades: Array<{ studentId: string; score: number }>;
}

interface ServiceTokenResponse {
  accessToken: string;
  tokenType: "Bearer";
  expiresIn: number;
}

export function createTranscriptSyncClient(options: {
  gatewayBaseUrl: string;
  clientId: string;
  clientSecret: string;
}): (payload: SyncPayload) => Promise<void> {
  const baseUrl = new URL(options.gatewayBaseUrl);
  if (
    baseUrl.protocol !== "http:" || baseUrl.hostname !== "127.0.0.1" ||
    baseUrl.username || baseUrl.password || Buffer.byteLength(options.clientSecret, "utf8") < 32
  ) throw new Error("Transcript sync requires a local Gateway URL and a service secret of at least 32 bytes.");

  return async (payload) => {
    const tokenResponse = await fetch(new URL("/auth/service", baseUrl), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_id: options.clientId, client_secret: options.clientSecret }),
      signal: AbortSignal.timeout(5000)
    });
    if (!tokenResponse.ok) throw new Error("Service token request was rejected.");
    const token = await tokenResponse.json() as Partial<ServiceTokenResponse>;
    if (
      token.tokenType !== "Bearer" || typeof token.accessToken !== "string" ||
      typeof token.expiresIn !== "number" || token.expiresIn <= 0 || token.expiresIn > 300
    ) throw new Error("Gateway returned an invalid service token response.");

    const syncResponse = await fetch(new URL("/transkrip/sinkron", baseUrl), {
      method: "POST",
      headers: {
        authorization: `Bearer ${token.accessToken}`,
        "content-type": "application/json"
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000)
    });
    if (!syncResponse.ok) throw new Error("Transcript synchronization was rejected.");
    const result = await syncResponse.json() as { synced?: unknown };
    if (result.synced !== true) throw new Error("Transcript synchronization was not confirmed.");
  };
}
