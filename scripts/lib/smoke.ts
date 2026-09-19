// Smoke test of a deployment (TIO-DEPLOY-007): discovery, JWKS and health must
// answer. Discovery and JWKS join the list in Phase 1.

export const SMOKE_PATHS = ["/api/v1/health"] as const;

export interface SmokeFailure {
  path: string;
  reason: string;
}

export async function smoke(
  baseUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<SmokeFailure[]> {
  const failures: SmokeFailure[] = [];
  const base = baseUrl.replace(/\/+$/, "");
  for (const path of SMOKE_PATHS) {
    try {
      const res = await fetchImpl(`${base}${path}`, { redirect: "manual" });
      if (res.status !== 200) {
        failures.push({ path, reason: `status ${res.status}` });
        continue;
      }
      const body = (await res.json()) as Record<string, unknown>;
      if (path === "/api/v1/health" && body["status"] !== "ok") {
        failures.push({ path, reason: `health reports ${JSON.stringify(body)}` });
      }
    } catch (error) {
      failures.push({ path, reason: error instanceof Error ? error.message : String(error) });
    }
  }
  return failures;
}
