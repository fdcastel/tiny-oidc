// Smoke test of a deployment (TIO-DEPLOY-007): discovery, JWKS and health must
// answer with 200 JSON, and health must report ok. A deploy smoke-tests a new
// version before it takes traffic on the issuer's own hostname, with the
// version-override header naming it; health's `version` then shows whether the
// override reached the new build rather than the live one.

export const SMOKE_PATHS = [
  "/.well-known/openid-configuration",
  "/.well-known/jwks.json",
  "/api/v1/health",
] as const;

export interface SmokeFailure {
  path: string;
  reason: string;
}

export interface SmokeOptions {
  /** Sent with every request, e.g. `Cloudflare-Workers-Version-Overrides`. */
  headers?: Record<string, string>;
  /** The build health must report (the deploy's `VERSION` var). */
  version?: string;
  fetch?: typeof fetch;
}

export async function smoke(baseUrl: string, options: SmokeOptions = {}): Promise<SmokeFailure[]> {
  const fetchImpl = options.fetch ?? fetch;
  const failures: SmokeFailure[] = [];
  const base = baseUrl.replace(/\/+$/, "");
  for (const path of SMOKE_PATHS) {
    try {
      const res = await fetchImpl(`${base}${path}`, {
        redirect: "manual",
        headers: options.headers ?? {},
      });
      if (res.status !== 200) {
        failures.push({ path, reason: `status ${res.status}` });
        continue;
      }
      const body = (await res.json()) as Record<string, unknown>;
      if (path !== "/api/v1/health") continue;
      if (body["status"] !== "ok") {
        failures.push({ path, reason: `health reports ${JSON.stringify(body)}` });
      } else if (options.version !== undefined && body["version"] !== options.version) {
        failures.push({
          path,
          reason: `health reports version ${JSON.stringify(body["version"])}, expected "${options.version}"`,
        });
      }
    } catch (error) {
      failures.push({ path, reason: error instanceof Error ? error.message : String(error) });
    }
  }
  return failures;
}
