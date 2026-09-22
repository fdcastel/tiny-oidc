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

const HEALTH = "/api/v1/health";
const SETTLE_INTERVAL_MS = 2_000;

export interface SmokeFailure {
  path: string;
  reason: string;
}

export interface SmokeOptions {
  /** Sent with every request, e.g. `Cloudflare-Workers-Version-Overrides`. */
  headers?: Record<string, string>;
  /** The build health must report (the deploy's `VERSION` var). */
  version?: string;
  /**
   * How long to wait for health to report `version` before the checks run. A
   * new deployment takes seconds to reach every Cloudflare location, and until
   * it does the override is ignored there and the live build answers.
   */
  settleMs?: number;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
}

export async function smoke(baseUrl: string, options: SmokeOptions = {}): Promise<SmokeFailure[]> {
  const fetchImpl = options.fetch ?? fetch;
  const sleep = options.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const base = baseUrl.replace(/\/+$/, "");
  const get = (path: string) =>
    fetchImpl(`${base}${path}`, { redirect: "manual", headers: options.headers ?? {} });

  let waited = 0;
  if (options.version !== undefined) {
    const settle = options.settleMs ?? 60_000;
    while (waited < settle) {
      const reported = await get(HEALTH)
        .then(async (res) =>
          res.status === 200 ? ((await res.json()) as { version?: unknown }).version : undefined,
        )
        .catch(() => undefined);
      if (reported === options.version) break;
      await sleep(SETTLE_INTERVAL_MS);
      waited += SETTLE_INTERVAL_MS;
    }
  }

  const failures: SmokeFailure[] = [];
  for (const path of SMOKE_PATHS) {
    try {
      const res = await get(path);
      if (res.status !== 200) {
        failures.push({ path, reason: `status ${res.status}` });
        continue;
      }
      const body = (await res.json()) as Record<string, unknown>;
      if (path !== HEALTH) continue;
      if (body["status"] !== "ok") {
        failures.push({ path, reason: `health reports ${JSON.stringify(body)}` });
      } else if (options.version !== undefined && body["version"] !== options.version) {
        failures.push({
          path,
          reason: `health reports version ${JSON.stringify(body["version"])}, expected "${options.version}" after waiting ${waited / 1000} s`,
        });
      }
    } catch (error) {
      failures.push({ path, reason: error instanceof Error ? error.message : String(error) });
    }
  }
  return failures;
}
