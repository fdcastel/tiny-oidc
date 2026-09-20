// The pure parts of the conformance runner (spec §13.9, TIO-TEST-040,
// TIO-TEST-041): plan templates rendered with the run's values, the waivers
// file turned into the suite's expected-failures format, and the command line
// of scripts/run-test-plan.py. conformance/run.ts does the I/O.

export interface RunValues {
  /** The OP under test. */
  issuer: string;
  /** The login app's URL (the `login_url` setting). */
  loginUrl: string;
  /** The alias of the staging-only auto-approving upstream. */
  upstreamAlias: string;
  /** The suite's public base URL (the tunnel), without a trailing slash. */
  suite: string;
  /** The alias the suite uses in its callback paths (`/test/a/<alias>/…`). */
  alias: string;
  clients: Record<"basic" | "post" | "none", { id: string; secret: string | null }>;
  clients2: Record<"basic" | "post" | "none", { id: string; secret: string | null }>;
}

/** Fills `{NAME}` placeholders; a placeholder without a value is an error. */
export function render(template: string, values: Record<string, string>): string {
  return template.replaceAll(/\{([A-Z0-9_]+)\}/g, (_, name: string) => {
    const value = values[name];
    if (value === undefined) throw new Error(`no value for {${name}}`);
    return value;
  });
}

/** The placeholder values of one client-authentication variant. */
export function placeholders(
  values: RunValues,
  variant: "basic" | "post" | "none",
): Record<string, string> {
  const client = values.clients[variant];
  const client2 = values.clients2[variant];
  return {
    ISSUER: values.issuer,
    LOGIN_URL: values.loginUrl,
    LOGIN_ORIGIN: new URL(values.loginUrl).origin,
    UPSTREAM_ALIAS: values.upstreamAlias,
    SUITE: values.suite,
    ALIAS: values.alias,
    CLIENT_ID: client.id,
    CLIENT_SECRET: client.secret ?? "",
    CLIENT2_ID: client2.id,
    CLIENT2_SECRET: client2.secret ?? "",
  };
}

/** The suite's variant name for a client-authentication variant of ours. */
export const CLIENT_AUTH_TYPE = {
  basic: "client_secret_basic",
  post: "client_secret_post",
  none: "none",
} as const;

export interface PlanRun {
  /** The plan as `run-test-plan.py` takes it: `name[variant=value]…`. */
  plan: string;
  /** The rendered configuration file. */
  config: string;
}

/**
 * The four plans of TIO-TEST-040 with their variants: config, basic in the
 * three client-authentication variants, RP-initiated logout and back-channel
 * logout (both with the basic client).
 */
export function planRuns(configDir: string): PlanRun[] {
  // The certification plans fix the response type and mode themselves, and the config plan its
  // metadata source: only the selectable variants are given (the suite refuses the rest).
  const server = "[server_metadata=discovery][client_registration=static_client]";
  const auth = (v: keyof typeof CLIENT_AUTH_TYPE) => `[client_auth_type=${CLIENT_AUTH_TYPE[v]}]`;
  return [
    { plan: "oidcc-config-certification-test-plan", config: `${configDir}/config.json` },
    {
      plan: `oidcc-basic-certification-test-plan${server}${auth("basic")}`,
      config: `${configDir}/basic-client_secret_basic.json`,
    },
    {
      plan: `oidcc-basic-certification-test-plan${server}${auth("post")}`,
      config: `${configDir}/basic-client_secret_post.json`,
    },
    {
      plan: `oidcc-basic-certification-test-plan${server}${auth("none")}`,
      config: `${configDir}/basic-none.json`,
    },
    {
      plan: `oidcc-rp-initiated-logout-certification-test-plan${server}${auth("basic")}`,
      config: `${configDir}/rp-initiated-logout.json`,
    },
    {
      plan: `oidcc-backchannel-rp-initiated-logout-certification-test-plan${server}${auth("basic")}`,
      config: `${configDir}/backchannel-logout.json`,
    },
  ];
}

/** Which template and variant each rendered configuration comes from. */
export const CONFIG_SOURCES: Record<
  string,
  { template: string; variant: "basic" | "post" | "none" }
> = {
  "config.json": { template: "config.json", variant: "basic" },
  "basic-client_secret_basic.json": { template: "basic.json", variant: "basic" },
  "basic-client_secret_post.json": { template: "basic.json", variant: "post" },
  "basic-none.json": { template: "basic.json", variant: "none" },
  "rp-initiated-logout.json": { template: "rp-initiated-logout.json", variant: "basic" },
  "backchannel-logout.json": { template: "backchannel-logout.json", variant: "basic" },
};

/** The one reason a waiver may carry (TIO-TEST-040). */
export const WAIVER_REASON =
  "feature intentionally unsupported and advertised as such in discovery";

export interface Waiver {
  "test-name": string;
  variant: Record<string, string> | "*";
  "configuration-filename": string;
  condition: string;
  "current-block": string;
  "expected-result": "failure" | "warning";
  reason: string;
  /** What in discovery advertises the absence (a metadata field), for the reviewer. */
  advertised_by: string;
}

/** Validates the waivers and returns them in the suite's expected-failures format (reason dropped). */
export function expectedFailures(waivers: Waiver[]): Omit<Waiver, "reason" | "advertised_by">[] {
  const out: Omit<Waiver, "reason" | "advertised_by">[] = [];
  for (const [i, w] of waivers.entries()) {
    if (w.reason !== WAIVER_REASON)
      throw new Error(`waiver ${i} (${w["test-name"]}): reason must be "${WAIVER_REASON}"`);
    if (typeof w.advertised_by !== "string" || w.advertised_by.length === 0)
      throw new Error(
        `waiver ${i} (${w["test-name"]}): advertised_by must name the discovery field`,
      );
    if (w["expected-result"] !== "failure" && w["expected-result"] !== "warning")
      throw new Error(
        `waiver ${i} (${w["test-name"]}): expected-result must be failure or warning`,
      );
    const { reason: _reason, advertised_by: _by, ...entry } = w;
    out.push(entry);
  }
  return out;
}

/** The argument list of `run-test-plan.py` for the runs. */
export function runnerArgs(
  runs: PlanRun[],
  exportDir: string,
  expectedFailuresFile: string,
): string[] {
  return [
    "--export-dir",
    exportDir,
    "--expected-failures-file",
    expectedFailuresFile,
    ...runs.flatMap((r) => [r.plan, r.config]),
  ];
}

/** The suite's callback URIs for a plan alias, as the OP must register them (spec §13.9). */
export function suiteUris(suite: string, alias: string) {
  const base = `${suite}/test/a/${alias}`;
  return {
    redirect_uris: [`${base}/callback`, `${base}/callback?dummy1=lorem&dummy2=ipsum`],
    post_logout_redirect_uris: [`${base}/post_logout_redirect`],
    backchannel_logout_uri: `${base}/backchannel_logout`,
  };
}

/**
 * A plan configuration from its template: the `"{BROWSER}"` string becomes the
 * rendered browser block (an array, so it cannot be a plain placeholder), then
 * every `{NAME}` gets its value. The result is parsed, so a broken template
 * fails here and not in the suite.
 */
export function renderPlan(
  template: string,
  browserTemplate: string,
  values: Record<string, string>,
): string {
  const withBrowser = template.replace('"{BROWSER}"', browserTemplate.trim());
  const rendered = render(withBrowser, values);
  return `${JSON.stringify(JSON.parse(rendered), null, 2)}\n`;
}
