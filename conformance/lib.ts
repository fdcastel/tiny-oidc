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
  /**
   * The suite's relying parties: `client` and `client2` (client_secret_basic) for the
   * basic and RP-initiated logout plans, `client_secret_post` for the basic plan's
   * client_secret_post module, and the back-channel pair for the back-channel plan.
   */
  clients: Record<RelyingParty, { id: string; secret: string }>;
}

/**
 * The relying parties the plans read from their configuration (`client`,
 * `client2`, `client_secret_post`). Only the back-channel plan's parties
 * register a `backchannel_logout_uri`: the suite serves that path in that
 * plan alone, and a logout token sent to any other plan's callback is an
 * unexpected request that fails the module.
 */
export type RelyingParty = "basic" | "basic2" | "post" | "backchannel" | "backchannel2";

export interface RelyingPartyProfile {
  method: "client_secret_basic" | "client_secret_post";
  backchannel: boolean;
}

/** The registration of each relying party. */
export const RELYING_PARTIES: Record<RelyingParty, RelyingPartyProfile> = {
  basic: { method: "client_secret_basic", backchannel: false },
  basic2: { method: "client_secret_basic", backchannel: false },
  post: { method: "client_secret_post", backchannel: false },
  backchannel: { method: "client_secret_basic", backchannel: true },
  backchannel2: { method: "client_secret_basic", backchannel: true },
};

/** Fills `{NAME}` placeholders; a placeholder without a value is an error. */
export function render(template: string, values: Record<string, string>): string {
  return template.replaceAll(/\{([A-Z0-9_]+)\}/g, (_, name: string) => {
    const value = values[name];
    if (value === undefined) throw new Error(`no value for {${name}}`);
    return value;
  });
}

/** The placeholder values of a run. */
export function placeholders(values: RunValues): Record<string, string> {
  return {
    ISSUER: values.issuer,
    LOGIN_URL: values.loginUrl,
    LOGIN_ORIGIN: new URL(values.loginUrl).origin,
    UPSTREAM_ALIAS: values.upstreamAlias,
    SUITE: values.suite,
    ALIAS: values.alias,
    CLIENT_ID: values.clients.basic.id,
    CLIENT_SECRET: values.clients.basic.secret,
    CLIENT2_ID: values.clients.basic2.id,
    CLIENT2_SECRET: values.clients.basic2.secret,
    POST_CLIENT_ID: values.clients.post.id,
    POST_CLIENT_SECRET: values.clients.post.secret,
    BACKCHANNEL_CLIENT_ID: values.clients.backchannel.id,
    BACKCHANNEL_CLIENT_SECRET: values.clients.backchannel.secret,
    BACKCHANNEL_CLIENT2_ID: values.clients.backchannel2.id,
    BACKCHANNEL_CLIENT2_SECRET: values.clients.backchannel2.secret,
  };
}

export interface PlanRun {
  /** The plan as `run-test-plan.py` takes it: `name[variant=value]…`. */
  plan: string;
  /** The rendered configuration file. */
  config: string;
}

/**
 * The four plans of TIO-TEST-040 with the variants each one leaves to the
 * user, exactly as the suite's own CI invokes them (`.gitlab-ci/run-tests.sh`):
 * the config plan fixes every variant; the basic plan fixes the response type,
 * the client authentication (it runs client_secret_basic and one
 * client_secret_post module itself) and the response mode; the logout plans
 * fix the metadata source, the client authentication and the response mode.
 * A variant a plan fixes is refused on the command line.
 */
export function planRuns(configDir: string): PlanRun[] {
  return [
    { plan: "oidcc-config-certification-test-plan", config: `${configDir}/config.json` },
    {
      plan: "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]",
      config: `${configDir}/basic.json`,
    },
    {
      plan: "oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]",
      config: `${configDir}/rp-initiated-logout.json`,
    },
    {
      plan: "oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]",
      config: `${configDir}/backchannel-logout.json`,
    },
  ];
}

/** The rendered configurations, each from the template of the same name. */
export const CONFIG_FILES = [
  "config.json",
  "basic.json",
  "rp-initiated-logout.json",
  "backchannel-logout.json",
] as const;

/** The one reason a waiver may carry (TIO-TEST-040). */
export const WAIVER_REASON =
  "feature intentionally unsupported and advertised as such in discovery";

/**
 * A waiver: a condition allowed to fail or warn, or a whole module allowed to
 * skip (the suite skips a module itself when discovery says the feature is
 * absent, and an unexpected skip fails the plan like a failure does).
 */
export interface Waiver {
  "test-name": string;
  variant: Record<string, string> | "*";
  "configuration-filename": string;
  /** The failing condition class; absent for a skip. */
  condition?: string;
  /** The block the condition fails in (`"*"` for any); absent for a skip. */
  "current-block"?: string;
  "expected-result": "failure" | "warning" | "skip";
  reason: string;
  /** What in discovery advertises the absence (a metadata field), for the reviewer. */
  advertised_by: string;
}

/** An entry of the suite's expected-failures file. */
export interface ExpectedFailure {
  "test-name": string;
  variant: Record<string, string> | "*";
  "configuration-filename": string;
  condition: string;
  "current-block": string;
  "expected-result": "failure" | "warning";
}

/** An entry of the suite's expected-skips file. */
export interface ExpectedSkip {
  "test-name": string;
  variant: Record<string, string> | "*";
  "configuration-filename": string;
}

/**
 * Validates every waiver and splits them into the suite's two files: the
 * expected failures (with warnings) and the expected skips. The reason and
 * the advertising field are for the reviewer and do not travel.
 */
export function expectedProblems(waivers: Waiver[]): {
  failures: ExpectedFailure[];
  skips: ExpectedSkip[];
} {
  const failures: ExpectedFailure[] = [];
  const skips: ExpectedSkip[] = [];
  for (const [i, w] of waivers.entries()) {
    const where = `waiver ${i} (${w["test-name"]})`;
    if (w.reason !== WAIVER_REASON) throw new Error(`${where}: reason must be "${WAIVER_REASON}"`);
    if (typeof w.advertised_by !== "string" || w.advertised_by.length === 0)
      throw new Error(`${where}: advertised_by must name the discovery field`);
    const head = {
      "test-name": w["test-name"],
      variant: w.variant,
      "configuration-filename": w["configuration-filename"],
    };
    if (w["expected-result"] === "skip") {
      if (w.condition !== undefined || w["current-block"] !== undefined)
        throw new Error(`${where}: a skip names no condition or block`);
      skips.push(head);
    } else if (w["expected-result"] === "failure" || w["expected-result"] === "warning") {
      if (typeof w.condition !== "string" || typeof w["current-block"] !== "string")
        throw new Error(`${where}: a failure or warning names its condition and block`);
      failures.push({
        ...head,
        condition: w.condition,
        "current-block": w["current-block"],
        "expected-result": w["expected-result"],
      });
    } else {
      throw new Error(`${where}: expected-result must be failure, warning or skip`);
    }
  }
  return { failures, skips };
}

/** The argument list of `run-test-plan.py` for the runs. */
export function runnerArgs(
  runs: PlanRun[],
  exportDir: string,
  expectedFailuresFile: string,
  expectedSkipsFile: string,
): string[] {
  return [
    "--export-dir",
    exportDir,
    "--expected-failures-file",
    expectedFailuresFile,
    "--expected-skips-file",
    expectedSkipsFile,
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

/** One entry of a test module's event log (`GET /api/log/{id}`); the suite adds arbitrary fields. */
export interface LogEntry {
  src?: string;
  time?: number;
  msg?: string;
  result?: string;
  [key: string]: unknown;
}

const DIAGNOSTIC_SOURCES = new Set(["BROWSER", "WebRunner"]);
const BODY_LIMIT = 600;

/**
 * The lines worth reading when the browser automation fails: the suite's own
 * WebRunner entries (with `browser_verbose`, every request the browser made
 * and every response it got) and the BROWSER entries (script errors, console
 * output). Bodies are cut at BODY_LIMIT characters; headers are one line.
 */
export function browserDiagnostics(entries: LogEntry[]): string[] {
  const lines: string[] = [];
  for (const entry of entries) {
    if (!entry.src || !DIAGNOSTIC_SOURCES.has(entry.src)) continue;
    const at = entry.time === undefined ? "" : `${new Date(entry.time).toISOString()} `;
    lines.push(`${at}${entry.src}: ${entry.msg ?? ""}`);
    for (const [key, value] of Object.entries(entry)) {
      if (["src", "time", "msg", "result", "_id", "testId", "testOwner", "seq"].includes(key))
        continue;
      if (value === undefined || value === null || value === "") continue;
      const text = typeof value === "string" ? value : JSON.stringify(value);
      lines.push(
        `    ${key}: ${text.length > BODY_LIMIT ? `${text.slice(0, BODY_LIMIT)}…` : text}`,
      );
    }
  }
  return lines;
}
