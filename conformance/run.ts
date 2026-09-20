// The conformance run against staging (spec §13.9, TIO-TEST-040, TIO-TEST-041):
//
//   node conformance/run.ts --suite-scripts <checkout>/scripts [--suite-url https://localhost:8443]
//                           [--public-url https://<tunnel>] [--alias tiny-oidc] [--results conformance/results]
//
// with TIO_STAGING_ISSUER, TIO_STAGING_LOGIN_URL, TIO_STAGING_CLIENT_ID and
// TIO_STAGING_CLIENT_SECRET (an automation client with the admin scope) and
// TIO_STAGING_UPSTREAM_ALIAS (default `fake`) in the environment.
//
// It registers (or re-points) the suite's relying parties on staging with the
// suite's public URLs, rotates their secrets so no secret is stored anywhere,
// renders the plan configurations, turns conformance/waivers.json into the
// suite's expected-failures and expected-skips files, and hands everything to the suite's own
// scripts/run-test-plan.py, whose exit code is this script's. The suite runs
// in dev mode (no API token), reached over the local address; the OP reaches
// it over the public one.

import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import {
  CONFIG_FILES,
  expectedProblems,
  placeholders,
  planRuns,
  RELYING_PARTIES,
  type RelyingParty,
  type RunValues,
  renderPlan,
  runnerArgs,
  suiteUris,
  type Waiver,
} from "./lib.ts";

const { values } = parseArgs({
  options: {
    "suite-scripts": { type: "string" },
    "suite-url": {
      type: "string",
      default: process.env["CONFORMANCE_SERVER"] ?? "https://localhost:8443",
    },
    "public-url": { type: "string", default: process.env["CONFORMANCE_PUBLIC_URL"] },
    alias: { type: "string", default: "tiny-oidc" },
    results: { type: "string", default: "conformance/results" },
    "dry-run": { type: "boolean", default: false },
  },
});

const env = (name: string): string => {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
};
const issuer = env("TIO_STAGING_ISSUER").replace(/\/$/, "");
const loginUrl = env("TIO_STAGING_LOGIN_URL");
const upstreamAlias = process.env["TIO_STAGING_UPSTREAM_ALIAS"] ?? "fake";
const suiteUrl = (values["suite-url"] as string).replace(/\/$/, "");
const publicUrl = (values["public-url"] ?? suiteUrl).replace(/\/$/, "");
const alias = values.alias as string;
const results = values.results as string;
const log = (message: string) => console.error(`conformance: ${message}`);

// --- the admin session ------------------------------------------------------------------

let bearer: { value: string; at: number } | null = null;
async function token(): Promise<string> {
  if (bearer && Date.now() - bearer.at < 8 * 60_000) return bearer.value;
  const res = await fetch(`${issuer}/token`, {
    method: "POST",
    headers: {
      authorization: `Basic ${Buffer.from(`${env("TIO_STAGING_CLIENT_ID")}:${env("TIO_STAGING_CLIENT_SECRET")}`).toString("base64")}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ grant_type: "client_credentials", scope: "admin" }),
  });
  if (!res.ok) throw new Error(`admin token: ${res.status} ${await res.text()}`);
  bearer = { value: ((await res.json()) as { access_token: string }).access_token, at: Date.now() };
  return bearer.value;
}

async function admin<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: T }> {
  const init: RequestInit = { method, headers: { authorization: `Bearer ${await token()}` } };
  if (body !== undefined) {
    init.headers = { ...init.headers, "content-type": "application/json" };
    init.body = JSON.stringify(body);
  }
  const res = await fetch(`${issuer}/api/v1/admin/${path}`, init);
  const text = await res.text();
  return { status: res.status, body: (text === "" ? {} : JSON.parse(text)) as T };
}

// --- the suite's relying parties on staging ----------------------------------------------

/**
 * Creates or re-points one relying party and returns its fresh secret. The
 * suite's modules send no PKCE (only its one PKCE test does), so the parties
 * are confidential clients registered without the requirement (TIO-AUTHZ-008).
 */
async function relyingParty(party: RelyingParty): Promise<{ id: string; secret: string }> {
  const id = `conformance-${party}`;
  const method = RELYING_PARTIES[party];
  const uris = suiteUris(publicUrl, alias);
  const body = {
    client_name: `Conformance suite (${method}${party === "basic2" ? ", second client" : ""})`,
    redirect_uris: uris.redirect_uris,
    post_logout_redirect_uris: uris.post_logout_redirect_uris,
    backchannel_logout_uri: uris.backchannel_logout_uri,
    grant_types: ["authorization_code", "refresh_token"],
    token_endpoint_auth_method: method,
    scopes_allowed: ["openid", "email", "profile", "offline_access"],
    skip_consent: true,
    offline_access: true,
    require_pkce: false,
  };
  const existing = await admin<{ error?: string }>("GET", `clients/${id}`);
  let secret: string | undefined;
  if (existing.status === 404) {
    const created = await admin<{
      client_secret?: string;
      error?: string;
      error_description?: string;
    }>("POST", "clients", { client_id: id, ...body });
    if (created.status !== 201)
      throw new Error(`client ${id}: ${created.status} ${JSON.stringify(created.body)}`);
    secret = created.body.client_secret;
    log(`client ${id}: created`);
  } else if (existing.status === 200) {
    const updated = await admin<{ error?: string; error_description?: string }>(
      "PATCH",
      `clients/${id}`,
      body,
    );
    if (updated.status !== 200)
      throw new Error(`client ${id}: ${updated.status} ${JSON.stringify(updated.body)}`);
    const rotated = await admin<{ client_secret?: string }>("POST", `clients/${id}/rotate-secret`);
    if (rotated.status !== 200) throw new Error(`client ${id}: rotate ${rotated.status}`);
    secret = rotated.body.client_secret;
    log(`client ${id}: re-pointed at ${publicUrl}`);
  } else {
    throw new Error(`client ${id}: ${existing.status} ${JSON.stringify(existing.body)}`);
  }
  if (secret === undefined) throw new Error(`client ${id}: no secret returned`);
  return { id, secret };
}

// --- the run ----------------------------------------------------------------------------

async function main(): Promise<number> {
  const configDir = join(results, "config");
  const exportDir = join(results, "export");
  mkdirSync(configDir, { recursive: true });
  mkdirSync(exportDir, { recursive: true });
  // Waivers first: a bad one stops the run before anything touches staging.
  const waivers = JSON.parse(readFileSync("conformance/waivers.json", "utf8")) as Waiver[];
  const problems = expectedProblems(waivers);
  const expectedFile = join(results, "expected-failures.json");
  const skipsFile = join(results, "expected-skips.json");
  writeFileSync(expectedFile, `${JSON.stringify(problems.failures, null, 2)}\n`);
  writeFileSync(skipsFile, `${JSON.stringify(problems.skips, null, 2)}\n`);
  log(
    `${waivers.length} waiver(s): ${problems.failures.length} expected failure(s) → ${expectedFile}, ${problems.skips.length} expected skip(s) → ${skipsFile}`,
  );
  const run: RunValues = {
    issuer,
    loginUrl,
    upstreamAlias,
    suite: publicUrl,
    alias,
    clients: {
      basic: await relyingParty("basic"),
      basic2: await relyingParty("basic2"),
      post: await relyingParty("post"),
    },
  };
  const browser = readFileSync("conformance/plans/browser.json", "utf8");
  const placeholderValues = placeholders(run);
  for (const file of CONFIG_FILES) {
    const template = readFileSync(`conformance/plans/${file}`, "utf8");
    writeFileSync(join(configDir, file), renderPlan(template, browser, placeholderValues));
  }
  const runs = planRuns(configDir);
  const args = runnerArgs(runs, exportDir, expectedFile, skipsFile);
  log(`run-test-plan.py ${args.join(" ")}`);
  if (values["dry-run"]) return 0;
  const scripts = values["suite-scripts"];
  if (!scripts)
    throw new Error("--suite-scripts is required (the suite checkout's scripts/ directory)");
  const child = spawnSync("python3", [join(scripts, "run-test-plan.py"), ...args], {
    stdio: "inherit",
    env: {
      ...process.env,
      CONFORMANCE_SERVER: `${suiteUrl}/`,
      CONFORMANCE_SERVER_MTLS: `${suiteUrl}/`,
      CONFORMANCE_DEV_MODE: "1",
      DISABLE_SSL_VERIFY: "1",
    },
  });
  return child.status ?? 1;
}

process.exitCode = await main();
