import { readFileSync } from "node:fs";
import { parse } from "jsonc-parser";
import { describe, expect, it } from "vitest";
import { BUNDLE_LIMIT_BYTES, checkBundle } from "../../scripts/lib/bundle-check.ts";
import {
  checkPackageJson,
  checkReadme,
  checkWranglerConfig,
  D1_PLACEHOLDER_ID,
  RUNTIME_DEPENDENCIES,
} from "../../scripts/lib/config-check.ts";
import { checkNeutrality, isCheckedForNeutrality } from "../../scripts/lib/neutrality.ts";

type Json = Record<string, unknown>;
const realConfig = (): Json => parse(readFileSync("wrangler.jsonc", "utf8")) as Json;
const clone = (v: Json): Json => structuredClone(v);

describe("config-check (TIO-ARCH-003, TIO-CFG-001, TIO-GEN-003, TIO-DEPLOY-008)", () => {
  it("accepts the committed wrangler.jsonc, package.json and README", () => {
    expect(checkWranglerConfig(realConfig())).toEqual([]);
    expect(checkPackageJson(JSON.parse(readFileSync("package.json", "utf8")))).toEqual([]);
    expect(checkReadme(readFileSync("README.md", "utf8"))).toEqual([]);
  });

  it("rejects nodejs_compat and any compatibility flag", () => {
    const c = realConfig();
    c["compatibility_flags"] = ["nodejs_compat"];
    expect(checkWranglerConfig(c)).toContain(
      "wrangler.jsonc: compatibility_flags must be empty (TIO-CFG-001)",
    );
  });

  it("rejects bindings outside the spec's set and routes in the repository", () => {
    const c = realConfig();
    c["kv_namespaces"] = [{ binding: "KV", id: "x" }];
    c["routes"] = [{ pattern: "auth.example.com", custom_domain: true }];
    const errors = checkWranglerConfig(c);
    expect(errors).toContain(
      'wrangler.jsonc: "kv_namespaces" is not part of the spec\'s binding set (TIO-ARCH-003, TIO-DEPLOY-009)',
    );
    expect(errors).toContain(
      'wrangler.jsonc: "routes" is not part of the spec\'s binding set (TIO-ARCH-003, TIO-DEPLOY-009)',
    );
  });

  it("requires every binding of §2.2 with its exact name", () => {
    const c = realConfig();
    (c["ratelimits"] as Json[]).pop();
    (c["durable_objects"] as { bindings: Json[] }).bindings[0] = {
      name: "USER",
      class_name: "UserDO",
    };
    (c["migrations"] as Json[])[0] = { tag: "v1", new_sqlite_classes: ["UserDO"] };
    (c["analytics_engine_datasets"] as Json[]).length = 0;
    (c["assets"] as Json)["run_worker_first"] = false;
    (c["triggers"] as Json)["crons"] = ["0 * * * *"];
    (c["r2_buckets"] as Json[])[0] = { binding: "AUDIT_BUCKET" };
    (c["queues"] as { consumers: Json[] }).consumers[0] = { queue: "other" };
    delete (c["vars"] as Json)["RP_ID"];
    expect(checkWranglerConfig(c)).toEqual([
      "wrangler.jsonc: one queue consumer on the producer's queue is required",
      "wrangler.jsonc: queue consumer needs a dead_letter_queue",
      "wrangler.jsonc: r2 bucket needs bucket_name",
      'wrangler.jsonc: durable_objects.bindings must be exactly {"USER_DO":"UserDO","INTERACTION_DO":"InteractionDO"} (not inherited by environments)',
      "wrangler.jsonc: ratelimits must be exactly RL_IP, RL_CLIENT (not inherited by environments)",
      "wrangler.jsonc: analytics_engine_datasets must bind exactly METRICS (not inherited by environments)",
      "wrangler.jsonc: migrations must declare new_sqlite_classes for both Durable Object classes",
      "wrangler.jsonc: assets must bind ASSETS with run_worker_first: true",
      'wrangler.jsonc: triggers.crons must be exactly ["*/5 * * * *"]',
      "wrangler.jsonc: vars.RP_ID must be set for the Deploy button profile",
    ]);
  });

  it("requires the D1 placeholder id at top level and no id in environments (TIO-DEPLOY-005)", () => {
    const c = realConfig();
    (c["d1_databases"] as Json[])[0] = {
      binding: "DB",
      database_name: "x",
      migrations_dir: "migrations",
      database_id: "real",
    };
    const env = c["env"] as Record<string, Json>;
    ((env["staging"] as Json)["d1_databases"] as Json[])[0] = {
      binding: "DB",
      database_name: "x",
      migrations_dir: "migrations",
      database_id: D1_PLACEHOLDER_ID,
    };
    (env["production"] as Json)["d1_databases"] = [{ binding: "DB", migrations_dir: "migrations" }];
    (env["production"] as Json)["queues"] = { producers: [] };
    (env["production"] as Json)["r2_buckets"] = [];
    // The bindings wrangler does not inherit: an environment that leaves them out loses them.
    delete (env["production"] as Json)["durable_objects"];
    delete (env["production"] as Json)["ratelimits"];
    delete (env["production"] as Json)["analytics_engine_datasets"];
    const errors = checkWranglerConfig(c);
    expect(errors).toEqual([
      `wrangler.jsonc: top-level database_id must be the placeholder ${D1_PLACEHOLDER_ID} (TIO-DEPLOY-005, TIO-DEPLOY-008)`,
      "wrangler.jsonc env.staging: environment sections must omit database_id (resolved by scripts/deploy.ts)",
      "wrangler.jsonc env.production: d1 database needs database_name and migrations_dir",
      "wrangler.jsonc env.production: queues.producers must bind exactly TASKS",
      "wrangler.jsonc env.production: one queue consumer on the producer's queue is required",
      "wrangler.jsonc env.production: r2_buckets must bind exactly AUDIT_BUCKET",
      'wrangler.jsonc env.production: durable_objects.bindings must be exactly {"USER_DO":"UserDO","INTERACTION_DO":"InteractionDO"} (not inherited by environments)',
      "wrangler.jsonc env.production: ratelimits must be exactly RL_IP, RL_CLIENT (not inherited by environments)",
      "wrangler.jsonc env.production: analytics_engine_datasets must bind exactly METRICS (not inherited by environments)",
    ]);
  });

  it("requires both environment sections", () => {
    const c = clone(realConfig());
    delete (c["env"] as Json)["production"];
    expect(checkWranglerConfig(c)).toEqual(["wrangler.jsonc: env.production is missing"]);
    delete c["env"];
    expect(checkWranglerConfig(c)).toEqual([
      "wrangler.jsonc: env.staging is missing",
      "wrangler.jsonc: env.production is missing",
    ]);
  });

  it("rejects runtime dependencies outside spec §14.1 and missing button scripts", () => {
    expect(RUNTIME_DEPENDENCIES).toEqual([
      "hono",
      "@hono/zod-openapi",
      "zod",
      "jose",
      "@simplewebauthn/server",
      "uuidv7",
    ]);
    expect(
      checkPackageJson({ dependencies: { hono: "1", lodash: "1" }, scripts: { build: "x" } }),
    ).toEqual([
      'package.json: runtime dependency "lodash" is not in the spec §14.1 list (TIO-GEN-003)',
      'package.json: script "deploy" is required by the Deploy button (TIO-DEPLOY-008)',
    ]);
    expect(checkPackageJson({})).toHaveLength(2);
  });

  it("requires the Deploy button in the README", () => {
    expect(checkReadme("# no button")).toHaveLength(1);
  });
});

describe("neutrality-check (TIO-DEPLOY-005)", () => {
  it("flags 32-hex identifiers and non-placeholder database ids", () => {
    // Built at runtime so this file itself passes the neutrality check.
    const hex32 = "0123456789abcdef".repeat(2);
    const key = ["database", "id"].join("_");
    const fakeId = "12345678-1234-1234-1234-123456789012";
    const findings = checkNeutrality({
      "a.md": `account ${hex32} here\nsha ${hex32}01234567 is 40 hex\n`,
      "wrangler.jsonc": `{ "${key}": "${D1_PLACEHOLDER_ID}" }\n{ "${key}": "${fakeId}" }`,
    });
    expect(findings).toEqual([
      {
        path: "a.md",
        line: 1,
        message: `32-hex identifier "${hex32}" looks like a Cloudflare account or resource id`,
      },
      {
        path: "wrangler.jsonc",
        line: 2,
        message: `${key} "${fakeId}" is not the placeholder ${D1_PLACEHOLDER_ID}`,
      },
    ]);
  });

  it("skips binary files and the lockfile", () => {
    expect(isCheckedForNeutrality("doc/x.png")).toBe(false);
    expect(isCheckedForNeutrality("pnpm-lock.yaml")).toBe(false);
    expect(isCheckedForNeutrality("src/index.ts")).toBe(true);
  });
});

describe("bundle-check (TIO-PERF-002, TIO-GEN-002)", () => {
  it("measures the bundle and rejects forbidden content", () => {
    expect(checkBundle({ "a.js": "export default {}" })).toEqual({ bytes: 17, errors: [] });
    const big = checkBundle({ "a.js": "x".repeat(BUNDLE_LIMIT_BYTES + 1) });
    expect(big.errors).toEqual([
      `bundle is ${BUNDLE_LIMIT_BYTES + 1} bytes, over the ${BUNDLE_LIMIT_BYTES} byte budget (TIO-PERF-002)`,
    ]);
    const bad = checkBundle({ "a.js": 'var Handlebars = 1; var DOMPurify = 2; "<!DOCTYPE html>"' });
    expect(bad.errors).toEqual([
      "a.js: bundle contains template engine (handlebars) (TIO-GEN-002)",
      "a.js: bundle contains HTML sanitizer (DOMPurify) (TIO-GEN-002)",
      "a.js: bundle contains an HTML document (TIO-GEN-002)",
    ]);
  });
});
