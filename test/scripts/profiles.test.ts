import { readdirSync, readFileSync } from "node:fs";
import { parse } from "jsonc-parser";
import { describe, expect, it } from "vitest";

// Requirements the spec once verified by review only (review 2026-09-26, §4):
// the deployment profiles share nothing, the runbook covers what TIO-DEPLOY-004
// lists, and no workflow holds a Cloudflare credential or deploys.

interface Profile {
  name?: string;
  main?: string;
  d1_databases?: { database_name: string }[];
  queues?: {
    producers?: { queue: string }[];
    consumers?: { queue: string; dead_letter_queue?: string }[];
  };
  r2_buckets?: { bucket_name: string }[];
  ratelimits?: { namespace_id: string }[];
  analytics_engine_datasets?: { dataset: string }[];
  durable_objects?: { bindings: { class_name: string }[] };
  env?: Record<string, Profile>;
}

const config = parse(readFileSync("wrangler.jsonc", "utf8")) as Profile;
const profiles: Record<string, Profile> = {
  button: config,
  staging: config.env?.["staging"] as Profile,
  production: config.env?.["production"] as Profile,
};

/** Every named resource of a profile: the Worker, databases, queues, buckets, limits, datasets. */
function resources(profile: Profile): string[] {
  return [
    `worker:${profile.name}`,
    ...(profile.d1_databases ?? []).map((d) => `d1:${d.database_name}`),
    ...(profile.queues?.producers ?? []).map((q) => `queue:${q.queue}`),
    ...(profile.queues?.consumers ?? []).flatMap((q) => [
      `queue:${q.queue}`,
      ...(q.dead_letter_queue === undefined ? [] : [`queue:${q.dead_letter_queue}`]),
    ]),
    ...(profile.r2_buckets ?? []).map((b) => `r2:${b.bucket_name}`),
    ...(profile.ratelimits ?? []).map((r) => `ratelimit:${r.namespace_id}`),
    ...(profile.analytics_engine_datasets ?? []).map((a) => `dataset:${a.dataset}`),
  ];
}

describe("deployment profiles", () => {
  it("[TIO-DEPLOY-001] the button, staging and production profiles share no Worker name, database, queue, bucket, rate-limit namespace or dataset", () => {
    const owners = new Map<string, string[]>();
    for (const [name, profile] of Object.entries(profiles)) {
      const own = resources(profile);
      // Each profile declares every kind of resource it needs.
      for (const kind of ["worker", "d1", "queue", "r2", "ratelimit", "dataset"]) {
        expect(
          own.some((r) => r.startsWith(`${kind}:`)),
          `${name} ${kind}`,
        ).toBe(true);
      }
      for (const resource of new Set(own)) {
        owners.set(resource, [...(owners.get(resource) ?? []), name]);
      }
    }
    expect([...owners].filter(([, names]) => names.length > 1)).toEqual([]);
    expect(profiles["production"]?.name).toBe("tiny-oidc-production");
  });
});

describe("the single Worker script (wrangler side)", () => {
  it("[TIO-ARCH-001] every profile runs src/index.ts and binds exactly the UserDO and InteractionDO classes", () => {
    expect(config.main).toBe("src/index.ts");
    for (const [name, profile] of Object.entries(profiles)) {
      const classes = (profile.durable_objects?.bindings ?? []).map((b) => b.class_name).sort();
      expect(classes, name).toEqual(["InteractionDO", "UserDO"]);
    }
  });
});

describe("the runbook", () => {
  it("[TIO-DEPLOY-004] has a section for bootstrap, key rotation, master-key rotation, emergency key retirement, client-secret rotation, user recovery, D1 restore, reindex and a lost MASTER_KEYS", () => {
    const headings = readFileSync("doc/RUNBOOK.md", "utf8")
      .split("\n")
      .filter((line) => line.startsWith("## "));
    for (const topic of [
      /Bootstrap/,
      /Signing-key rotation/,
      /Master-key rotation/,
      /Emergency key retirement/,
      /Client-secret rotation/,
      /User recovery/,
      /D1 backup and restore/,
      /Reindex/,
      /Lost `MASTER_KEYS`/,
    ]) {
      expect(
        headings.some((h) => topic.test(h)),
        String(topic),
      ).toBe(true);
    }
  });
});

describe("GitHub workflows", () => {
  it("[TIO-DEPLOY-006] hold no Cloudflare credential and never deploy: Workers Builds deploys, GitHub runs tests and gates", () => {
    const dir = ".github/workflows";
    const files = readdirSync(dir).filter((f) => /\.ya?ml$/.test(f));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const code = readFileSync(`${dir}/${file}`, "utf8")
        .split("\n")
        .filter((line) => !line.trim().startsWith("#"))
        .join("\n");
      expect(code, file).not.toMatch(/CLOUDFLARE_API_TOKEN|CLOUDFLARE_ACCOUNT_ID|CF_API_TOKEN/);
      expect(code, file).not.toMatch(/wrangler\s+(deploy|versions|secret|d1\s+migrations)/);
      expect(code, file).not.toMatch(/scripts\/deploy\.ts|pnpm\s+(run\s+)?deploy/);
    }
  });
});
