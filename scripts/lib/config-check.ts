// Configuration invariants (TIO-ARCH-003, TIO-CFG-001, TIO-GEN-003, TIO-DEPLOY-008,
// TIO-DEPLOY-009). Pure checks over parsed wrangler.jsonc, package.json and README.

/** Runtime dependencies allowed by spec §14.1. Adding one requires a spec change. */
export const RUNTIME_DEPENDENCIES = [
  "hono",
  "@hono/zod-openapi",
  "zod",
  "jose",
  "@simplewebauthn/server",
  "uuidv7",
] as const;

/** The exact binding set of spec §2.2. */
const EXPECTED_BINDINGS = {
  d1: ["DB"],
  durableObjects: { USER_DO: "UserDO", INTERACTION_DO: "InteractionDO" },
  queues: ["TASKS"],
  r2: ["AUDIT_BUCKET"],
  ratelimits: ["RL_IP", "RL_CLIENT"],
  analytics: ["METRICS"],
  assets: "ASSETS",
  crons: ["*/5 * * * *"],
} as const;

export const D1_PLACEHOLDER_ID = "00000000-0000-4000-8000-000000000000";
const DEPLOY_BUTTON_URL = "https://deploy.workers.cloudflare.com/?url=";

/** Wrangler config keys that declare bindings the spec does not allow. */
const FORBIDDEN_BINDING_KEYS = [
  "kv_namespaces",
  "services",
  "vectorize",
  "hyperdrive",
  "workflows",
  "browser",
  "ai",
  "send_email",
  "mtls_certificates",
  "dispatch_namespaces",
  "version_metadata",
  "secrets_store_secrets",
  "pipelines",
  "images",
  "unsafe",
  "routes",
  "route",
  "tail_consumers",
  "containers",
  "media",
];

type Json = Record<string, unknown>;

const asArray = (v: unknown): Json[] => (Array.isArray(v) ? (v as Json[]) : []);
const asObject = (v: unknown): Json =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Json) : {};
const names = (items: Json[], key: string): string[] => items.map((i) => String(i[key]));

function sameSet(actual: string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && expected.every((e) => actual.includes(e));
}

/**
 * Checks one profile (top-level or an env section). Bindings are not inherited by
 * environments (wrangler's config schema says so for d1_databases, queues, r2_buckets,
 * durable_objects, ratelimits and analytics_engine_datasets), so every profile must
 * declare all of them; migrations, assets, triggers and the button-only vars are
 * top-level facts.
 */
function checkProfile(profile: Json, label: string, errors: string[], topLevel: boolean): void {
  const d1 = asArray(profile["d1_databases"]);
  if (!sameSet(names(d1, "binding"), EXPECTED_BINDINGS.d1))
    errors.push(`${label}: d1_databases must bind exactly ${EXPECTED_BINDINGS.d1.join(", ")}`);
  for (const db of d1) {
    if (!db["database_name"] || !db["migrations_dir"])
      errors.push(`${label}: d1 database needs database_name and migrations_dir`);
    if (topLevel && db["database_id"] !== D1_PLACEHOLDER_ID)
      errors.push(
        `${label}: top-level database_id must be the placeholder ${D1_PLACEHOLDER_ID} (TIO-DEPLOY-005, TIO-DEPLOY-008)`,
      );
    if (!topLevel && db["database_id"] !== undefined)
      errors.push(
        `${label}: environment sections must omit database_id (resolved by scripts/deploy.ts)`,
      );
  }
  const queues = asObject(profile["queues"]);
  const producers = asArray(queues["producers"]);
  const consumers = asArray(queues["consumers"]);
  if (!sameSet(names(producers, "binding"), EXPECTED_BINDINGS.queues))
    errors.push(
      `${label}: queues.producers must bind exactly ${EXPECTED_BINDINGS.queues.join(", ")}`,
    );
  if (consumers.length !== 1 || consumers[0]?.["queue"] !== producers[0]?.["queue"])
    errors.push(`${label}: one queue consumer on the producer's queue is required`);
  if (consumers[0] && !consumers[0]["dead_letter_queue"])
    errors.push(`${label}: queue consumer needs a dead_letter_queue`);
  const r2 = asArray(profile["r2_buckets"]);
  if (!sameSet(names(r2, "binding"), EXPECTED_BINDINGS.r2))
    errors.push(`${label}: r2_buckets must bind exactly ${EXPECTED_BINDINGS.r2.join(", ")}`);
  for (const b of r2) if (!b["bucket_name"]) errors.push(`${label}: r2 bucket needs bucket_name`);
  for (const key of FORBIDDEN_BINDING_KEYS)
    if (key in profile)
      errors.push(
        `${label}: "${key}" is not part of the spec's binding set (TIO-ARCH-003, TIO-DEPLOY-009)`,
      );
  const dos = asArray(asObject(profile["durable_objects"])["bindings"]);
  const actual = Object.fromEntries(dos.map((d) => [String(d["name"]), String(d["class_name"])]));
  if (JSON.stringify(actual) !== JSON.stringify(EXPECTED_BINDINGS.durableObjects))
    errors.push(
      `${label}: durable_objects.bindings must be exactly ${JSON.stringify(EXPECTED_BINDINGS.durableObjects)} (not inherited by environments)`,
    );
  if (!sameSet(names(asArray(profile["ratelimits"]), "name"), EXPECTED_BINDINGS.ratelimits))
    errors.push(
      `${label}: ratelimits must be exactly ${EXPECTED_BINDINGS.ratelimits.join(", ")} (not inherited by environments)`,
    );
  if (
    !sameSet(
      names(asArray(profile["analytics_engine_datasets"]), "binding"),
      EXPECTED_BINDINGS.analytics,
    )
  )
    errors.push(
      `${label}: analytics_engine_datasets must bind exactly ${EXPECTED_BINDINGS.analytics.join(", ")} (not inherited by environments)`,
    );
  if (topLevel) {
    const flags = asArray(profile["compatibility_flags"]);
    if (!Array.isArray(profile["compatibility_flags"]) || flags.length !== 0)
      errors.push(`${label}: compatibility_flags must be empty (TIO-CFG-001)`);
    const migrations = asArray(profile["migrations"]);
    const classes = migrations.flatMap((m) =>
      Array.isArray(m["new_sqlite_classes"]) ? (m["new_sqlite_classes"] as string[]) : [],
    );
    if (!sameSet(classes, Object.values(EXPECTED_BINDINGS.durableObjects)))
      errors.push(
        `${label}: migrations must declare new_sqlite_classes for both Durable Object classes`,
      );
    const assets = asObject(profile["assets"]);
    if (assets["binding"] !== EXPECTED_BINDINGS.assets || assets["run_worker_first"] !== true)
      errors.push(
        `${label}: assets must bind ${EXPECTED_BINDINGS.assets} with run_worker_first: true`,
      );
    const crons = asObject(profile["triggers"])["crons"];
    if (JSON.stringify(crons) !== JSON.stringify(EXPECTED_BINDINGS.crons))
      errors.push(
        `${label}: triggers.crons must be exactly ${JSON.stringify(EXPECTED_BINDINGS.crons)}`,
      );
    for (const v of ["ISSUER", "RP_ID", "RP_NAME", "BUNDLED_LOGIN_APP"])
      if (typeof asObject(profile["vars"])[v] !== "string")
        errors.push(`${label}: vars.${v} must be set for the Deploy button profile`);
  }
}

export function checkWranglerConfig(config: Json): string[] {
  const errors: string[] = [];
  checkProfile(config, "wrangler.jsonc", errors, true);
  const env = asObject(config["env"]);
  for (const name of ["staging", "production"]) {
    const profile = env[name];
    if (!profile) errors.push(`wrangler.jsonc: env.${name} is missing`);
    else checkProfile(asObject(profile), `wrangler.jsonc env.${name}`, errors, false);
  }
  return errors;
}

export function checkPackageJson(pkg: Json): string[] {
  const errors: string[] = [];
  const deps = Object.keys(asObject(pkg["dependencies"]));
  for (const dep of deps) {
    if (!(RUNTIME_DEPENDENCIES as readonly string[]).includes(dep))
      errors.push(
        `package.json: runtime dependency "${dep}" is not in the spec §14.1 list (TIO-GEN-003)`,
      );
  }
  const scripts = asObject(pkg["scripts"]);
  for (const s of ["build", "deploy"])
    if (typeof scripts[s] !== "string")
      errors.push(`package.json: script "${s}" is required by the Deploy button (TIO-DEPLOY-008)`);
  return errors;
}

export function checkReadme(readme: string): string[] {
  return readme.includes(DEPLOY_BUTTON_URL)
    ? []
    : [
        `README.md: Deploy-to-Cloudflare button (${DEPLOY_BUTTON_URL}…) is missing (TIO-DEPLOY-008)`,
      ];
}
