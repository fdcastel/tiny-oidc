// Deployment logic (TIO-DEPLOY-007): the same `pnpm run deploy` for every
// profile. Pure over an injected runner so it is unit-tested with a fake
// wrangler; scripts/deploy.ts wires the real one.
import { applyEdits, modify, parse } from "jsonc-parser";

export type Profile = "button" | "staging" | "production";

export interface DeployEnv {
  TIO_ENV?: string | undefined;
  TIO_ISSUER?: string | undefined;
  TIO_RP_ID?: string | undefined;
  TIO_RP_NAME?: string | undefined;
  /** Commit sha exposed by Workers Builds; reported by /api/v1/health as VERSION. */
  WORKERS_CI_COMMIT_SHA?: string | undefined;
  /**
   * `true` deploys staging or production with a plain `wrangler deploy`: for
   * the Worker's first deployment (no live version to keep serving) and for a
   * release that carries a Durable Object class migration, which Cloudflare
   * cannot upload as a version. Set it for that one build only.
   */
  TIO_DIRECT_DEPLOY?: string | undefined;
  /** The fake upstream's configuration (staging only, TIO-TEST-031). */
  TIO_FAKE_ISSUER?: string | undefined;
  TIO_FAKE_CLIENT_ID?: string | undefined;
  TIO_FAKE_CLIENT_SECRET?: string | undefined;
  /** Comma-separated redirect URIs the fake accepts (the OP's federation callback). */
  TIO_FAKE_REDIRECT_URIS?: string | undefined;
}

export interface DeployIO {
  /** Runs wrangler with the arguments and returns its stdout. Throws on a non-zero exit. */
  wrangler(args: string[]): Promise<string>;
  readConfig(): string;
  /** Writes the generated configuration (never committed) and returns its path. */
  writeGeneratedConfig(content: string): string;
  /** Throws when the deployment at `baseUrl`, reached with `headers`, is not healthy or not `version`. */
  smoke(
    baseUrl: string,
    options: { headers: Record<string, string>; version: string },
  ): Promise<void>;
  log(message: string): void;
}

export const GENERATED_CONFIG = "wrangler.generated.jsonc";
const VERSION_ID = /Worker Version ID:\s*([0-9a-f-]{36})/i;

/** Routes one request to a named version of a Worker, if that version is in the current deployment. */
export const VERSION_OVERRIDE_HEADER = "Cloudflare-Workers-Version-Overrides";

export function profileOf(env: DeployEnv): Profile {
  const value = env.TIO_ENV ?? "";
  if (value === "") return "button";
  if (value === "staging" || value === "production") return value;
  throw new Error(`TIO_ENV must be empty, "staging" or "production"; got "${value}"`);
}

/** `--var` arguments for the values the deploy environment supplies (never from the repository). */
export function varArgs(env: DeployEnv): string[] {
  const args: string[] = [];
  const pairs: [string, string | undefined][] = [
    ["ISSUER", env.TIO_ISSUER],
    ["RP_ID", env.TIO_RP_ID],
    ["RP_NAME", env.TIO_RP_NAME],
    ["VERSION", env.WORKERS_CI_COMMIT_SHA?.slice(0, 7)],
  ];
  for (const [name, value] of pairs) if (value) args.push("--var", `${name}:${value}`);
  return args;
}

interface D1ListEntry {
  uuid: string;
  name: string;
}

/** The database id for a name from `wrangler d1 list --json` output. */
export function resolveDatabaseId(listJson: string, name: string): string {
  const entries = JSON.parse(listJson) as D1ListEntry[];
  const match = entries.find((e) => e.name === name);
  if (!match)
    throw new Error(`D1 database "${name}" not found; create it with: wrangler d1 create ${name}`);
  return match.uuid;
}

/** The environment's database name from wrangler.jsonc. */
export function databaseName(configText: string, profile: "staging" | "production"): string {
  const config = parse(configText) as {
    env?: Record<string, { d1_databases?: { database_name?: string }[] }>;
  };
  const name = config.env?.[profile]?.d1_databases?.[0]?.database_name;
  if (!name) throw new Error(`wrangler.jsonc env.${profile} has no d1 database_name`);
  return name;
}

/** The environment's Worker name from wrangler.jsonc (the version-override header names it). */
export function workerName(configText: string, profile: "staging" | "production"): string {
  const config = parse(configText) as { env?: Record<string, { name?: string }> };
  const name = config.env?.[profile]?.name;
  if (!name) throw new Error(`wrangler.jsonc env.${profile} has no name`);
  return name;
}

/**
 * The version serving all traffic, from `wrangler deployments status --json`;
 * null when nothing is deployed. A deployment split between versions is a
 * gradual rollout someone else started (one this script left at 0% when it was
 * interrupted still has its live version at 100%, and is accepted): without a
 * version at 100% there is nothing safe to restore to, so it is refused.
 */
export function liveVersion(statusJson: string): string | null {
  const status = JSON.parse(statusJson) as {
    versions?: { version_id: string; percentage: number }[];
  };
  const versions = status.versions ?? [];
  if (versions.length === 0) return null;
  const live = versions.find((v) => v.percentage === 100);
  if (!live) {
    const split = versions.map((v) => `${v.version_id}@${v.percentage}%`).join(" ");
    throw new Error(
      `the current deployment splits traffic (${split}); finish or undo that rollout first`,
    );
  }
  return live.version_id;
}

/** The configuration with the resolved `database_id` inserted for the environment. */
export function withDatabaseId(
  configText: string,
  profile: "staging" | "production",
  id: string,
): string {
  const edits = modify(configText, ["env", profile, "d1_databases", 0, "database_id"], id, {
    formattingOptions: { insertSpaces: true, tabSize: 2 },
  });
  return applyEdits(configText, edits);
}

/**
 * The deploy environment's values must be usable before anything is deployed
 * (TIO-DEPLOY-007: any failing step aborts before traffic changes). A build
 * variable holding its own name or an unparseable URL would otherwise deploy
 * a Worker that answers every request with "server misconfigured" in place of
 * a working one. Same rules as the Worker's startup check (TIO-CFG-002).
 */
export function assertDeployVars(env: DeployEnv, profile: Profile): void {
  if (profile === "button") return;
  const issuer = env.TIO_ISSUER ?? "";
  const url = URL.canParse(issuer) ? new URL(issuer) : undefined;
  if (
    url?.protocol !== "https:" ||
    url.search !== "" ||
    url.hash !== "" ||
    /[?#]/.test(issuer) ||
    url.username !== "" ||
    url.password !== ""
  ) {
    throw new Error(
      `TIO_ISSUER must be an https URL with no query, fragment or credentials; got "${issuer}"`,
    );
  }
  const rpId = env.TIO_RP_ID ?? "";
  if (!(url.hostname === rpId || url.hostname.endsWith(`.${rpId}`))) {
    throw new Error(
      `TIO_RP_ID must equal the TIO_ISSUER host or be a parent domain of it; got "${rpId}"`,
    );
  }
  if (!env.TIO_RP_NAME) throw new Error("TIO_RP_NAME must be set");
}

/** The fake upstream Worker is never deployed outside staging (TIO-TEST-031). */
export function assertDeployable(configText: string, profile: Profile): void {
  const config = parse(configText) as { name?: string };
  if ((config.name ?? "").includes("fake-upstream") && profile !== "staging") {
    throw new Error("the fake upstream may only be deployed to staging");
  }
}

export interface DeployResult {
  profile: Profile;
  commands: string[][];
}

export const FAKE_UPSTREAM_CONFIG = "test/support/fake-upstream/wrangler.jsonc";

/**
 * Deploys the fake upstream Worker (TIO-TEST-031): staging only, its
 * configuration from the deploy environment, nothing from the repository.
 */
export async function deployFakeUpstream(
  env: DeployEnv,
  io: Pick<DeployIO, "wrangler" | "readConfig" | "log">,
): Promise<DeployResult> {
  const profile = profileOf(env);
  assertDeployable(io.readConfig(), profile);
  if (profile !== "staging") throw new Error("the fake upstream may only be deployed to staging");
  const vars: string[] = [];
  const pairs: [string, string | undefined][] = [
    ["FAKE_ISSUER", env.TIO_FAKE_ISSUER],
    ["FAKE_CLIENT_ID", env.TIO_FAKE_CLIENT_ID],
    ["FAKE_CLIENT_SECRET", env.TIO_FAKE_CLIENT_SECRET],
    ["FAKE_REDIRECT_URIS", env.TIO_FAKE_REDIRECT_URIS],
  ];
  for (const [name, value] of pairs) {
    if (!value) throw new Error(`TIO_${name} must be set to deploy the fake upstream`);
    vars.push("--var", `${name}:${value}`);
  }
  const args = ["deploy", "--config", FAKE_UPSTREAM_CONFIG, ...vars];
  io.log(`wrangler ${args.filter((a) => !a.startsWith("FAKE_CLIENT_SECRET:")).join(" ")}`);
  await io.wrangler(args);
  return { profile, commands: [args] };
}

export async function deploy(env: DeployEnv, io: DeployIO): Promise<DeployResult> {
  const profile = profileOf(env);
  const configText = io.readConfig();
  assertDeployable(configText, profile);
  assertDeployVars(env, profile);
  const commands: string[][] = [];
  const run = async (args: string[]): Promise<string> => {
    commands.push(args);
    io.log(`wrangler ${args.join(" ")}`);
    return io.wrangler(args);
  };
  const vars = varArgs(env);

  if (profile === "button") {
    await run(["d1", "migrations", "apply", "DB", "--remote"]);
    await run(["deploy", ...vars]);
    return { profile, commands };
  }

  // Resolve the D1 id by name so no account-specific id lives in the repository (TIO-DEPLOY-005).
  const list = await run(["d1", "list", "--json"]);
  const id = resolveDatabaseId(list, databaseName(configText, profile));
  const generated = io.writeGeneratedConfig(withDatabaseId(configText, profile, id));
  const scoped = ["--config", generated, "--env", profile];
  const migrate = ["d1", "migrations", "apply", "DB", "--remote", ...scoped];

  if (env.TIO_DIRECT_DEPLOY === "true") {
    io.log(
      "TIO_DIRECT_DEPLOY: deploying with no smoke test before traffic moves; remove the variable after this build and run `pnpm smoke <issuer>`",
    );
    await run(migrate);
    await run(["deploy", ...scoped, ...vars]);
    return { profile, commands };
  }

  // Staged rollout (§12.3): the new version joins the deployment at 0%, the
  // smoke test reaches it on the issuer's own hostname through the version
  // override, and only then does it take 100%. A failed smoke test restores
  // the live version, so no request but the smoke test's reaches a version
  // that failed. Everything that can refuse the rollout is read first, before
  // anything on the account changes.
  const version = env.WORKERS_CI_COMMIT_SHA?.slice(0, 7);
  if (!version) {
    throw new Error(
      "a staged rollout needs the commit sha (WORKERS_CI_COMMIT_SHA) to recognise the new version",
    );
  }
  const worker = workerName(configText, profile);
  let status: string;
  try {
    status = await run(["deployments", "status", "--json", ...scoped]);
  } catch (error) {
    throw new Error(
      "could not read the current deployment; for the Worker's first deployment set TIO_DIRECT_DEPLOY=true for that build",
      { cause: error },
    );
  }
  const live = liveVersion(status);
  if (live === null) {
    throw new Error(
      "no version is deployed yet; for the Worker's first deployment set TIO_DIRECT_DEPLOY=true for that build",
    );
  }

  await run(migrate);
  const output = await run(["versions", "upload", ...scoped, ...vars]);
  const candidate = VERSION_ID.exec(output)?.[1];
  if (!candidate) throw new Error("could not find the version id in the upload output");
  await run(["versions", "deploy", `${candidate}@0%`, `${live}@100%`, "--yes", ...scoped]);
  try {
    await io.smoke(env.TIO_ISSUER as string, {
      headers: { [VERSION_OVERRIDE_HEADER]: `${worker}="${candidate}"` },
      version,
    });
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    try {
      await run(["versions", "deploy", `${live}@100%`, "--yes", ...scoped]);
    } catch (restoreError) {
      throw new Error(
        `${reason}; restoring ${live}@100% failed as well (the new version ${candidate} stays in the deployment at 0% and takes no traffic)`,
        { cause: restoreError },
      );
    }
    throw new Error(`${reason}; ${live} serves all traffic again`, { cause: error });
  }
  await run(["versions", "deploy", `${candidate}@100%`, "--yes", ...scoped]);
  return { profile, commands };
}
