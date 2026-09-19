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
  smoke(baseUrl: string): Promise<void>;
  log(message: string): void;
}

export const GENERATED_CONFIG = "wrangler.generated.jsonc";
const PREVIEW_URL = /https:\/\/[a-z0-9-]+-[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev/i;
const VERSION_ID = /Worker Version ID:\s*([0-9a-f-]{36})/i;

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
  const commands: string[][] = [];
  const run = async (args: string[]): Promise<string> => {
    commands.push(args);
    io.log(`wrangler ${args.join(" ")}`);
    return io.wrangler(args);
  };

  const scoped: string[] = [];
  if (profile !== "button") {
    // Resolve the D1 id by name so no account-specific id lives in the repository (TIO-DEPLOY-005).
    const list = await run(["d1", "list", "--json"]);
    const id = resolveDatabaseId(list, databaseName(configText, profile));
    const generated = io.writeGeneratedConfig(withDatabaseId(configText, profile, id));
    scoped.push("--config", generated, "--env", profile);
  }

  await run(["d1", "migrations", "apply", "DB", "--remote", ...scoped]);

  const vars = varArgs(env);
  if (profile === "production") {
    // Upload, smoke-test the preview, then move 100% of traffic (§12.3).
    const output = await run(["versions", "upload", ...scoped, ...vars]);
    const preview = PREVIEW_URL.exec(output)?.[0];
    const versionId = VERSION_ID.exec(output)?.[1];
    if (!preview || !versionId)
      throw new Error("could not find the preview URL and version id in the upload output");
    await io.smoke(preview);
    await run(["versions", "deploy", `${versionId}@100%`, "--yes", ...scoped]);
  } else {
    await run(["deploy", ...scoped, ...vars]);
  }
  return { profile, commands };
}
