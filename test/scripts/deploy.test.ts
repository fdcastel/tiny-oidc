import { readFileSync } from "node:fs";
import { parse } from "jsonc-parser";
import { describe, expect, it } from "vitest";
import {
  assertDeployable,
  assertDeployVars,
  type DeployIO,
  databaseName,
  deploy,
  deployFakeUpstream,
  FAKE_UPSTREAM_CONFIG,
  liveVersion,
  profileOf,
  resolveDatabaseId,
  VERSION_OVERRIDE_HEADER,
  varArgs,
  withDatabaseId,
  workerName,
} from "../../scripts/lib/deploy.ts";
import { SMOKE_PATHS, smoke } from "../../scripts/lib/smoke.ts";

const SHA = "0123456789abcdef0123456789abcdef01234567";
const PRODUCTION = {
  TIO_ENV: "production",
  TIO_ISSUER: "https://auth.example.com",
  TIO_RP_ID: "example.com",
  TIO_RP_NAME: "Example",
  WORKERS_CI_COMMIT_SHA: SHA,
};
const STAGING = {
  TIO_ENV: "staging",
  TIO_ISSUER: "https://auth.staging.example.com",
  TIO_RP_ID: "staging.example.com",
  TIO_RP_NAME: "Example Staging",
  WORKERS_CI_COMMIT_SHA: SHA,
};

const realConfig = readFileSync("wrangler.jsonc", "utf8");
const D1_LIST = JSON.stringify([
  { uuid: "11111111-2222-4333-8444-555555555555", name: "tiny-oidc-staging" },
  { uuid: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", name: "tiny-oidc-production" },
]);
const LIVE = "1f40bd8a-ca69-45df-9ee8-e48e82233d70";
const CANDIDATE = "2bcd9f3a-aebd-46cc-9fc0-7d8a968e7f9e";
const STATUS = JSON.stringify({
  id: "2fe29eac-0d55-473b-8bd0-9c225b65f13d",
  source: "wrangler",
  strategy: "percentage",
  versions: [{ version_id: LIVE, percentage: 100 }],
});
// What `wrangler versions upload` (4.135) printed for this Worker on staging,
// trimmed of the bindings table: a version id and no preview URL. The deploy
// once required a preview URL and would have refused every production release.
const UPLOAD_OUTPUT = [
  "Total Upload: 1186.00 KiB / gzip: 301.53 KiB",
  "Worker Startup Time: 76 ms",
  "Uploaded tiny-oidc-staging (8.86 sec)",
  `Worker Version ID: ${CANDIDATE}`,
  "",
  "To deploy this version to production traffic use the command wrangler versions deploy",
].join("\n");

interface SmokeCall {
  baseUrl: string;
  headers: Record<string, string>;
  version: string;
}

/** A fake wrangler that records calls and answers with canned output. */
function fakeIo(
  options: {
    smokeFails?: boolean;
    uploadOutput?: string;
    status?: string | Error;
    restoreFails?: boolean;
  } = {},
) {
  const calls: string[][] = [];
  const written: string[] = [];
  const logs: string[] = [];
  const smokes: SmokeCall[] = [];
  const io: DeployIO = {
    wrangler: async (args) => {
      calls.push(args);
      if (args[0] === "d1" && args[1] === "list") return D1_LIST;
      if (args[0] === "deployments" && args[1] === "status") {
        const status = options.status ?? STATUS;
        if (status instanceof Error) throw status;
        return status;
      }
      if (args[0] === "versions" && args[1] === "upload")
        return options.uploadOutput ?? UPLOAD_OUTPUT;
      if (options.restoreFails && args[0] === "versions" && args[2] === `${LIVE}@100%`) {
        throw new Error("wrangler: network unreachable");
      }
      return "";
    },
    readConfig: () => realConfig,
    writeGeneratedConfig: (content) => {
      written.push(content);
      return "wrangler.generated.jsonc";
    },
    smoke: async (baseUrl, smokeOptions) => {
      smokes.push({ baseUrl, ...smokeOptions });
      logs.push(`smoke ${baseUrl}`);
      if (options.smokeFails) throw new Error("smoke test failed: /api/v1/health: status 500");
    },
    log: (m) => logs.push(m),
  };
  return { io, calls, written, logs, smokes };
}

const scoped = (profile: string) => ["--config", "wrangler.generated.jsonc", "--env", profile];

describe("deploy script (TIO-DEPLOY-007)", () => {
  it("[TIO-DEPLOY-007] the button profile applies migrations and deploys with the committed configuration and no --var", async () => {
    const { io, calls, written } = fakeIo();
    const result = await deploy({}, io);
    expect(result.profile).toBe("button");
    expect(calls).toEqual([["d1", "migrations", "apply", "DB", "--remote"], ["deploy"]]);
    expect(written).toEqual([]);
  });

  it("[TIO-DEPLOY-007] staging reads the live version, migrates, uploads the new one at 0%, smoke-tests it on the issuer through the version override and only then gives it 100%", async () => {
    const { io, calls, written, smokes } = fakeIo();
    const result = await deploy(STAGING, io);
    expect(result.profile).toBe("staging");
    expect(calls).toEqual([
      ["d1", "list", "--json"],
      ["deployments", "status", "--json", ...scoped("staging")],
      ["d1", "migrations", "apply", "DB", "--remote", ...scoped("staging")],
      [
        "versions",
        "upload",
        ...scoped("staging"),
        "--var",
        "ISSUER:https://auth.staging.example.com",
        "--var",
        "RP_ID:staging.example.com",
        "--var",
        "RP_NAME:Example Staging",
        "--var",
        "VERSION:0123456",
      ],
      ["versions", "deploy", `${CANDIDATE}@0%`, `${LIVE}@100%`, "--yes", ...scoped("staging")],
      ["versions", "deploy", `${CANDIDATE}@100%`, "--yes", ...scoped("staging")],
    ]);
    // The smoke test runs between the 0% and the 100% deployments, on the
    // issuer's own hostname (anything else answers 421, TIO-HTTP-006), and
    // must meet the new build.
    expect(smokes).toEqual([
      {
        baseUrl: "https://auth.staging.example.com",
        headers: { [VERSION_OVERRIDE_HEADER]: `tiny-oidc-staging="${CANDIDATE}"` },
        version: "0123456",
      },
    ]);
    expect(written).toHaveLength(1);
    const generated = parse(written[0] as string) as {
      env: Record<string, { d1_databases: { database_id?: string; database_name: string }[] }>;
      d1_databases: { database_id: string }[];
    };
    expect(generated.env["staging"]?.d1_databases[0]).toEqual({
      binding: "DB",
      database_name: "tiny-oidc-staging",
      migrations_dir: "migrations",
      database_id: "11111111-2222-4333-8444-555555555555",
    });
    expect(generated.env["production"]?.d1_databases[0]?.database_id).toBeUndefined();
    expect(generated.d1_databases[0]?.database_id).toBe("00000000-0000-4000-8000-000000000000");
    // Comments of the source file survive the edit.
    expect(written[0]).toContain("Host-neutral configuration");
  });

  it("[TIO-DEPLOY-007] production rolls out the same way, the override naming the production Worker", async () => {
    const { io, calls, logs, smokes } = fakeIo();
    const result = await deploy(PRODUCTION, io);
    expect(result.profile).toBe("production");
    expect(calls.map((c) => c.slice(0, 3))).toEqual([
      ["d1", "list", "--json"],
      ["deployments", "status", "--json"],
      ["d1", "migrations", "apply"],
      ["versions", "upload", "--config"],
      ["versions", "deploy", `${CANDIDATE}@0%`],
      ["versions", "deploy", `${CANDIDATE}@100%`],
    ]);
    expect(calls[3]).toContain("--var");
    expect(smokes[0]?.headers).toEqual({ [VERSION_OVERRIDE_HEADER]: `tiny-oidc="${CANDIDATE}"` });
    const smokeIndex = logs.indexOf("smoke https://auth.example.com");
    const fullIndex = logs.indexOf(
      `wrangler versions deploy ${CANDIDATE}@100% --yes ${scoped("production").join(" ")}`,
    );
    expect(smokeIndex).toBeGreaterThan(-1);
    expect(smokeIndex).toBeLessThan(fullIndex);
  });

  it("[TIO-DEPLOY-007] a failed smoke test restores the live version and never gives the new one traffic", async () => {
    const { io, calls } = fakeIo({ smokeFails: true });
    await expect(deploy(PRODUCTION, io)).rejects.toThrow(
      `smoke test failed: /api/v1/health: status 500; ${LIVE} serves all traffic again`,
    );
    expect(calls.slice(-2)).toEqual([
      ["versions", "deploy", `${CANDIDATE}@0%`, `${LIVE}@100%`, "--yes", ...scoped("production")],
      ["versions", "deploy", `${LIVE}@100%`, "--yes", ...scoped("production")],
    ]);
    expect(calls.some((c) => c.includes(`${CANDIDATE}@100%`))).toBe(false);
    // When the restore fails too, the smoke failure is still what the operator reads.
    const both = fakeIo({ smokeFails: true, restoreFails: true });
    await expect(deploy(PRODUCTION, both.io)).rejects.toThrow(
      `smoke test failed: /api/v1/health: status 500; restoring ${LIVE}@100% failed as well (the new version ${CANDIDATE} stays in the deployment at 0% and takes no traffic)`,
    );
  });

  it("[TIO-DEPLOY-007] what can refuse a rollout is read before anything on the account changes", async () => {
    const beforeChanges = (calls: string[][]) =>
      calls.every((c) => (c[0] === "d1" && c[1] === "list") || c[0] === "deployments");
    const cases: [ReturnType<typeof fakeIo>, Record<string, string | undefined>, string][] = [
      [fakeIo(), { WORKERS_CI_COMMIT_SHA: undefined }, "needs the commit sha"],
      [
        fakeIo({ status: new Error("Worker not found") }),
        {},
        "could not read the current deployment; for the Worker's first deployment set TIO_DIRECT_DEPLOY=true",
      ],
      [fakeIo({ status: JSON.stringify({ versions: [] }) }), {}, "no version is deployed yet"],
      [
        fakeIo({
          status: JSON.stringify({
            versions: [
              { version_id: LIVE, percentage: 50 },
              { version_id: CANDIDATE, percentage: 50 },
            ],
          }),
        }),
        {},
        `the current deployment splits traffic (${LIVE}@50% ${CANDIDATE}@50%)`,
      ],
    ];
    for (const [fake, override, message] of cases) {
      await expect(deploy({ ...STAGING, ...override }, fake.io)).rejects.toThrow(message);
      expect(beforeChanges(fake.calls)).toBe(true);
    }
    const noVersion = fakeIo({ uploadOutput: "nothing useful" });
    await expect(deploy(STAGING, noVersion.io)).rejects.toThrow("could not find the version id");
    expect(noVersion.calls.some((c) => c[1] === "deploy")).toBe(false);
    const unknownDb = fakeIo();
    unknownDb.io.readConfig = () =>
      realConfig.replace('"database_name": "tiny-oidc-staging"', '"database_name": "other"');
    await expect(deploy(STAGING, unknownDb.io)).rejects.toThrow('D1 database "other" not found');
    expect(() => profileOf({ TIO_ENV: "dev" })).toThrow("TIO_ENV must be empty");
  });

  it("[TIO-DEPLOY-007] TIO_DIRECT_DEPLOY deploys straight to 100% for a first deployment or a Durable Object migration, and says so", async () => {
    const { io, calls, logs, smokes } = fakeIo();
    await deploy({ ...PRODUCTION, TIO_DIRECT_DEPLOY: "true" }, io);
    expect(calls.map((c) => c.slice(0, 2))).toEqual([
      ["d1", "list"],
      ["d1", "migrations"],
      ["deploy", "--config"],
    ]);
    expect(calls[2]).toContain("VERSION:0123456");
    expect(smokes).toEqual([]);
    expect(logs.some((l) => l.startsWith("TIO_DIRECT_DEPLOY: deploying with no smoke test"))).toBe(
      true,
    );
  });

  it("[TIO-DEPLOY-007] staging and production refuse unusable deploy variables before any wrangler command (a build variable holding its own name, a non-https issuer, a foreign RP id)", async () => {
    const cases: [Partial<typeof STAGING>, string][] = [
      [{ TIO_ISSUER: "TIO_ISSUER" }, "TIO_ISSUER must be an https URL"],
      [{ TIO_ISSUER: "" }, "TIO_ISSUER must be an https URL"],
      [{ TIO_ISSUER: "http://auth.staging.example.com" }, "TIO_ISSUER must be an https URL"],
      [{ TIO_ISSUER: "https://auth.staging.example.com/?x=1" }, "TIO_ISSUER must be an https URL"],
      [{ TIO_ISSUER: "https://auth.staging.example.com/#f" }, "TIO_ISSUER must be an https URL"],
      [{ TIO_ISSUER: "https://u:p@auth.staging.example.com" }, "TIO_ISSUER must be an https URL"],
      [{ TIO_RP_ID: "TIO_RP_ID" }, "TIO_RP_ID must equal the TIO_ISSUER host"],
      [{ TIO_RP_ID: "example.org" }, "TIO_RP_ID must equal the TIO_ISSUER host"],
      [{ TIO_RP_ID: "" }, "TIO_RP_ID must equal the TIO_ISSUER host"],
      [{ TIO_RP_NAME: "" }, "TIO_RP_NAME must be set"],
    ];
    for (const [override, message] of cases) {
      const { io, calls } = fakeIo();
      await expect(deploy({ ...STAGING, ...override }, io)).rejects.toThrow(message);
      await expect(deploy({ ...PRODUCTION, ...override }, io)).rejects.toThrow(message);
      expect(calls).toEqual([]);
    }
    // The host itself and a path prefix are fine; the button profile deploys the committed configuration.
    expect(() =>
      assertDeployVars({ ...STAGING, TIO_RP_ID: "auth.staging.example.com" }, "staging"),
    ).not.toThrow();
    expect(() =>
      assertDeployVars(
        { ...STAGING, TIO_ISSUER: "https://auth.staging.example.com/op" },
        "staging",
      ),
    ).not.toThrow();
    expect(() => assertDeployVars({ TIO_ISSUER: "TIO_ISSUER" }, "button")).not.toThrow();
  });

  it("helpers: vars, database lookup, config edit, Worker names, the live version and the fake-upstream refusal (TIO-TEST-031)", () => {
    expect(varArgs({})).toEqual([]);
    expect(varArgs({ TIO_RP_NAME: "X", WORKERS_CI_COMMIT_SHA: "abcdef0123" })).toEqual([
      "--var",
      "RP_NAME:X",
      "--var",
      "VERSION:abcdef0",
    ]);
    expect(resolveDatabaseId(D1_LIST, "tiny-oidc-production")).toBe(
      "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    );
    expect(databaseName(realConfig, "production")).toBe("tiny-oidc-production");
    expect(() => databaseName('{ "env": {} }', "staging")).toThrow("no d1 database_name");
    const edited = withDatabaseId(realConfig, "production", "x");
    expect(
      (parse(edited) as { env: { production: { d1_databases: { database_id: string }[] } } }).env
        .production.d1_databases[0]?.database_id,
    ).toBe("x");
    expect(workerName(realConfig, "staging")).toBe("tiny-oidc-staging");
    expect(workerName(realConfig, "production")).toBe("tiny-oidc");
    expect(() => workerName('{ "env": {} }', "production")).toThrow("env.production has no name");
    expect(liveVersion(STATUS)).toBe(LIVE);
    // An interrupted rollout leaves the new version at 0% beside the live one: still restorable.
    expect(
      liveVersion(
        JSON.stringify({
          versions: [
            { version_id: CANDIDATE, percentage: 0 },
            { version_id: LIVE, percentage: 100 },
          ],
        }),
      ),
    ).toBe(LIVE);
    expect(liveVersion("{}")).toBeNull();
    expect(() => assertDeployable('{ "name": "tiny-oidc-fake-upstream" }', "production")).toThrow(
      "only be deployed to staging",
    );
    expect(() =>
      assertDeployable('{ "name": "tiny-oidc-fake-upstream" }', "staging"),
    ).not.toThrow();
    expect(() => assertDeployable("{}", "button")).not.toThrow();
  });

  it("[TIO-TEST-031] the fake upstream deploys to staging only, with its issuer, client and redirect URIs from the environment and its secret kept out of the log", async () => {
    const fakeConfig = readFileSync(FAKE_UPSTREAM_CONFIG, "utf8");
    const { io, calls, logs } = fakeIo();
    io.readConfig = () => fakeConfig;
    const values = {
      TIO_ENV: "staging",
      TIO_FAKE_ISSUER: "https://idp.staging.example",
      TIO_FAKE_CLIENT_ID: "tiny-oidc",
      TIO_FAKE_CLIENT_SECRET: "s3cret",
      TIO_FAKE_REDIRECT_URIS: "https://auth.staging.example/federation/callback",
    };
    const result = await deployFakeUpstream(values, io);
    expect(result.profile).toBe("staging");
    expect(calls).toEqual([
      [
        "deploy",
        "--config",
        FAKE_UPSTREAM_CONFIG,
        "--var",
        "FAKE_ISSUER:https://idp.staging.example",
        "--var",
        "FAKE_CLIENT_ID:tiny-oidc",
        "--var",
        "FAKE_CLIENT_SECRET:s3cret",
        "--var",
        "FAKE_REDIRECT_URIS:https://auth.staging.example/federation/callback",
      ],
    ]);
    expect(logs.join(" ")).not.toContain("s3cret");
    for (const profile of ["", "production"]) {
      await expect(deployFakeUpstream({ ...values, TIO_ENV: profile }, io)).rejects.toThrow(
        "only be deployed to staging",
      );
    }
    await expect(
      deployFakeUpstream({ ...values, TIO_FAKE_CLIENT_SECRET: undefined }, io),
    ).rejects.toThrow("TIO_FAKE_CLIENT_SECRET must be set");
    expect(calls).toHaveLength(1);
    // The committed configuration names the fake and carries only placeholders.
    const parsed = parse(fakeConfig) as { name: string; vars: Record<string, string> };
    expect(parsed.name).toBe("tiny-oidc-fake-upstream");
    expect(parsed.vars["FAKE_ISSUER"]).toContain("example");
  });
});

describe("smoke test", () => {
  const respond = (routes: Record<string, (init?: RequestInit) => Response>): typeof fetch =>
    (async (input: string | URL | Request, init?: RequestInit) => {
      const path = new URL(String(input)).pathname;
      const route = routes[path];
      return route ? route(init) : new Response("nope", { status: 404 });
    }) as typeof fetch;
  const documents = {
    "/.well-known/openid-configuration": () => Response.json({ issuer: "https://op.example" }),
    "/.well-known/jwks.json": () => Response.json({ keys: [] }),
  };

  it("passes when every path answers 200 and health is ok, and reports each failure otherwise", async () => {
    expect(SMOKE_PATHS).toEqual([
      "/.well-known/openid-configuration",
      "/.well-known/jwks.json",
      "/api/v1/health",
    ]);
    const ok = respond({ ...documents, "/api/v1/health": () => Response.json({ status: "ok" }) });
    expect(await smoke("https://op.example/", { fetch: ok })).toEqual([]);
    const degraded = respond({
      ...documents,
      "/api/v1/health": () => Response.json({ status: "degraded" }),
    });
    expect(await smoke("https://op.example", { fetch: degraded })).toEqual([
      { path: "/api/v1/health", reason: 'health reports {"status":"degraded"}' },
    ]);
    expect(await smoke("https://op.example", { fetch: respond({}) })).toEqual([
      { path: "/.well-known/openid-configuration", reason: "status 404" },
      { path: "/.well-known/jwks.json", reason: "status 404" },
      { path: "/api/v1/health", reason: "status 404" },
    ]);
    const throwing = (async () => {
      throw new Error("connection refused");
    }) as typeof fetch;
    expect((await smoke("https://op.example", { fetch: throwing })).map((f) => f.reason)).toEqual([
      "connection refused",
      "connection refused",
      "connection refused",
    ]);
    const throwingValue = (async () => {
      throw "boom";
    }) as typeof fetch;
    expect((await smoke("https://op.example", { fetch: throwingValue }))[0]).toEqual({
      path: "/.well-known/openid-configuration",
      reason: "boom",
    });
  });

  it("[TIO-DEPLOY-007] sends the version-override header on every request and fails unless health reports the expected build", async () => {
    const seen: (string | null)[] = [];
    const slept: number[] = [];
    const sleep = async (ms: number) => {
      slept.push(ms);
    };
    const versioned = (version: string) =>
      respond({
        "/.well-known/openid-configuration": (init) => {
          seen.push(new Headers(init?.headers).get(VERSION_OVERRIDE_HEADER));
          return Response.json({});
        },
        "/.well-known/jwks.json": (init) => {
          seen.push(new Headers(init?.headers).get(VERSION_OVERRIDE_HEADER));
          return Response.json({ keys: [] });
        },
        "/api/v1/health": (init) => {
          seen.push(new Headers(init?.headers).get(VERSION_OVERRIDE_HEADER));
          return Response.json({ status: "ok", version });
        },
      });
    const headers = { [VERSION_OVERRIDE_HEADER]: `tiny-oidc="${CANDIDATE}"` };
    expect(
      await smoke("https://op.example", {
        fetch: versioned("0123456"),
        headers,
        version: "0123456",
        sleep,
      }),
    ).toEqual([]);
    // One health request finds the build at once, then the three checks.
    expect(seen).toEqual(Array(4).fill(`tiny-oidc="${CANDIDATE}"`));
    expect(slept).toEqual([]);
    // The override never reached the new version: the live build answered
    // throughout the settle window, and the failure says how long it waited.
    expect(
      await smoke("https://op.example", {
        fetch: versioned("fedcba9"),
        headers,
        version: "0123456",
        settleMs: 6_000,
        sleep,
      }),
    ).toEqual([
      {
        path: "/api/v1/health",
        reason: 'health reports version "fedcba9", expected "0123456" after waiting 6 s',
      },
    ]);
    expect(slept).toEqual([2_000, 2_000, 2_000]);
  });

  it("[TIO-DEPLOY-007] waits for a new deployment to reach the location that answers before checking it", async () => {
    // The first answers come from the live build (the deployment has not
    // arrived yet, so the override is ignored), then one that fails outright,
    // then the new build.
    const answers = [
      () => Response.json({ status: "ok", version: "fedcba9" }),
      () => Response.json({ status: "ok", version: "fedcba9" }),
      () => new Response("unavailable", { status: 503 }),
      () => Response.json({ status: "ok", version: "0123456" }),
    ];
    let polls = 0;
    const slept: number[] = [];
    const fetchImpl = respond({
      ...documents,
      "/api/v1/health": () => {
        const answer = answers[Math.min(polls, answers.length - 1)] as () => Response;
        polls += 1;
        return answer();
      },
    });
    expect(
      await smoke("https://op.example", {
        fetch: fetchImpl,
        version: "0123456",
        sleep: async (ms) => {
          slept.push(ms);
        },
      }),
    ).toEqual([]);
    expect(slept).toEqual([2_000, 2_000, 2_000]);
    expect(polls).toBe(5);
    // A health endpoint that cannot be reached at all is waited out too, then reported.
    const unreachable = (async () => {
      throw new Error("connection refused");
    }) as typeof fetch;
    expect(
      await smoke("https://op.example", {
        fetch: unreachable,
        version: "0123456",
        settleMs: 2_000,
        sleep: async () => {},
      }),
    ).toEqual(SMOKE_PATHS.map((path) => ({ path, reason: "connection refused" })));
  });
});
