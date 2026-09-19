import { readFileSync } from "node:fs";
import { parse } from "jsonc-parser";
import { describe, expect, it } from "vitest";
import {
  assertDeployable,
  type DeployIO,
  databaseName,
  deploy,
  profileOf,
  resolveDatabaseId,
  varArgs,
  withDatabaseId,
} from "../../scripts/lib/deploy.ts";
import { SMOKE_PATHS, smoke } from "../../scripts/lib/smoke.ts";

const realConfig = readFileSync("wrangler.jsonc", "utf8");
const D1_LIST = JSON.stringify([
  { uuid: "11111111-2222-4333-8444-555555555555", name: "tiny-oidc-staging" },
  { uuid: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", name: "tiny-oidc-production" },
]);

/** A fake wrangler that records calls and answers with canned output. */
function fakeIo(options: { smokeFails?: boolean; uploadOutput?: string } = {}) {
  const calls: string[][] = [];
  const written: string[] = [];
  const logs: string[] = [];
  const io: DeployIO = {
    wrangler: async (args) => {
      calls.push(args);
      if (args[0] === "d1" && args[1] === "list") return D1_LIST;
      if (args[0] === "versions" && args[1] === "upload") {
        return (
          options.uploadOutput ??
          "Uploaded tiny-oidc (1.23 sec)\nWorker Version ID: 12345678-1234-4123-8123-123456789abc\nVersion Preview URL: https://12345678-tiny-oidc.example.workers.dev\n"
        );
      }
      return "";
    },
    readConfig: () => realConfig,
    writeGeneratedConfig: (content) => {
      written.push(content);
      return "wrangler.generated.jsonc";
    },
    smoke: async (baseUrl) => {
      logs.push(`smoke ${baseUrl}`);
      if (options.smokeFails) throw new Error("smoke test failed");
    },
    log: (m) => logs.push(m),
  };
  return { io, calls, written, logs };
}

describe("deploy script (TIO-DEPLOY-007)", () => {
  it("[TIO-DEPLOY-007] the button profile applies migrations and deploys with the committed configuration and no --var", async () => {
    const { io, calls, written } = fakeIo();
    const result = await deploy({}, io);
    expect(result.profile).toBe("button");
    expect(calls).toEqual([["d1", "migrations", "apply", "DB", "--remote"], ["deploy"]]);
    expect(written).toEqual([]);
  });

  it("[TIO-DEPLOY-007] staging resolves the D1 id by name into a generated config and passes the deploy-environment vars", async () => {
    const { io, calls, written } = fakeIo();
    const result = await deploy(
      {
        TIO_ENV: "staging",
        TIO_ISSUER: "https://auth.staging.example.com",
        TIO_RP_ID: "staging.example.com",
        TIO_RP_NAME: "Example Staging",
        WORKERS_CI_COMMIT_SHA: "0123456789abcdef0123456789abcdef01234567",
      },
      io,
    );
    expect(result.profile).toBe("staging");
    expect(calls).toEqual([
      ["d1", "list", "--json"],
      [
        "d1",
        "migrations",
        "apply",
        "DB",
        "--remote",
        "--config",
        "wrangler.generated.jsonc",
        "--env",
        "staging",
      ],
      [
        "deploy",
        "--config",
        "wrangler.generated.jsonc",
        "--env",
        "staging",
        "--var",
        "ISSUER:https://auth.staging.example.com",
        "--var",
        "RP_ID:staging.example.com",
        "--var",
        "RP_NAME:Example Staging",
        "--var",
        "VERSION:0123456",
      ],
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

  it("[TIO-DEPLOY-007] production uploads a version, smoke-tests its preview URL and only then deploys it to 100%", async () => {
    const { io, calls, logs } = fakeIo();
    const result = await deploy(
      { TIO_ENV: "production", TIO_ISSUER: "https://auth.example.com" },
      io,
    );
    expect(result.profile).toBe("production");
    expect(calls.map((c) => c.slice(0, 2))).toEqual([
      ["d1", "list"],
      ["d1", "migrations"],
      ["versions", "upload"],
      ["versions", "deploy"],
    ]);
    expect(calls[2]).toContain("--var");
    expect(calls[3]).toEqual([
      "versions",
      "deploy",
      "12345678-1234-4123-8123-123456789abc@100%",
      "--yes",
      "--config",
      "wrangler.generated.jsonc",
      "--env",
      "production",
    ]);
    const smokeIndex = logs.findIndex((l) => l.startsWith("smoke "));
    const deployIndex = logs.findIndex((l) => l.startsWith("wrangler versions deploy"));
    expect(logs[smokeIndex]).toBe("smoke https://12345678-tiny-oidc.example.workers.dev");
    expect(smokeIndex).toBeLessThan(deployIndex);
  });

  it("[TIO-DEPLOY-007] a failing step aborts before traffic changes", async () => {
    const failing = fakeIo({ smokeFails: true });
    await expect(deploy({ TIO_ENV: "production" }, failing.io)).rejects.toThrow(
      "smoke test failed",
    );
    expect(failing.calls.map((c) => c[1])).toEqual(["list", "migrations", "upload"]);
    const noPreview = fakeIo({ uploadOutput: "nothing useful" });
    await expect(deploy({ TIO_ENV: "production" }, noPreview.io)).rejects.toThrow("preview URL");
    const unknownDb = fakeIo();
    unknownDb.io.readConfig = () =>
      realConfig.replace('"database_name": "tiny-oidc-staging"', '"database_name": "other"');
    await expect(deploy({ TIO_ENV: "staging" }, unknownDb.io)).rejects.toThrow(
      'D1 database "other" not found',
    );
    expect(() => profileOf({ TIO_ENV: "dev" })).toThrow("TIO_ENV must be empty");
  });

  it("helpers: vars, database lookup, config edit and the fake-upstream refusal (TIO-TEST-031)", () => {
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
    expect(() => assertDeployable('{ "name": "tiny-oidc-fake-upstream" }', "production")).toThrow(
      "only be deployed to staging",
    );
    expect(() =>
      assertDeployable('{ "name": "tiny-oidc-fake-upstream" }', "staging"),
    ).not.toThrow();
    expect(() => assertDeployable("{}", "button")).not.toThrow();
  });
});

describe("smoke test", () => {
  const respond = (routes: Record<string, () => Response>): typeof fetch =>
    (async (input: string | URL | Request) => {
      const path = new URL(String(input)).pathname;
      const route = routes[path];
      return route ? route() : new Response("nope", { status: 404 });
    }) as typeof fetch;

  it("passes when every path answers 200 and health is ok, and reports each failure otherwise", async () => {
    expect(SMOKE_PATHS).toEqual([
      "/.well-known/openid-configuration",
      "/.well-known/jwks.json",
      "/api/v1/health",
    ]);
    const documents = {
      "/.well-known/openid-configuration": () => Response.json({ issuer: "https://op.example" }),
      "/.well-known/jwks.json": () => Response.json({ keys: [] }),
    };
    const ok = respond({ ...documents, "/api/v1/health": () => Response.json({ status: "ok" }) });
    expect(await smoke("https://op.example/", ok)).toEqual([]);
    const degraded = respond({
      ...documents,
      "/api/v1/health": () => Response.json({ status: "degraded" }),
    });
    expect(await smoke("https://op.example", degraded)).toEqual([
      { path: "/api/v1/health", reason: 'health reports {"status":"degraded"}' },
    ]);
    expect(await smoke("https://op.example", respond({}))).toEqual([
      { path: "/.well-known/openid-configuration", reason: "status 404" },
      { path: "/.well-known/jwks.json", reason: "status 404" },
      { path: "/api/v1/health", reason: "status 404" },
    ]);
    const throwing = (async () => {
      throw new Error("connection refused");
    }) as typeof fetch;
    expect((await smoke("https://op.example", throwing)).map((f) => f.reason)).toEqual([
      "connection refused",
      "connection refused",
      "connection refused",
    ]);
    const throwingValue = (async () => {
      throw "boom";
    }) as typeof fetch;
    expect((await smoke("https://op.example", throwingValue))[0]).toEqual({
      path: "/.well-known/openid-configuration",
      reason: "boom",
    });
  });
});
