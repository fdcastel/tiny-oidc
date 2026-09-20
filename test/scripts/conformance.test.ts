import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  CONFIG_FILES,
  expectedProblems,
  placeholders,
  planRuns,
  RELYING_PARTIES,
  type RunValues,
  render,
  renderPlan,
  runnerArgs,
  suiteUris,
  WAIVER_REASON,
  type Waiver,
} from "../../conformance/lib.ts";

// The conformance harness (spec §13.9, TIO-TEST-040, TIO-TEST-041): the plans
// and variants the spec names, the browser automation that drives the
// reference login app, the waivers' one permitted reason, and the runner's
// command line. The suite itself runs in the nightly job against staging.

const run: RunValues = {
  issuer: "https://auth.example.com",
  loginUrl: "https://login.example.com/",
  upstreamAlias: "fake",
  suite: "https://suite.example.net",
  alias: "tiny-oidc",
  clients: {
    basic: { id: "conformance-basic", secret: "s1" },
    basic2: { id: "conformance-basic2", secret: "s2" },
    post: { id: "conformance-post", secret: "s3" },
  },
};

describe("conformance plans", () => {
  it("run the four plans of TIO-TEST-040 with only the variants each plan leaves selectable, as the suite's own CI does", () => {
    const runs = planRuns("cfg");
    expect(runs.map((r) => r.plan)).toEqual([
      "oidcc-config-certification-test-plan",
      "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]",
      "oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]",
      "oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]",
    ]);
    // Every run has a rendered configuration of its own, and every configuration a template.
    expect(runs.map((r) => r.config)).toEqual(CONFIG_FILES.map((f) => `cfg/${f}`));
    for (const file of CONFIG_FILES)
      expect(existsSync(`conformance/plans/${file}`), file).toBe(true);
    // The basic plan authenticates its client both ways; the second client mirrors the first.
    expect(RELYING_PARTIES).toEqual({
      basic: "client_secret_basic",
      basic2: "client_secret_basic",
      post: "client_secret_post",
    });
    const config = JSON.parse(readFileSync("scripts/trace.config.json", "utf8")) as {
      conformance_plans: Record<string, string[]>;
    };
    const named = new Set(Object.values(config.conformance_plans).flat());
    for (const plan of named)
      expect(
        runs.some((r) => r.plan === plan || r.plan.startsWith(`${plan}[`)),
        plan,
      ).toBe(true);
    expect(runnerArgs(runs.slice(0, 1), "out", "expected.json", "skips.json")).toEqual([
      "--export-dir",
      "out",
      "--expected-failures-file",
      "expected.json",
      "--expected-skips-file",
      "skips.json",
      runs[0]?.plan,
      "cfg/config.json",
    ]);
  });

  it("render every template into valid JSON with the run's values, the browser block driving the login app by its control ids (TIO-TEST-041)", () => {
    const browser = readFileSync("conformance/plans/browser.json", "utf8");
    for (const file of CONFIG_FILES) {
      const template = readFileSync(`conformance/plans/${file}`, "utf8");
      const rendered = JSON.parse(renderPlan(template, browser, placeholders(run))) as {
        alias: string;
        server: { discoveryUrl: string };
        client?: { client_id: string; client_secret: string };
        client2?: { client_id: string; client_secret: string };
        client_secret_post?: { client_id: string; client_secret: string };
        browser?: { match: string; tasks: { match: string; commands?: unknown[][] }[] }[];
      };
      expect(rendered.alias, file).toBe("tiny-oidc");
      expect(rendered.server.discoveryUrl).toBe(
        "https://auth.example.com/.well-known/openid-configuration",
      );
      expect(JSON.stringify(rendered)).not.toMatch(/\{[A-Z_]+\}/);
      if (file !== "config.json") {
        expect(rendered.client).toEqual(
          expect.objectContaining({ client_id: "conformance-basic", client_secret: "s1" }),
        );
        expect(rendered.client2).toEqual({ client_id: "conformance-basic2", client_secret: "s2" });
        // The basic plan's client_secret_post module reads its own client (static_client fields).
        expect(rendered.client_secret_post, file).toEqual(
          file === "basic.json"
            ? expect.objectContaining({ client_id: "conformance-post", client_secret: "s3" })
            : undefined,
        );
        const [authorize, logout] = rendered.browser as NonNullable<typeof rendered.browser>;
        expect(authorize?.match).toBe("https://auth.example.com/authorize*");
        expect(authorize?.tasks[0]?.match).toBe("https://login.example.com/*");
        expect(authorize?.tasks[0]?.commands).toContainEqual([
          "click",
          "id",
          "upstream-fake",
          "optional",
        ]);
        expect(authorize?.tasks[1]?.match).toBe(
          "https://suite.example.net/test/a/tiny-oidc/callback*",
        );
        expect(logout?.match).toBe("https://auth.example.com/logout*");
        expect(logout?.tasks[0]?.commands).toContainEqual([
          "click",
          "id",
          "logout-confirm",
          "optional",
        ]);
      }
    }
    // The login app really has those controls.
    const app = readFileSync("examples/login-app/app.js", "utf8");
    expect(app).toContain("id: `upstream-${upstream.alias}`");
    for (const id of ["logout-confirm", "consent-grant", "signin-passkey", "abort"]) {
      expect(app).toContain(`id: "${id}"`);
    }
    expect(() => render("{NOPE}", {})).toThrow("no value for {NOPE}");
  });

  it("register the suite's callback, post-logout and back-channel URIs for the alias", () => {
    expect(suiteUris("https://suite.example.net", "tiny-oidc")).toEqual({
      redirect_uris: [
        "https://suite.example.net/test/a/tiny-oidc/callback",
        "https://suite.example.net/test/a/tiny-oidc/callback?dummy1=lorem&dummy2=ipsum",
      ],
      post_logout_redirect_uris: [
        "https://suite.example.net/test/a/tiny-oidc/post_logout_redirect",
      ],
      backchannel_logout_uri: "https://suite.example.net/test/a/tiny-oidc/backchannel_logout",
    });
  });

  it("accept only waivers with the one permitted reason and a discovery field, and turn them into the suite's expected-failures and expected-skips entries", () => {
    const waiver: Waiver = {
      "test-name": "oidcc-request-object-*",
      variant: "*",
      "configuration-filename": "*",
      condition: "EnsureRequestObjectSupported",
      "current-block": "*",
      "expected-result": "failure",
      reason: WAIVER_REASON,
      advertised_by: "request_parameter_supported: false",
    };
    const skip: Waiver = {
      "test-name": "oidcc-scope-address",
      variant: "*",
      "configuration-filename": "basic.json",
      "expected-result": "skip",
      reason: WAIVER_REASON,
      advertised_by: "scopes_supported (no address)",
    };
    expect(expectedProblems([waiver, skip])).toEqual({
      failures: [
        {
          "test-name": "oidcc-request-object-*",
          variant: "*",
          "configuration-filename": "*",
          condition: "EnsureRequestObjectSupported",
          "current-block": "*",
          "expected-result": "failure",
        },
      ],
      skips: [
        {
          "test-name": "oidcc-scope-address",
          variant: "*",
          "configuration-filename": "basic.json",
        },
      ],
    });
    expect(() => expectedProblems([{ ...waiver, reason: "flaky" }])).toThrow("reason must be");
    expect(() => expectedProblems([{ ...waiver, advertised_by: "" }])).toThrow("advertised_by");
    expect(() => expectedProblems([{ ...waiver, "expected-result": "info" as "failure" }])).toThrow(
      "expected-result",
    );
    const { condition: _c, ...noCondition } = waiver;
    expect(() => expectedProblems([noCondition])).toThrow("names its condition and block");
    expect(() => expectedProblems([{ ...skip, condition: "X" }])).toThrow(
      "a skip names no condition or block",
    );
    // The committed file is valid.
    const committed = JSON.parse(readFileSync("conformance/waivers.json", "utf8")) as Waiver[];
    const problems = expectedProblems(committed);
    expect(problems.failures.length + problems.skips.length).toBe(committed.length);
  });

  it("is what the nightly job runs", () => {
    const nightly = readFileSync(".github/workflows/nightly.yml", "utf8");
    expect(nightly).toContain("node conformance/run.ts --suite-scripts conformance/suite/scripts");
    expect(nightly).toContain("docker compose -f conformance/docker-compose.yml up -d");
    expect(nightly).toContain("cloudflared tunnel --url https://localhost:8443");
    expect(nightly).toContain("conformance/results/export/");
  });
});
