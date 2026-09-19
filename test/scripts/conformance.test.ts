import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  CONFIG_SOURCES,
  expectedFailures,
  placeholders,
  planRuns,
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
    post: { id: "conformance-post", secret: "s2" },
    none: { id: "conformance-none", secret: null },
  },
  clients2: {
    basic: { id: "conformance-basic-2", secret: "t1" },
    post: { id: "conformance-post-2", secret: "t2" },
    none: { id: "conformance-none-2", secret: null },
  },
};

describe("conformance plans", () => {
  it("run the four plans of TIO-TEST-040, the basic one in the three client-authentication variants", () => {
    const runs = planRuns("cfg");
    expect(runs.map((r) => r.plan)).toEqual([
      "oidcc-config-certification-test-plan[server_metadata=discovery][client_registration=static_client]",
      "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client][client_auth_type=client_secret_basic][response_type=code][response_mode=default]",
      "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client][client_auth_type=client_secret_post][response_type=code][response_mode=default]",
      "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client][client_auth_type=none][response_type=code][response_mode=default]",
      "oidcc-rp-initiated-logout-certification-test-plan[server_metadata=discovery][client_registration=static_client][client_auth_type=client_secret_basic][response_type=code][response_mode=default]",
      "oidcc-backchannel-rp-initiated-logout-certification-test-plan[server_metadata=discovery][client_registration=static_client][client_auth_type=client_secret_basic][response_type=code][response_mode=default]",
    ]);
    // Every rendered configuration has a template, and every template is used.
    for (const r of runs) expect(CONFIG_SOURCES[r.config.replace("cfg/", "")]).toBeDefined();
    const config = JSON.parse(readFileSync("scripts/trace.config.json", "utf8")) as {
      conformance_plans: Record<string, string[]>;
    };
    const named = new Set(Object.values(config.conformance_plans).flat());
    for (const plan of named)
      expect(
        runs.some((r) => r.plan.startsWith(`${plan}[`)),
        plan,
      ).toBe(true);
    expect(runnerArgs(runs.slice(0, 1), "out", "expected.json")).toEqual([
      "--export-dir",
      "out",
      "--expected-failures-file",
      "expected.json",
      runs[0]?.plan,
      "cfg/config.json",
    ]);
  });

  it("render every template into valid JSON with the run's values, the browser block driving the login app by its control ids (TIO-TEST-041)", () => {
    const browser = readFileSync("conformance/plans/browser.json", "utf8");
    for (const [file, source] of Object.entries(CONFIG_SOURCES)) {
      const template = readFileSync(`conformance/plans/${source.template}`, "utf8");
      const rendered = JSON.parse(
        renderPlan(template, browser, placeholders(run, source.variant)),
      ) as {
        alias: string;
        server: { discoveryUrl: string };
        client?: { client_id: string; client_secret: string };
        browser?: { match: string; tasks: { match: string; commands?: unknown[][] }[] }[];
      };
      expect(rendered.alias, file).toBe("tiny-oidc");
      expect(rendered.server.discoveryUrl).toBe(
        "https://auth.example.com/.well-known/openid-configuration",
      );
      expect(JSON.stringify(rendered)).not.toMatch(/\{[A-Z_]+\}/);
      if (source.template !== "config.json") {
        expect(rendered.client?.client_id).toBe(run.clients[source.variant].id);
        expect(rendered.client?.client_secret).toBe(run.clients[source.variant].secret ?? "");
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

  it("accept only waivers with the one permitted reason and a discovery field, and turn them into the suite's expected-failures entries", () => {
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
    expect(expectedFailures([waiver])).toEqual([
      {
        "test-name": "oidcc-request-object-*",
        variant: "*",
        "configuration-filename": "*",
        condition: "EnsureRequestObjectSupported",
        "current-block": "*",
        "expected-result": "failure",
      },
    ]);
    expect(() => expectedFailures([{ ...waiver, reason: "flaky" }])).toThrow("reason must be");
    expect(() => expectedFailures([{ ...waiver, advertised_by: "" }])).toThrow("advertised_by");
    expect(() => expectedFailures([{ ...waiver, "expected-result": "skip" as "failure" }])).toThrow(
      "expected-result",
    );
    // The committed file is valid and, so far, empty.
    const committed = JSON.parse(readFileSync("conformance/waivers.json", "utf8")) as Waiver[];
    expect(expectedFailures(committed)).toEqual(
      committed.map(({ reason: _r, advertised_by: _a, ...rest }) => rest),
    );
  });

  it("is what the nightly job runs", () => {
    const nightly = readFileSync(".github/workflows/nightly.yml", "utf8");
    expect(nightly).toContain("node conformance/run.ts --suite-scripts conformance/suite/scripts");
    expect(nightly).toContain("docker compose -f conformance/docker-compose.yml up -d");
    expect(nightly).toContain("cloudflared tunnel --url https://localhost:8443");
    expect(nightly).toContain("conformance/results/export/");
  });
});
