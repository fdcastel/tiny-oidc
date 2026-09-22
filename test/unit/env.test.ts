import { describe, expect, it } from "vitest";
import {
  buildConfig,
  type Config,
  type Env,
  EnvVarsSchema,
  jurisdictional,
  resolveSettings,
  SecretsSchema,
  SettingsSchema,
} from "../../src/env.ts";
import { TEST_MASTER_KEYS } from "../support/keys.ts";

const baseEnv = (): Env =>
  ({
    ISSUER: "https://auth.example.com",
    RP_ID: "example.com",
    RP_NAME: "Example",
    BUNDLED_LOGIN_APP: "false",
    LOG_LEVEL: "info",
    DO_JURISDICTION: "",
    MASTER_KEYS: TEST_MASTER_KEYS,
    MASTER_KEY_ACTIVE: "1",
  }) as unknown as Env;

const configOf = (env: Env): Config => {
  const result = buildConfig(env);
  if (!result.ok) throw new Error(result.error);
  return result.config;
};

describe("buildConfig", () => {
  it("[TIO-CFG-002] accepts an https ISSUER without query or fragment, optionally with a path, and http only on loopback hosts", () => {
    const ok = configOf(baseEnv());
    expect(ok.issuerUrl).toBe("https://auth.example.com");
    expect(ok.issuer.href).toBe("https://auth.example.com/");
    expect(ok.rpId).toBe("example.com");
    expect(ok.version).toBe("dev");
    expect(ok.bundledLoginApp).toBe(false);
    expect(ok.keys.active).toBe(1);
    expect(configOf({ ...baseEnv(), ISSUER: "https://auth.example.com/oidc/" }).issuerUrl).toBe(
      "https://auth.example.com/oidc",
    );
    expect(
      configOf({ ...baseEnv(), ISSUER: "http://localhost:8787", RP_ID: "localhost" }).issuerUrl,
    ).toBe("http://localhost:8787");
    expect(
      configOf({ ...baseEnv(), ISSUER: "http://127.0.0.1:8787", RP_ID: "127.0.0.1" }).issuerUrl,
    ).toBe("http://127.0.0.1:8787");
    for (const issuer of [
      "http://auth.example.com",
      "https://auth.example.com/?x=1",
      "https://auth.example.com/#frag",
      "https://auth.example.com?",
      "https://auth.example.com#",
      "https://user:pw@auth.example.com",
      "auth.example.com",
      "ftp://auth.example.com",
      "",
    ]) {
      expect(buildConfig({ ...baseEnv(), ISSUER: issuer }), issuer).toEqual({
        ok: false,
        error: "ISSUER must be an https URL with no query, fragment or credentials (TIO-CFG-002)",
      });
    }
  });

  it("requires RP_ID to equal the ISSUER host or be a parent domain of it", () => {
    expect(configOf({ ...baseEnv(), RP_ID: "auth.example.com" }).rpId).toBe("auth.example.com");
    for (const rpId of ["example.org", "xample.com", "", "login.example.com"]) {
      expect(buildConfig({ ...baseEnv(), RP_ID: rpId }).ok, rpId).toBe(false);
    }
  });

  it("[TIO-CRYPTO-010] fails when the master keys or other secrets are missing or malformed", () => {
    const { MASTER_KEYS: _omitted, ...withoutKeys } = baseEnv();
    expect(buildConfig(withoutKeys as Env)).toMatchObject({ ok: false });
    expect(buildConfig({ ...baseEnv(), MASTER_KEY_ACTIVE: "9" })).toEqual({
      ok: false,
      error: 'MASTER_KEY_ACTIVE "9" is not a version in MASTER_KEYS',
    });
    expect(buildConfig({ ...baseEnv(), ADMIN_BOOTSTRAP_TOKEN: "short" })).toMatchObject({
      ok: false,
    });
    expect(
      configOf({ ...baseEnv(), ADMIN_BOOTSTRAP_TOKEN: "x".repeat(32) }).adminBootstrapToken,
    ).toBe("x".repeat(32));
  });

  it("rejects invalid environment variables and applies var defaults", () => {
    expect(buildConfig({ ...baseEnv(), LOG_LEVEL: "loud" })).toMatchObject({ ok: false });
    expect(buildConfig({ ...baseEnv(), RP_NAME: "" })).toMatchObject({ ok: false });
    const config = configOf({
      ...baseEnv(),
      BUNDLED_LOGIN_APP: "true",
      VERSION: "abc1234",
      LOG_LEVEL: "debug",
    });
    expect(config.bundledLoginApp).toBe(true);
    expect(config.version).toBe("abc1234");
    expect(config.logLevel).toBe("debug");
  });

  it("declares every var, secret and setting exactly once with a description", () => {
    for (const schema of [EnvVarsSchema, SecretsSchema, SettingsSchema]) {
      for (const [key, field] of Object.entries(schema.shape)) {
        expect(field.description, key).toBeTruthy();
      }
    }
    expect(Object.keys(EnvVarsSchema.shape)).toEqual([
      "ISSUER",
      "RP_ID",
      "RP_NAME",
      "BUNDLED_LOGIN_APP",
      "LOG_LEVEL",
      "DO_JURISDICTION",
      "VERSION",
    ]);
    expect(Object.keys(SecretsSchema.shape)).toEqual([
      "MASTER_KEYS",
      "MASTER_KEY_ACTIVE",
      "ADMIN_BOOTSTRAP_TOKEN",
    ]);
  });
});

describe("Durable Object jurisdiction", () => {
  const withJurisdiction = (value: string) =>
    configOf({ ...baseEnv(), DO_JURISDICTION: value } as Env);

  it("[TIO-CFG-006] the configuration carries the jurisdiction; only the values Tiny OIDC supports are accepted", () => {
    expect(configOf(baseEnv()).doJurisdiction).toBe("");
    expect(withJurisdiction("eu").doJurisdiction).toBe("eu");
    expect(withJurisdiction("fedramp").doJurisdiction).toBe("fedramp");
    for (const bad of ["EU", "us", "fedramp-high", "moon"]) {
      expect(buildConfig({ ...baseEnv(), DO_JURISDICTION: bad } as Env).ok).toBe(false);
    }
  });

  it("[TIO-CFG-006] objects are addressed in the jurisdiction's namespace, or in the namespace itself when there is none", () => {
    const calls: string[] = [];
    const restricted = { restricted: true } as unknown as DurableObjectNamespace;
    const namespace = {
      jurisdiction(value: string) {
        calls.push(value);
        return restricted;
      },
    } as unknown as DurableObjectNamespace;
    expect(jurisdictional(namespace, "")).toBe(namespace);
    expect(calls).toEqual([]);
    expect(jurisdictional(namespace, "eu")).toBe(restricted);
    expect(jurisdictional(namespace, "fedramp")).toBe(restricted);
    expect(calls).toEqual(["eu", "fedramp"]);
    // Unreachable past configuration validation; refused rather than guessed.
    expect(() => jurisdictional(namespace, "us")).toThrow('unsupported DO_JURISDICTION "us"');
  });

  it("[TIO-CFG-006] the settings fail validation while the configured jurisdiction differs from the one the accounts were created under", () => {
    const check = (stored: Record<string, unknown>, jurisdiction: string) => {
      const result = resolveSettings(stored, withJurisdiction(jurisdiction));
      return result.ok ? "ok" : result.violations.join("; ");
    };
    // Before bootstrap nothing is recorded and no object exists: any jurisdiction may start.
    expect(check({}, "")).toBe("ok");
    expect(check({}, "eu")).toBe("ok");
    // Recorded at bootstrap: only that one.
    expect(check({ bootstrapped_at: 1, do_jurisdiction: "eu" }, "eu")).toBe("ok");
    expect(check({ bootstrapped_at: 1, do_jurisdiction: "" }, "")).toBe("ok");
    expect(check({ bootstrapped_at: 1, do_jurisdiction: "eu" }, "")).toBe(
      'do_jurisdiction: the accounts were created under jurisdiction "eu" but DO_JURISDICTION asks for no jurisdiction; every existing account would be unreachable, so the setting must match',
    );
    expect(check({ bootstrapped_at: 1, do_jurisdiction: "" }, "fedramp")).toContain(
      'created under no jurisdiction but DO_JURISDICTION asks for jurisdiction "fedramp"',
    );
    // Bootstrapped before the record existed: its objects have no jurisdiction,
    // because the variable was not applied until the record was.
    expect(check({ bootstrapped_at: 1 }, "")).toBe("ok");
    expect(check({ bootstrapped_at: 1 }, "eu")).toContain("created under no jurisdiction");
  });
});

describe("resolveSettings", () => {
  const config = configOf(baseEnv());
  const bundled = configOf({ ...baseEnv(), BUNDLED_LOGIN_APP: "true" });

  it("applies the documented defaults and reports every key as default when nothing is stored", () => {
    const result = resolveSettings({}, config);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const s = result.settings;
    expect(s.login_url).toBeNull();
    expect(s.login_origins).toBeNull();
    expect(s.webauthn_origins).toEqual([]);
    expect(s.logout_landing_url).toBeNull();
    expect(s["registration.mode"]).toBe("invite");
    expect(s["federation.auto_create"]).toBe(false);
    expect(s["federation.link_by_verified_email"]).toBe("reauth");
    expect(s["passkeys.max_per_user"]).toBe(20);
    expect(s["passkeys.attestation_policy"]).toBe("ignore");
    expect(s.interaction_ttl).toBe(600);
    expect(s["session.idle_ttl"]).toBe(86_400);
    expect(s["session.absolute_ttl"]).toBe(2_592_000);
    expect(s["tokens.access_ttl"]).toBe(600);
    expect(s["tokens.id_ttl"]).toBe(600);
    expect(s["tokens.refresh_idle_ttl"]).toBe(1_209_600);
    expect(s["tokens.refresh_absolute_ttl"]).toBe(2_592_000);
    expect(s["tokens.refresh_reuse_window"]).toBe(86_400);
    expect(s["keys.rotation_days"]).toBe(90);
    expect(s["keys.prepublish_seconds"]).toBe(86_400);
    expect(s["keys.retire_after_seconds"]).toBe(604_800);
    expect(s["audit.hot_retention_days"]).toBe(30);
    expect(s["me.allow_email_change"]).toBe(false);
    expect(s["me.passkey_add_max_auth_age"]).toBe(900);
    expect(s.bootstrapped_at).toBeNull();
    expect(s.do_jurisdiction).toBeNull();
    expect(new Set(Object.values(s.sources))).toEqual(new Set(["default"]));
  });

  it("[TIO-CFG-004] derives login_url, login_origins, webauthn_origins and the landing URL from the bundled login app", () => {
    const result = resolveSettings({}, bundled);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.settings.login_url).toBe("https://auth.example.com/login/");
    expect(result.settings.login_origins).toEqual(["https://auth.example.com"]);
    expect(result.settings.webauthn_origins).toEqual(["https://auth.example.com"]);
    expect(result.settings.logout_landing_url).toBe(
      "https://auth.example.com/login/?event=logged_out",
    );
    const subPath = resolveSettings(
      {},
      configOf({
        ...baseEnv(),
        ISSUER: "https://auth.example.com/oidc",
        BUNDLED_LOGIN_APP: "true",
      }),
    );
    expect(subPath.ok && subPath.settings.login_url).toBe("https://auth.example.com/oidc/login/");
  });

  it("prefers stored values, marks their source, and derives the rest from them", () => {
    const result = resolveSettings(
      {
        login_url: "https://login.example.com/?app=1",
        login_origins: ["https://login.example.com", "https://app.example.com"],
        "registration.mode": "open",
        "tokens.access_ttl": 900,
      },
      config,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.settings.login_url).toBe("https://login.example.com/?app=1");
    const explicitLanding = resolveSettings(
      { logout_landing_url: "https://www.example.org/bye" },
      config,
    );
    expect(explicitLanding.ok && explicitLanding.settings.logout_landing_url).toBe(
      "https://www.example.org/bye",
    );
    expect(result.settings.webauthn_origins).toEqual([
      "https://login.example.com",
      "https://app.example.com",
    ]);
    expect(result.settings.logout_landing_url).toBe(
      "https://login.example.com/?app=1&event=logged_out",
    );
    expect(result.settings["registration.mode"]).toBe("open");
    expect(result.settings["tokens.access_ttl"]).toBe(900);
    expect(result.settings.sources.login_url).toBe("setting");
    expect(result.settings.sources["tokens.access_ttl"]).toBe("setting");
    expect(result.settings.sources["tokens.id_ttl"]).toBe("default");
  });

  it("[TIO-CFG-003] rejects schema violations and every cross-field rule as a whole, listing each violation", () => {
    const schema = resolveSettings(
      { "registration.mode": "anyone", "tokens.access_ttl": 5 },
      config,
    );
    expect(schema.ok).toBe(false);
    if (schema.ok) return;
    expect(schema.violations).toHaveLength(2);
    expect(schema.violations[0]).toMatch(/^registration\.mode: /);
    expect(schema.violations[1]).toMatch(/^tokens\.access_ttl: /);

    const cross = resolveSettings(
      {
        login_url: "https://login.other.org/",
        login_origins: [],
        webauthn_origins: [
          "https://a.one.com",
          "https://b.two.com",
          "https://c.three.com",
          "https://d.four.com",
          "https://e.five.com",
          "https://f.six.com",
          "not-an-origin",
        ],
        logout_landing_url: "not a url",
        "keys.retire_after_seconds": 4_000,
        "tokens.refresh_idle_ttl": 2_592_000,
        "tokens.refresh_absolute_ttl": 86_400,
        "session.idle_ttl": 2_592_000,
        "session.absolute_ttl": 3_600,
      },
      config,
    );
    expect(cross.ok).toBe(false);
    if (cross.ok) return;
    expect(cross.violations).toEqual([
      "login_url: must be same-site with ISSUER",
      "login_origins: must not be empty",
      'webauthn_origins: "not-an-origin" is not an https origin',
      "webauthn_origins: at most 5 distinct registrable domains are allowed",
      "logout_landing_url: must be an absolute https URL",
      "keys.retire_after_seconds: must exceed the longest token lifetime plus 3600 seconds",
      "tokens.refresh_idle_ttl: must not exceed tokens.refresh_absolute_ttl",
      "session.idle_ttl: must not exceed session.absolute_ttl",
    ]);
  });

  it("[TIO-PK-001] validates origins: scheme, exact origin form and same-site login origins", () => {
    const bad = resolveSettings(
      {
        login_url: "http://login.example.com/",
        login_origins: [
          "https://login.example.com/path",
          "http://login.example.com",
          "https://login.other.org",
        ],
      },
      config,
    );
    expect(bad.ok).toBe(false);
    if (bad.ok) return;
    expect(bad.violations).toEqual([
      "login_url: must be an absolute https URL without a fragment",
      'login_origins: "https://login.example.com/path" is not an https origin',
      'login_origins: "http://login.example.com" is not an https origin',
      'login_origins: "https://login.other.org" is not same-site with ISSUER',
    ]);
    const fragment = resolveSettings({ login_url: "https://login.example.com/#x" }, config);
    expect(fragment.ok).toBe(false);
    const scheme = resolveSettings({ logout_landing_url: "javascript:alert(1)" }, config);
    expect(scheme.ok).toBe(false);
    if (!scheme.ok)
      expect(scheme.violations).toEqual(["logout_landing_url: must be an absolute https URL"]);
    const local = resolveSettings(
      { login_url: "http://localhost:3000/", login_origins: ["http://localhost:3000"] },
      configOf({ ...baseEnv(), ISSUER: "http://localhost:8787", RP_ID: "localhost" }),
    );
    expect(local.ok).toBe(true);
    const five = resolveSettings(
      {
        webauthn_origins: [
          "https://a.one.com",
          "https://b.one.com",
          "https://two.com",
          "https://three.com",
          "https://four.com",
          "https://five.com",
        ],
      },
      config,
    );
    expect(five.ok).toBe(true);
  });
});
