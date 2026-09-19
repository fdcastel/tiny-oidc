import { describe, expect, it } from "vitest";
import { renderConfigMarkdown, renderDevVarsExample } from "../../scripts/lib/config-docs.ts";
import { generateSecrets, renderDevVars } from "../../scripts/lib/secrets.ts";
import { EnvVarsSchema, SecretsSchema, SettingsSchema } from "../../src/config/schema.ts";

describe("generated configuration docs (TIO-CFG-005, TIO-DEPLOY-008)", () => {
  it("documents every variable, secret and setting with its description, default and bounds", () => {
    const md = renderConfigMarkdown();
    for (const schema of [EnvVarsSchema, SecretsSchema, SettingsSchema]) {
      for (const [key, field] of Object.entries(schema.shape)) {
        expect(md, key).toContain(`| \`${key}\` |`);
        expect(md, key).toContain(field.description as string);
      }
    }
    expect(md).toContain("| `ISSUER` | string | required |");
    // Markdown tables escape the pipe of a union type as "\|".
    const or = "\\|";
    expect(md).toContain(`| \`BUNDLED_LOGIN_APP\` | \`"true"\` ${or} \`"false"\` | \`"false"\` |`);
    expect(md).toContain("| `VERSION` | string | unset |");
    expect(md).toContain("| `MASTER_KEYS` | yes |");
    expect(md).toContain("| `ADMIN_BOOTSTRAP_TOKEN` | no |");
    expect(md).toContain("| `passkeys.max_per_user` | integer | `20` | 1–50 |");
    expect(md).toContain(`| \`login_origins\` | array of string ${or} null | \`null\` |  |`);
    expect(md).toContain(`| \`bootstrapped_at\` | integer ${or} null | \`null\` |  |`);
    expect(md).toContain("| `RP_NAME` | string | required |");
  });

  it("lists every secret in .dev.vars.example with a one-line description", () => {
    const example = renderDevVarsExample();
    for (const [key, field] of Object.entries(SecretsSchema.shape)) {
      expect(example).toContain(`\n# ${field.description}`);
      expect(example).toContain(`\n${key}=\n`);
    }
    expect(example).toContain("(optional)\nADMIN_BOOTSTRAP_TOKEN=");
    expect(example).not.toContain("(optional)\nMASTER_KEYS=");
    expect(example).toContain("# ISSUER=http://localhost:8787");
  });

  it("generates 32-byte master keys and bootstrap tokens and renders .dev.vars", () => {
    const secrets = generateSecrets();
    const keys = JSON.parse(secrets.MASTER_KEYS) as Record<string, string>;
    expect(Object.keys(keys)).toEqual(["1"]);
    expect(Buffer.from(keys["1"] as string, "base64")).toHaveLength(32);
    expect(secrets.MASTER_KEY_ACTIVE).toBe("1");
    expect(secrets.ADMIN_BOOTSTRAP_TOKEN).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(generateSecrets().MASTER_KEYS).not.toBe(secrets.MASTER_KEYS);
    const devVars = renderDevVars(secrets, "http://localhost:8787", "localhost");
    expect(devVars).toContain(`MASTER_KEYS=${secrets.MASTER_KEYS}\n`);
    expect(devVars).toContain("ISSUER=http://localhost:8787\nRP_ID=localhost\n");
  });
});
