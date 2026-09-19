import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { USER_SCHEMA_STEPS } from "../../src/do/schema.ts";

// What the OP stores about a person (spec §11.5, TIO-PRIV-001): the columns of
// every user-related table, in the Durable Object and in D1, are enumerated
// here so that nothing beyond the allowed attributes can appear unnoticed.

/** Columns of every `CREATE TABLE` in `sql`, keyed by table name. */
function columnsOf(sql: string): Record<string, string[]> {
  const tables: Record<string, string[]> = {};
  const pattern = /CREATE TABLE(?: IF NOT EXISTS)? (\w+) \(([\s\S]*?)\n\);/g;
  for (const match of sql.matchAll(pattern)) {
    const [, name, body] = match as unknown as [string, string, string];
    tables[name] = body
      .split("\n")
      .map((line) => line.replace(/--.*$/, "").trim())
      .filter((line) => line.length > 0 && !/^(PRIMARY KEY|UNIQUE|CHECK|FOREIGN KEY)/.test(line))
      .map((line) => line.split(/\s+/)[0] as string);
  }
  return tables;
}

const ALLOWED = {
  // UserDO (§4.2)
  user: [
    "id",
    "email",
    "email_norm",
    "email_verified",
    "display_name",
    "groups",
    "disabled_at",
    "created_at",
    "updated_at",
  ],
  passkeys: [
    "id",
    "credential_id",
    "public_key",
    "alg",
    "counter",
    "transports",
    "aaguid",
    "backup_eligible",
    "backed_up",
    "name",
    "created_via",
    "created_at",
    "last_used_at",
  ],
  identities: [
    "id",
    "issuer",
    "subject",
    "email",
    "email_verified",
    "name",
    "created_at",
    "last_login_at",
  ],
  sessions: [
    "sid",
    "secret_hash",
    "created_at",
    "last_seen_at",
    "idle_expires_at",
    "absolute_expires_at",
    "auth_time",
    "amr",
    "acr",
    "upstream",
    "ip_hash",
    "ua_family",
    "country",
    "revoked_at",
    "revoke_reason",
  ],
  grants: ["client_id", "client_created_at", "scopes", "granted_at", "updated_at"],
  // D1 mirror (§4.1)
  users: [
    "id",
    "email",
    "email_norm",
    "email_verified",
    "display_name",
    "status",
    "created_at",
    "updated_at",
  ],
  identity_index: ["issuer", "subject", "user_id", "created_at"],
  passkey_index: ["credential_id", "user_id", "created_at"],
  group_members: ["group_id", "user_id", "added_at"],
};

const FORBIDDEN = /picture|avatar|photo|address|phone|birth|gender|bio|notes|attributes|metadata/i;

describe("stored personal data", () => {
  it("[TIO-PRIV-001] the user, passkey, identity, session and grant tables hold only the attributes of §11.5, nowhere a picture, address, phone number or free-form attribute", () => {
    const doTables = columnsOf(USER_SCHEMA_STEPS.join("\n"));
    const d1Tables = columnsOf(readFileSync("migrations/0001_init.sql", "utf8"));
    for (const [table, allowed] of Object.entries(ALLOWED)) {
      const columns = doTables[table] ?? d1Tables[table];
      expect(columns, table).toBeDefined();
      expect(columns, table).toEqual(allowed);
    }
    const everything = [...Object.values(doTables), ...Object.values(d1Tables)].flat();
    expect(everything.filter((column) => FORBIDDEN.test(column))).toEqual([]);
    // Pseudonymized network metadata only: a hash of the address, a browser family, a country.
    expect(ALLOWED.sessions).not.toContain("ip");
    expect(ALLOWED.sessions).not.toContain("user_agent");
  });
});
