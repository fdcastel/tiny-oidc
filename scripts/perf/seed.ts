// Generates NDJSON for `POST /api/v1/admin/import/users` (spec §9.4 Import,
// TIO-ADMIN-021): `node scripts/perf/seed.ts --users 1000 --groups staff --identities 2 > users.ndjson`.
// Every user gets a unique verified email, `identities` upstream pairs and the
// given groups; the output is deterministic for a given `--seed`.

import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    users: { type: "string", default: "1000" },
    groups: { type: "string", default: "" },
    identities: { type: "string", default: "2" },
    seed: { type: "string", default: "1" },
    issuer: { type: "string", default: "https://idp.example.com" },
  },
});

const count = Number(values.users);
const identities = Number(values.identities);
const groups = values.groups === "" ? [] : values.groups.split(",");
const seed = values.seed;

/** One import line for user number `n`. */
export function seedLine(n: number): string {
  const tag = `${seed}-${n}`;
  return JSON.stringify({
    email: `user-${tag}@example.com`,
    email_verified: true,
    display_name: `User ${tag}`,
    groups,
    identities: Array.from({ length: identities }, (_, i) => ({
      issuer: i === 0 ? values.issuer : `${values.issuer}/${i}`,
      subject: `sub-${tag}`,
    })),
  });
}

const chunks: string[] = [];
for (let n = 0; n < count; n++) {
  chunks.push(seedLine(n));
  if (chunks.length === 1_000) {
    process.stdout.write(`${chunks.join("\n")}\n`);
    chunks.length = 0;
  }
}
if (chunks.length > 0) process.stdout.write(`${chunks.join("\n")}\n`);
