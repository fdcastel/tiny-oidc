// The synthetic population (spec §13.10, TIO-TEST-050): one import line per
// user number, deterministic for a seed, so the harvest can name any user's
// upstream subject without a lookup and a re-run produces the same people.

export interface Population {
  /** Distinguishes populations; part of every email and subject. */
  seed: string;
  /** Group names every user gets; each must exist before the import. */
  groups: string[];
  /** Upstream identities per user; the first is at `issuer`, the rest at `issuer/<i>`. */
  identities: number;
  /** The issuer of the first identity (the staging fake upstream in the load runs). */
  issuer: string;
}

export const DEFAULT_POPULATION: Population = {
  seed: "1",
  groups: [],
  identities: 2,
  issuer: "https://idp.example.com",
};

export function emailOf(p: Population, n: number): string {
  return `user-${p.seed}-${n}@example.com`;
}

export function subjectOf(p: Population, n: number): string {
  return `sub-${p.seed}-${n}`;
}

/** One import line for user number `n` (NDJSON, without the newline). */
export function seedLine(p: Population, n: number): string {
  const tag = `${p.seed}-${n}`;
  return JSON.stringify({
    email: emailOf(p, n),
    email_verified: true,
    display_name: `User ${tag}`,
    groups: p.groups,
    identities: Array.from({ length: p.identities }, (_, i) => ({
      issuer: i === 0 ? p.issuer : `${p.issuer}/${i}`,
      subject: subjectOf(p, n),
    })),
  });
}

/** The NDJSON body of users `from` to `from + count - 1`. */
export function seedBatch(p: Population, from: number, count: number): string {
  const lines: string[] = [];
  for (let n = from; n < from + count; n++) lines.push(seedLine(p, n));
  return `${lines.join("\n")}\n`;
}
