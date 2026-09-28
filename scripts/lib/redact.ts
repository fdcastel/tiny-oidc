// Redaction of the nightly's artifacts: the artifacts of a public repository
// are downloadable, and the conformance logs, the server log and the load
// reports carry the staging hostnames in every request they record. Each
// configured URL's registrable domain (and so every host under it, the RP ID
// included) becomes `redacted.invalid` before the upload.

import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { extname, join } from "node:path";

export const PLACEHOLDER = "redacted.invalid";

/** Extensions of the files the jobs upload as text; anything else is left as it is. */
const TEXT = new Set([".json", ".ndjson", ".txt", ".log", ".html", ".md", ".csv"]);

/**
 * The registrable domain of a URL or host: its last two labels, or three under a
 * two-letter country code with a short second level (`example.com.br`).
 */
export function registrableDomain(urlOrHost: string): string | null {
  let host = urlOrHost.trim();
  if (host === "") return null;
  try {
    host = new URL(host.includes("://") ? host : `https://${host}`).hostname;
  } catch {
    return null;
  }
  const labels = host.split(".").filter((l) => l.length > 0);
  if (labels.length < 2) return null;
  const tld = labels.at(-1) as string;
  const second = labels.at(-2) as string;
  const take = tld.length === 2 && second.length <= 3 && labels.length >= 3 ? 3 : 2;
  return labels.slice(-take).join(".").toLowerCase();
}

/** `text` with every occurrence of the domains (any case) replaced by the placeholder. */
export function redact(text: string, domains: string[]): string {
  let out = text;
  for (const domain of [...new Set(domains)].sort((a, b) => b.length - a.length)) {
    const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    out = out.replace(new RegExp(escaped, "gi"), PLACEHOLDER);
  }
  return out;
}

/** Redacts every text file under `dir` in place; returns the files it changed. */
export function redactTree(dir: string, domains: string[]): string[] {
  const changed: string[] = [];
  const walk = (path: string) => {
    for (const name of readdirSync(path)) {
      const full = join(path, name);
      if (statSync(full).isDirectory()) walk(full);
      else if (TEXT.has(extname(name).toLowerCase())) {
        const before = readFileSync(full, "utf8");
        const after = redact(before, domains);
        if (after !== before) {
          writeFileSync(full, after);
          changed.push(full);
        }
      }
    }
  };
  walk(dir);
  return changed;
}
