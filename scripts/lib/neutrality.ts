// Host- and account-neutrality of the public repository (TIO-DEPLOY-005):
// no 32-hex Cloudflare account ids and no real D1 database id in any committed file.
import { D1_PLACEHOLDER_ID } from "./config-check.ts";

const HEX32 = /(?<![0-9a-fA-F])[0-9a-f]{32}(?![0-9a-fA-F])/g;
const DATABASE_ID = /"database_id"\s*:\s*"([^"]*)"/g;

export interface NeutralityFinding {
  path: string;
  line: number;
  message: string;
}

function lineOf(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (source[i] === "\n") line++;
  return line;
}

export function checkNeutrality(files: Record<string, string>): NeutralityFinding[] {
  const findings: NeutralityFinding[] = [];
  for (const [path, source] of Object.entries(files)) {
    for (const match of source.matchAll(HEX32)) {
      findings.push({
        path,
        line: lineOf(source, match.index),
        message: `32-hex identifier "${match[0]}" looks like a Cloudflare account or resource id`,
      });
    }
    for (const match of source.matchAll(DATABASE_ID)) {
      if (match[1] !== D1_PLACEHOLDER_ID) {
        findings.push({
          path,
          line: lineOf(source, match.index),
          message: `database_id "${match[1]}" is not the placeholder ${D1_PLACEHOLDER_ID}`,
        });
      }
    }
  }
  return findings;
}

/** Files whose content is binary or generated and never carries configuration. */
export function isCheckedForNeutrality(path: string): boolean {
  return !/\.(png|jpg|jpeg|gif|ico|woff2?|gz|zip|pdf)$/i.test(path) && path !== "pnpm-lock.yaml";
}
