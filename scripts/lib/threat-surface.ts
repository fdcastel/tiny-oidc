// The surface the threat model (§15) was reviewed against, and what changed
// since. TIO-SEC-001 asks for a review when an endpoint or a handle type is
// added, so the three things worth watching are the route table, the handle
// kinds and the requirements each threat row leans on. Each changes rarely and
// every change is a review trigger, which is what makes a red build here a
// real one — unlike a diff of the evidence table, which moves whenever a test
// gains or drops a citation.
//
// The reviewed surface is `test/scripts/threat-surface.json`; the test in
// `test/scripts/threat-surface.test.ts` compares it with the current one, and
// `pnpm surface --write` rewrites it once the review is done.

import { parseThreats } from "./trace.ts";

/** Where the reviewed surface is kept, relative to the repository root. */
export const SURFACE_PATH = "test/scripts/threat-surface.json";

export interface Surface {
  /** `"<METHOD> <path>"` for every route of §5.1, sorted. */
  routes: string[];
  /** `"<kind> <prefix> 0x<type>"` for every handle type of §2.4, sorted. */
  handles: string[];
  /** The requirement ids of each §15 row, ranges expanded, sorted. */
  threats: Record<string, string[]>;
}

export interface SurfaceInputs {
  routes: readonly { readonly method: string; readonly path: string }[];
  handles: Readonly<Record<string, { readonly prefix: string; readonly type: number }>>;
  /** The specification's markdown, for §15. */
  spec: string;
}

const unique = (values: Iterable<string>): string[] => [...new Set(values)].sort();

export function surfaceOf(inputs: SurfaceInputs): Surface {
  const threats: Record<string, string[]> = {};
  for (const row of parseThreats(inputs.spec)) threats[row.id] = unique(row.requirements);
  return {
    routes: unique(inputs.routes.map((route) => `${route.method} ${route.path}`)),
    handles: unique(
      Object.entries(inputs.handles).map(
        ([kind, spec]) => `${kind} ${spec.prefix} 0x${spec.type.toString(16).padStart(2, "0")}`,
      ),
    ),
    threats,
  };
}

/** One line per difference between the reviewed surface and the current one. */
export function surfaceDiff(reviewed: Surface, current: Surface): string[] {
  const lines: string[] = [];
  const compare = (label: string, before: string[], after: string[]): void => {
    for (const value of after.filter((v) => !before.includes(v)))
      lines.push(`${label} added: ${value}`);
    for (const value of before.filter((v) => !after.includes(v)))
      lines.push(`${label} removed: ${value}`);
  };
  compare("route", reviewed.routes, current.routes);
  compare("handle", reviewed.handles, current.handles);
  for (const id of unique([...Object.keys(reviewed.threats), ...Object.keys(current.threats)])) {
    const before = reviewed.threats[id];
    const after = current.threats[id];
    if (before === undefined) lines.push(`threat ${id} added`);
    else if (after === undefined) lines.push(`threat ${id} removed`);
    else compare(`threat ${id}`, before, after);
  }
  return lines;
}

/** What to do about a difference; printed by the script and by the failing test. */
export const REVIEW_NOTICE = [
  "The surface the threat model was reviewed against has changed.",
  "[TIO-SEC-001] asks for a review of §15 when an endpoint or a handle type is added;",
  "a row's requirements changing means the evidence behind a threat moved.",
  "Re-review the model, record the outcome (an addendum to the review record or a new one),",
  `and update ${SURFACE_PATH} with \`pnpm surface --write\` in the same commit.`,
].join("\n");
