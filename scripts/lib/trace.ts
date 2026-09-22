// Pure logic of the traceability gate (TIO-TEST-006, TIO-TEST-007). No I/O here;
// scripts/trace.ts reads the files and writes doc/TRACEABILITY.md.

const ID_PATTERN = /TIO-[A-Z]+-\d{3}/g;

type Verification = "test" | "ci" | "conformance" | "load" | "review" | "withdrawn";

export interface Requirement {
  id: string;
  /** Section number of the nearest heading above the definition, e.g. "5.4.1" or "B". */
  section: string;
  verification: Verification;
  line: number;
}

export interface TestReference {
  file: string;
  title: string;
  ids: string[];
}

export interface TraceConfig {
  /** The phase currently being implemented; identifiers assigned to later phases may be uncovered. */
  phase: number;
  /** Phase → section numbers whose default-tag identifiers must be covered by the end of that phase. */
  phases: Record<string, string[]>;
  /** Identifier → phase, overriding the section mapping. */
  overrides: Record<string, number>;
  /** Identifier → k6 threshold names that verify it (TIO-TEST-007). */
  load_thresholds: Record<string, string[]>;
  /** Identifier → conformance plan names that verify it (TIO-TEST-007). */
  conformance_plans: Record<string, string[]>;
}

const DEFINITION =
  /\*\*\[(TIO-[A-Z]+-\d{3})\]\*\*(?:\s*\((withdrawn|V: (ci|conformance|load|review))\))?/g;
const HEADING = /^(#{2,4})\s+(?:(\d+(?:\.\d+)*)\.?|Appendix\s+([A-Z]))\b/;

/** Parses every `**[TIO-…]**` definition of the specification with its section and verification tag. */
export function parseSpec(markdown: string): Requirement[] {
  const requirements: Requirement[] = [];
  let section = "0";
  const lines = markdown.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const heading = HEADING.exec(line);
    if (heading) {
      section = heading[2] ?? heading[3] ?? section;
      continue;
    }
    for (const match of line.matchAll(DEFINITION)) {
      const id = match[1] as string;
      let verification: Verification = "test";
      if (match[2] === "withdrawn") verification = "withdrawn";
      else if (match[3]) verification = match[3] as Verification;
      requirements.push({ id, section, verification, line: index + 1 });
    }
  }
  return requirements;
}

/** Returns identifiers defined more than once (TIO-TEST-006: "an identifier appears twice"). */
export function duplicateIds(requirements: Requirement[]): string[] {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const r of requirements) {
    if (seen.has(r.id)) duplicates.add(r.id);
    seen.add(r.id);
  }
  return [...duplicates].sort();
}

const CALLEE =
  /(?:it|test)(?:\.(?:only|skip|todo|concurrent|sequential|fails|runIf|skipIf))*(\.(?:each|for))?\s*/y;
const IDENTIFIER_CHAR = /[\w$]/;

/**
 * Extracts the titles of `it(...)`, `test(...)` and their `.each`/`.for` forms
 * from a test file's source. The scanner skips comments and string literals
 * it is not reading as a title, so fixtures that contain test source do not
 * count. `describe` titles are deliberately not counted: the identifier must
 * be in the title of the test that proves it.
 */
export function parseTestTitles(source: string): string[] {
  const titles: string[] = [];
  let position = 0;
  while (position < source.length) {
    const ch = source[position];
    const next = source[position + 1];
    if (ch === "/" && next === "/") {
      position = skipLineComment(source, position);
      continue;
    }
    if (ch === "/" && next === "*") {
      position = skipBlockComment(source, position);
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      const end = skipString(source, position);
      if (end < 0) break;
      position = end;
      continue;
    }
    const previous = source[position - 1];
    if (previous !== undefined && IDENTIFIER_CHAR.test(previous)) {
      position++;
      continue;
    }
    CALLEE.lastIndex = position;
    const callee = CALLEE.exec(source);
    if (!callee) {
      position++;
      continue;
    }
    let cursor = position + callee[0].length;
    if (callee[1]) {
      // it.each(table)(title) or it.each`table`(title): skip the table argument.
      const argument = source[cursor];
      if (argument === "(") cursor = skipBalanced(source, cursor);
      else if (argument === "`") cursor = skipString(source, cursor);
      else {
        position++;
        continue;
      }
      if (cursor < 0) break;
      cursor = skipWhitespace(source, cursor);
    }
    if (source[cursor] !== "(") {
      position++;
      continue;
    }
    cursor = skipWhitespace(source, cursor + 1);
    const quote = source[cursor];
    if (quote !== '"' && quote !== "'" && quote !== "`") {
      position = cursor;
      continue;
    }
    const end = skipString(source, cursor);
    if (end < 0) break;
    titles.push(source.slice(cursor + 1, end - 1));
    position = end;
  }
  return titles;
}

function skipLineComment(source: string, position: number): number {
  const end = source.indexOf("\n", position);
  return end < 0 ? source.length : end;
}

function skipBlockComment(source: string, position: number): number {
  const end = source.indexOf("*/", position + 2);
  return end < 0 ? source.length : end + 2;
}

function skipWhitespace(source: string, position: number): number {
  let p = position;
  while (p < source.length && /\s/.test(source[p] as string)) p++;
  return p;
}

/** Returns the index just past the closing quote of the string starting at `position`, or -1. */
function skipString(source: string, position: number): number {
  const quote = source[position];
  let p = position + 1;
  while (p < source.length) {
    const ch = source[p];
    if (ch === "\\") p += 2;
    else if (ch === quote) return p + 1;
    else p++;
  }
  return -1;
}

/** Returns the index just past the parenthesis group starting at `position`, or -1. */
function skipBalanced(source: string, position: number): number {
  let depth = 0;
  let p = position;
  while (p < source.length) {
    const ch = source[p];
    if (ch === '"' || ch === "'" || ch === "`") {
      p = skipString(source, p);
      if (p < 0) return -1;
      continue;
    }
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return p + 1;
    }
    p++;
  }
  return -1;
}

function idsInTitle(title: string): string[] {
  return [...new Set(title.match(ID_PATTERN) ?? [])];
}

/** Collects every test title that cites an identifier, per file. */
export function collectReferences(files: Record<string, string>): TestReference[] {
  const references: TestReference[] = [];
  for (const [file, source] of Object.entries(files)) {
    for (const title of parseTestTitles(source)) {
      const ids = idsInTitle(title);
      if (ids.length > 0) references.push({ file, title, ids });
    }
  }
  return references;
}

/** Phase in which a requirement must be covered: an explicit override, else the most specific section mapping. */
export function phaseOf(requirement: Requirement, config: TraceConfig): number | undefined {
  const override = config.overrides[requirement.id];
  if (override !== undefined) return override;
  let best: { phase: number; length: number } | undefined;
  for (const [phase, sections] of Object.entries(config.phases)) {
    for (const section of sections) {
      const matches =
        requirement.section === section || requirement.section.startsWith(`${section}.`);
      if (matches && (best === undefined || section.length > best.length)) {
        best = { phase: Number(phase), length: section.length };
      }
    }
  }
  return best?.phase;
}

export interface TraceResult {
  errors: string[];
  warnings: string[];
  rows: TraceRow[];
}

export interface TraceRow {
  id: string;
  section: string;
  verification: Verification;
  phase: number | undefined;
  status:
    | "covered"
    | "uncovered"
    | "deferred"
    | "withdrawn"
    | "ci"
    | "review"
    | "load"
    | "conformance";
  files: string[];
}

export function trace(
  requirements: Requirement[],
  references: TestReference[],
  config: TraceConfig,
): TraceResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  for (const id of duplicateIds(requirements)) errors.push(`duplicate definition: ${id}`);

  const byId = new Map(requirements.map((r) => [r.id, r]));
  const filesById = new Map<string, Set<string>>();
  for (const ref of references) {
    for (const id of ref.ids) {
      const requirement = byId.get(id);
      if (!requirement) {
        errors.push(`${ref.file}: test "${ref.title}" cites unknown identifier ${id}`);
        continue;
      }
      if (requirement.verification === "withdrawn") {
        errors.push(`${ref.file}: test "${ref.title}" cites withdrawn identifier ${id}`);
        continue;
      }
      if (requirement.verification !== "test") {
        warnings.push(
          `${ref.file}: test "${ref.title}" cites ${id}, which is verified by (V: ${requirement.verification})`,
        );
      }
      let files = filesById.get(id);
      if (!files) {
        files = new Set();
        filesById.set(id, files);
      }
      files.add(ref.file);
    }
  }

  const rows: TraceRow[] = [];
  for (const requirement of requirements) {
    const files = [...(filesById.get(requirement.id) ?? [])].sort();
    const phase = phaseOf(requirement, config);
    let status: TraceRow["status"];
    if (requirement.verification === "withdrawn") status = "withdrawn";
    else if (requirement.verification !== "test") {
      status = requirement.verification;
      if (requirement.verification === "load" && !config.load_thresholds[requirement.id]) {
        errors.push(
          `${requirement.id} is (V: load) but has no k6 threshold mapping in trace.config.json`,
        );
      }
      if (requirement.verification === "conformance" && !config.conformance_plans[requirement.id]) {
        errors.push(
          `${requirement.id} is (V: conformance) but has no conformance plan mapping in trace.config.json`,
        );
      }
    } else if (files.length > 0) status = "covered";
    else if (phase === undefined) {
      status = "uncovered";
      errors.push(`${requirement.id} (§${requirement.section}) has no test and no phase mapping`);
    } else if (phase > config.phase) status = "deferred";
    else {
      status = "uncovered";
      errors.push(
        `${requirement.id} (§${requirement.section}, phase ${phase}) has no test whose title cites it`,
      );
    }
    rows.push({
      id: requirement.id,
      section: requirement.section,
      verification: requirement.verification,
      phase,
      status,
      files,
    });
  }
  return { errors, warnings, rows };
}

/** One row of the threat model (§15): the threat and the requirement ids it names, ranges expanded. */
export interface ThreatRow {
  id: string;
  threat: string;
  requirements: string[];
  /** Tokens of the Requirements column the parser could not read (an em dash, a space, a lowercase prefix): no evidence is derived from them. */
  unparsable: string[];
}

/**
 * The threat model's rows, with a range such as `FED-030–FED-043` expanded to
 * every id in it. An id the specification never assigns (a gap in a range)
 * stays in the list: the evidence section shows it as unknown, which is
 * where a reviewer learns that a row rests on fewer requirements than its
 * range suggests (ADR 0011).
 */
export function parseThreats(markdown: string): ThreatRow[] {
  const start = markdown.indexOf("## 15. Threat model");
  if (start === -1) return [];
  const rows: ThreatRow[] = [];
  for (const line of markdown.slice(start).split("\n")) {
    const m = /^\| (T\d+) \| ([^|]*) \| [^|]* \| ([^|]*) \|/.exec(line);
    if (!m) continue;
    const requirements: string[] = [];
    const unparsable: string[] = [];
    for (const token of (m[3] as string).split(/,\s*/)) {
      const r = /^([A-Z]+)-(\d+)(?:[–-]([A-Z]+)-(\d+))?$/.exec(token.trim());
      if (!r) {
        if (token.trim() !== "") unparsable.push(token.trim());
        continue;
      }
      if (r[3] !== undefined) {
        for (let n = Number(r[2]); n <= Number(r[4]); n++)
          requirements.push(`TIO-${r[1]}-${String(n).padStart(3, "0")}`);
      } else requirements.push(`TIO-${r[1]}-${r[2]}`);
    }
    rows.push({ id: m[1] as string, threat: (m[2] as string).trim(), requirements, unparsable });
  }
  return rows;
}

/** The evidence behind one threat: the test files of its requirements, and the ids the specification does not assign. */
export interface ThreatEvidence {
  id: string;
  threat: string;
  files: string[];
  unassigned: string[];
}

export function threatEvidence(threats: ThreatRow[], rows: TraceRow[]): ThreatEvidence[] {
  const byId = new Map(rows.map((r) => [r.id, r]));
  return threats.map((t) => {
    const files = new Set<string>();
    const unassigned: string[] = [];
    for (const id of t.requirements) {
      const row = byId.get(id);
      if (row === undefined) unassigned.push(id);
      else for (const f of row.files) files.add(f);
    }
    return { id: t.id, threat: t.threat, files: [...files].sort(), unassigned };
  });
}

/** Renders doc/TRACEABILITY.md: the requirement rows, then the threat evidence (TIO-SEC-001). */
export function renderTraceability(
  rows: TraceRow[],
  config: TraceConfig,
  threats: ThreatRow[] = [],
): string {
  const counts = new Map<string, number>();
  for (const row of rows) counts.set(row.status, (counts.get(row.status) ?? 0) + 1);
  const summary = [...counts.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([status, n]) => `${status}: ${n}`)
    .join(", ");
  const lines = [
    "# Traceability",
    "",
    "Generated by `pnpm trace` from [TINY_OIDC_SPEC.md](TINY_OIDC_SPEC.md) and `test/**`. Do not edit by hand.",
    "",
    `Current phase: ${config.phase}. Requirements: ${rows.length} (${summary}).`,
    "",
    "| Identifier | Section | Verification | Phase | Status | Tests |",
    "|---|---|---|---|---|---|",
  ];
  for (const row of rows) {
    const phase = row.verification === "test" ? String(row.phase ?? "?") : "—";
    lines.push(
      `| ${row.id} | §${row.section} | ${row.verification} | ${phase} | ${row.status} | ${row.files.join("<br>")} |`,
    );
  }
  if (threats.length > 0) {
    lines.push(
      "",
      "## Threat evidence",
      "",
      "The test files behind every row of the threat model (§15), through the requirement ids the row names. The threat-model review (TIO-SEC-001, ADR 0011) cites this section instead of copying it.",
      "",
      "| Threat | Requirements | Tests | Ids the specification does not assign |",
      "|---|---|---|---|",
    );
    for (const t of threatEvidence(threats, rows)) {
      const requirements = threats.find((x) => x.id === t.id)?.requirements ?? [];
      lines.push(
        `| ${t.id} ${t.threat} | ${requirements.length} | ${t.files.join("<br>")} | ${t.unassigned.join(", ")} |`,
      );
    }
  }
  lines.push("");
  return lines.join("\n");
}
