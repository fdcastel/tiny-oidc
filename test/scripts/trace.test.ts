import { describe, expect, it } from "vitest";
import {
  collectReferences,
  duplicateIds,
  parseSpec,
  parseTestTitles,
  phaseOf,
  renderTraceability,
  type TraceConfig,
  trace,
} from "../../scripts/lib/trace.ts";

const config: TraceConfig = {
  phase: 1,
  phases: { "0": ["2"], "1": ["5.2"], "2": ["5"] },
  overrides: { "TIO-X-009": 0 },
  load_thresholds: { "TIO-L-001": ["t"] },
  conformance_plans: { "TIO-C-001": ["p"] },
};

describe("parseSpec", () => {
  it("records the section, verification tag and line of every definition", () => {
    const spec = [
      "## 2. Architecture",
      "**[TIO-A-001]** default tag.",
      "### 5.2 Discovery",
      "text **[TIO-B-001]** (V: ci) and **[TIO-B-002]** (withdrawn) same line",
      "#### 5.2.1 Deeper",
      "1. **[TIO-B-003]** (V: load) list item",
      "## Appendix B. Decisions",
      "**[TIO-Z-001]** (V: review)",
    ].join("\n");
    expect(parseSpec(spec)).toEqual([
      { id: "TIO-A-001", section: "2", verification: "test", line: 2 },
      { id: "TIO-B-001", section: "5.2", verification: "ci", line: 4 },
      { id: "TIO-B-002", section: "5.2", verification: "withdrawn", line: 4 },
      { id: "TIO-B-003", section: "5.2.1", verification: "load", line: 6 },
      { id: "TIO-Z-001", section: "B", verification: "review", line: 8 },
    ]);
  });

  it("finds duplicate definitions", () => {
    const reqs = parseSpec("**[TIO-A-001]** a\n**[TIO-A-001]** b\n**[TIO-A-002]** c");
    expect(duplicateIds(reqs)).toEqual(["TIO-A-001"]);
  });
});

describe("parseTestTitles", () => {
  it("extracts it/test titles in every quote style and modifier", () => {
    const src = [
      'it("plain [TIO-A-001]", () => {});',
      "test('single [TIO-A-002]', () => {});",
      "it.only(`template ${x} [TIO-A-003]`, () => {});",
      'test.skip.concurrent("modifiers [TIO-A-004]", () => {});',
      'it.each([["a"], ["b"]])("each %s [TIO-A-005]", (v) => {});',
      "it.each`",
      "  a | b",
      "  ${1} | ${2}",
      '`("each template $a [TIO-A-006]", () => {});',
      'test.for([1, 2])("for %i [TIO-A-007]", () => {});',
      'it("escaped \\" quote [TIO-A-008]", () => {});',
      'const its = 1; limit(3); commit("no");',
    ].join("\n");
    expect(parseTestTitles(src)).toEqual([
      "plain [TIO-A-001]",
      "single [TIO-A-002]",
      "template ${x} [TIO-A-003]",
      "modifiers [TIO-A-004]",
      "each %s [TIO-A-005]",
      "each template $a [TIO-A-006]",
      "for %i [TIO-A-007]",
      'escaped \\" quote [TIO-A-008]',
    ]);
  });

  it("ignores describe titles and calls without a string title", () => {
    const src =
      'describe("[TIO-A-001]", () => { it(title, () => {}); it.each(rows)(fn); it.each(x); it.each });';
    expect(parseTestTitles(src)).toEqual([]);
  });

  it("stops on unterminated strings and parentheses without throwing", () => {
    expect(parseTestTitles('it("unterminated')).toEqual([]);
    expect(parseTestTitles("it.each([1, 2")).toEqual([]);
    expect(parseTestTitles("it.each([1])('unterminated")).toEqual([]);
    expect(parseTestTitles("it.each(['a)']")).toEqual([]);
  });
});

describe("trace", () => {
  const spec = [
    "## 2. Architecture",
    "**[TIO-X-001]** covered",
    "**[TIO-X-002]** uncovered phase 0",
    "**[TIO-X-009]** overridden to phase 0",
    "### 5.2 Discovery",
    "**[TIO-X-003]** uncovered phase 1",
    "### 5.4 Authorize",
    "**[TIO-X-004]** deferred phase 2",
    "**[TIO-X-005]** (withdrawn)",
    "**[TIO-L-001]** (V: load)",
    "**[TIO-L-002]** (V: load)",
    "**[TIO-C-001]** (V: conformance)",
    "**[TIO-C-002]** (V: conformance)",
    "**[TIO-R-001]** (V: ci)",
    "## 9. Unmapped",
    "**[TIO-U-001]** no phase",
  ].join("\n");
  const requirements = parseSpec(spec);
  const byId = new Map(requirements.map((r) => [r.id, r]));
  const req = (id: string) => {
    const r = byId.get(id);
    if (!r) throw new Error(id);
    return r;
  };

  it("maps requirements to phases by most specific section or override", () => {
    expect(phaseOf(req("TIO-X-001"), config)).toBe(0);
    expect(phaseOf(req("TIO-X-003"), config)).toBe(1);
    expect(phaseOf(req("TIO-X-004"), config)).toBe(2);
    expect(phaseOf(req("TIO-X-009"), config)).toBe(0);
    expect(phaseOf(req("TIO-U-001"), config)).toBeUndefined();
  });

  it("reports uncovered, unknown, withdrawn, unmapped and non-test citations", () => {
    const references = collectReferences({
      "test/a.test.ts":
        'it("covers [TIO-X-001] and [TIO-X-001] twice", () => {}); it("unknown [TIO-N-999]", () => {});',
      "test/b.test.ts":
        'it("withdrawn [TIO-X-005]", () => {}); it("ci-tagged [TIO-R-001]", () => {}); it("no ids", () => {});',
    });
    expect(references).toEqual([
      {
        file: "test/a.test.ts",
        title: "covers [TIO-X-001] and [TIO-X-001] twice",
        ids: ["TIO-X-001"],
      },
      { file: "test/a.test.ts", title: "unknown [TIO-N-999]", ids: ["TIO-N-999"] },
      { file: "test/b.test.ts", title: "withdrawn [TIO-X-005]", ids: ["TIO-X-005"] },
      { file: "test/b.test.ts", title: "ci-tagged [TIO-R-001]", ids: ["TIO-R-001"] },
    ]);
    const result = trace(requirements, references, config);
    expect(result.errors).toEqual([
      'test/a.test.ts: test "unknown [TIO-N-999]" cites unknown identifier TIO-N-999',
      'test/b.test.ts: test "withdrawn [TIO-X-005]" cites withdrawn identifier TIO-X-005',
      "TIO-X-002 (§2, phase 0) has no test whose title cites it",
      "TIO-X-009 (§2, phase 0) has no test whose title cites it",
      "TIO-X-003 (§5.2, phase 1) has no test whose title cites it",
      "TIO-L-002 is (V: load) but has no k6 threshold mapping in trace.config.json",
      "TIO-C-002 is (V: conformance) but has no conformance plan mapping in trace.config.json",
      "TIO-U-001 (§9) has no test and no phase mapping",
    ]);
    expect(result.warnings).toEqual([
      'test/b.test.ts: test "ci-tagged [TIO-R-001]" cites TIO-R-001, which is verified by (V: ci)',
    ]);
    expect(result.rows.map((r) => [r.id, r.status])).toEqual([
      ["TIO-X-001", "covered"],
      ["TIO-X-002", "uncovered"],
      ["TIO-X-009", "uncovered"],
      ["TIO-X-003", "uncovered"],
      ["TIO-X-004", "deferred"],
      ["TIO-X-005", "withdrawn"],
      ["TIO-L-001", "load"],
      ["TIO-L-002", "load"],
      ["TIO-C-001", "conformance"],
      ["TIO-C-002", "conformance"],
      ["TIO-R-001", "ci"],
      ["TIO-U-001", "uncovered"],
    ]);
  });

  it("reports duplicate definitions", () => {
    const dup = parseSpec("**[TIO-D-001]** a\n**[TIO-D-001]** b");
    expect(trace(dup, [], { ...config, phases: { "0": ["0"] } }).errors[0]).toBe(
      "duplicate definition: TIO-D-001",
    );
  });

  it("renders the traceability table with a summary and phase per row", () => {
    const references = collectReferences({
      "test/a.test.ts": 'it("[TIO-X-001]", () => {});',
    });
    const md = renderTraceability(trace(requirements, references, config).rows, config);
    expect(md).toContain("Current phase: 1. Requirements: 12 (");
    expect(md).toContain("| TIO-X-001 | §2 | test | 0 | covered | test/a.test.ts |");
    expect(md).toContain("| TIO-X-004 | §5.4 | test | 2 | deferred |  |");
    expect(md).toContain("| TIO-X-005 | §5.4 | withdrawn | — | withdrawn |  |");
    expect(md).toContain("| TIO-U-001 | §9 | test | ? | uncovered |  |");
  });
});
