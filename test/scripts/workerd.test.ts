import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { orphans, parseProcessList } from "../../scripts/lib/workerd.ts";

// The pre-test cleanup of orphaned workerd processes (Windows): only a
// workerd whose parent is gone is stopped.

describe("orphaned workerd", () => {
  it("stops only the workerd processes whose parent no longer runs", () => {
    const rows = parseProcessList(
      '[{"ProcessId":11,"ParentProcessId":1},{"ProcessId":12,"ParentProcessId":2}]',
    );
    expect(rows).toEqual([
      { pid: 11, ppid: 1 },
      { pid: 12, ppid: 2 },
    ]);
    expect(orphans(rows, (pid) => pid === 1)).toEqual([12]);
    // PowerShell prints a single process bare, and nothing when there is none.
    expect(parseProcessList('{"ProcessId":5,"ParentProcessId":4}')).toEqual([{ pid: 5, ppid: 4 }]);
    expect(parseProcessList("")).toEqual([]);
  });

  it("runs before the test suite", () => {
    const scripts = (
      JSON.parse(readFileSync("package.json", "utf8")) as {
        scripts: Record<string, string>;
      }
    ).scripts;
    expect(scripts["test"]).toMatch(/^node scripts\/kill-orphan-workerd\.ts && vitest run/);
  });
});
