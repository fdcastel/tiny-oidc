import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

/** Recursively lists files under `dir` (repository-relative, forward slashes), skipping `node_modules`. */
function listFiles(dir: string, filter: (path: string) => boolean = () => true): string[] {
  const out: string[] = [];
  const walk = (current: string): void => {
    for (const entry of readdirSync(current)) {
      if (entry === "node_modules" || entry === ".git") continue;
      const full = join(current, entry);
      if (statSync(full).isDirectory()) walk(full);
      else {
        const path = relative(process.cwd(), full).split(sep).join("/");
        if (filter(path)) out.push(path);
      }
    }
  };
  walk(dir);
  return out.sort();
}

export function readText(path: string): string {
  return readFileSync(path, "utf8");
}

/** Reads every file matching `filter` under `dir` into a path → contents map. */
export function readAll(dir: string, filter: (path: string) => boolean): Record<string, string> {
  const files: Record<string, string> = {};
  for (const path of listFiles(dir, filter)) files[path] = readText(path);
  return files;
}
