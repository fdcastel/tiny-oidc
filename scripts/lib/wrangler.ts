import { type ExecFileSyncOptions, execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

/** Absolute path of wrangler's CLI entry, run with the current Node binary (no shell, portable on Windows). */
function wranglerBin(): string {
  const pkg = createRequire(import.meta.url).resolve("wrangler/package.json");
  return join(dirname(pkg), "bin", "wrangler.js");
}

export function runWrangler(args: string[], options: ExecFileSyncOptions = {}): string {
  const out = execFileSync(process.execPath, [wranglerBin(), ...args], {
    encoding: "utf8",
    ...options,
  });
  return typeof out === "string" ? out : "";
}
