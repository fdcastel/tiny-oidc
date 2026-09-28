// `node scripts/kill-orphan-workerd.ts`, run before the tests: on Windows,
// stops the workerd processes an interrupted run left behind (their parent is
// gone), which otherwise make the next run hang. Elsewhere it does nothing.
import { execFileSync } from "node:child_process";
import { orphans, parseProcessList } from "./lib/workerd.ts";

if (process.platform === "win32") {
  const json = execFileSync(
    "powershell",
    [
      "-NoProfile",
      "-Command",
      "Get-CimInstance Win32_Process -Filter \"Name='workerd.exe'\" | Select-Object ProcessId,ParentProcessId | ConvertTo-Json -Compress",
    ],
    { encoding: "utf8" },
  );
  const alive = (pid: number) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  };
  for (const pid of orphans(parseProcessList(json), alive)) {
    try {
      process.kill(pid);
      console.log(`kill-orphan-workerd: stopped workerd ${pid}`);
    } catch {
      // Already gone.
    }
  }
}
