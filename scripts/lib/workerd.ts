// Orphaned workerd processes (Windows): a test run interrupted on Windows can
// leave its workerd children behind, holding ports and files, and the next
// `pnpm test` hangs on them. Only a workerd whose parent is gone is an orphan;
// one a live `wrangler dev` or test run owns is left alone.

export interface ProcessRow {
  pid: number;
  ppid: number;
}

/** The workerd processes whose parent no longer runs. */
export function orphans(workerd: ProcessRow[], alive: (pid: number) => boolean): number[] {
  return workerd.filter((p) => !alive(p.ppid)).map((p) => p.pid);
}

/** `Get-CimInstance … | ConvertTo-Json` prints one object bare and several as an array. */
export function parseProcessList(json: string): ProcessRow[] {
  if (json.trim() === "") return [];
  const parsed = JSON.parse(json) as
    | { ProcessId: number; ParentProcessId: number }
    | { ProcessId: number; ParentProcessId: number }[];
  return (Array.isArray(parsed) ? parsed : [parsed]).map((p) => ({
    pid: p.ProcessId,
    ppid: p.ParentProcessId,
  }));
}
