// Types for budgets.js (k6 runs the .js; the Node test imports it too).
export interface Budget {
  endpoint: string;
  p50: number;
  p99: number;
  d1w: number;
  /** The row reads D1 by design: its budget covers every request. */
  d1: boolean;
}
export const BUDGETS: Record<string, Budget>;
export const TAIL_FACTOR: number;
export const BURST_FACTOR: number;
export const MAX_FAILED_RATE: number;
export const MAX_D1_WRITE_RATE: number;
