// Types for budgets.js (k6 runs the .js; the Node test imports it too).
export interface Budget {
  endpoint: string;
  p50: number;
  p99: number;
  d1w: number;
}
export const BUDGETS: Record<string, Budget>;
export const MAX_FAILED_RATE: number;
export const MAX_D1_WRITE_RATE: number;
