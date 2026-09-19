import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { request } from "@playwright/test";

// Once per run: bootstrap the fresh OP (scripts/e2e-server.ts starts it with
// empty storage) and park the first administrator's invitation for the first
// browser project to consume (TIO-ADMIN-010).

export const INVITATION_FILE = "test-results/e2e-invitation.json";

export default async function globalSetup(): Promise<void> {
  const op = process.env["TIO_E2E_BASE_URL"] ?? "http://localhost:8787";
  const match = /^ADMIN_BOOTSTRAP_TOKEN=(.+)$/m.exec(readFileSync(".dev.vars", "utf8"));
  if (!match) throw new Error(".dev.vars has no ADMIN_BOOTSTRAP_TOKEN");
  const api = await request.newContext();
  const res = await api.post(`${op}/api/v1/admin/bootstrap`, {
    headers: { authorization: `Bearer ${(match[1] as string).trim()}` },
    data: { email: "root@example.com", display_name: "Root" },
  });
  mkdirSync("test-results", { recursive: true });
  if (res.status() === 201) {
    writeFileSync(INVITATION_FILE, JSON.stringify(await res.json()));
  } else if (res.status() !== 410) {
    throw new Error(`bootstrap answered ${res.status()}: ${await res.text()}`);
  }
  await api.dispose();
}
