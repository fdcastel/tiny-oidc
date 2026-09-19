import { describe, expect, it } from "vitest";
import { auditAdmin } from "../../src/admin/audit.ts";
import {
  boundedDiff,
  MAX_DIFF_FIELDS,
  MAX_DIFF_VALUE_CHARS,
  SECRET_FIELDS,
} from "../../src/audit/diff.ts";
import { Auditor, MAX_DATA_BYTES } from "../../src/audit/events.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Logger, type LogLine } from "../../src/obs/log.ts";
import { FakeClock } from "../support/clock.ts";

// The audit emitter (spec §11.1) and the diff an admin mutation records
// (TIO-ADMIN-002, TIO-ADMIN-003).

const clock = new FakeClock(1_800_000_000);

function auditor() {
  return new Auditor(
    { request_id: "req-1", ip_hash: "iph", country: "BR", ua_family: "Chrome/128" },
    new UuidV7(clock),
    clock,
  );
}

describe("Auditor", () => {
  it("[TIO-ADMIN-002] fills the §11.1 record from the request context, defaults the optional references to null and flushes one info line per event", () => {
    const a = auditor();
    const event = a.emit({
      type: "client.created",
      outcome: "success",
      actor: { kind: "admin", id: "0192aaaa-0000-7000-8000-000000000001" },
      client_id: "c_new",
      data: { target: "c_new", diff: { client_name: { from: null, to: "New" } } },
    });
    expect(event).toEqual({
      id: expect.stringMatching(/^[0-9a-f-]{36}$/),
      ts: clock.now(),
      type: "client.created",
      outcome: "success",
      actor: { kind: "admin", id: "0192aaaa-0000-7000-8000-000000000001" },
      user_id: null,
      client_id: "c_new",
      upstream: null,
      sid: null,
      interaction_id: null,
      ip_hash: "iph",
      country: "BR",
      ua_family: "Chrome/128",
      request_id: "req-1",
      reason: null,
      data: { target: "c_new", diff: { client_name: { from: null, to: "New" } } },
    });
    a.emit({
      type: "user.updated",
      outcome: "failure",
      actor: { kind: "system", id: null },
      reason: "partial_failure",
    });
    const lines: LogLine[] = [];
    a.flush(new Logger((line) => lines.push(line), "info"));
    expect(lines.map((l) => [l["level"], l["msg"], (l["event"] as { type: string }).type])).toEqual(
      [
        ["info", "audit", "client.created"],
        ["info", "audit", "user.updated"],
      ],
    );
    expect((lines[1] as LogLine)["event"]).toMatchObject({ reason: "partial_failure" });
    expect(a.events).toHaveLength(2);
  });

  it("[TIO-ADMIN-002] a data payload past 4 KB is replaced by a marker rather than shipped", () => {
    const a = auditor();
    const big = a.emit({
      type: "admin.import_batch",
      outcome: "success",
      actor: { kind: "admin", id: "x" },
      data: { lines: "x".repeat(MAX_DATA_BYTES) },
    });
    expect(big.data).toEqual({ truncated: true });
    const fits = a.emit({
      type: "admin.import_batch",
      outcome: "success",
      actor: { kind: "admin", id: "x" },
      data: { lines: "x".repeat(MAX_DATA_BYTES - 12) },
    });
    expect(fits.data).toEqual({ lines: "x".repeat(MAX_DATA_BYTES - 12) });
  });
});

describe("boundedDiff", () => {
  it("[TIO-ADMIN-002] [TIO-ADMIN-003] records only changed fields, marks secret fields as changed without their values, shortens long values and caps the number of fields", () => {
    const before = {
      client_name: "Old",
      redirect_uris: ["https://a.example.com/cb"],
      client_secret_hash: "hash-1",
      jwks: { keys: [{ kid: "a" }] },
      untouched: 1,
      disabled_at: null,
    };
    const after = {
      client_name: "New",
      redirect_uris: ["https://a.example.com/cb", "https://b.example.com/cb"],
      client_secret_hash: "hash-2",
      jwks: { keys: [{ kid: "b" }] },
      untouched: 1,
      disabled_at: 1_800_000_000,
      long: "y".repeat(MAX_DIFF_VALUE_CHARS + 10),
    };
    const diff = boundedDiff(before, after);
    expect(diff).toEqual({
      client_name: { from: "Old", to: "New" },
      client_secret_hash: { changed: true },
      disabled_at: { from: null, to: 1_800_000_000 },
      jwks: { changed: true },
      long: {
        from: null,
        to: `${JSON.stringify("y".repeat(MAX_DIFF_VALUE_CHARS)).slice(0, MAX_DIFF_VALUE_CHARS)}…`,
      },
      redirect_uris: {
        from: ["https://a.example.com/cb"],
        to: ["https://a.example.com/cb", "https://b.example.com/cb"],
      },
    });
    expect(JSON.stringify(diff)).not.toContain("hash-");
    for (const field of SECRET_FIELDS) {
      expect(JSON.stringify(boundedDiff({ [field]: "s1" }, { [field]: "s2" }))).not.toContain("s1");
    }
    // Creation and deletion diff against nothing.
    expect(boundedDiff(null, { name: "x" })).toEqual({ name: { from: null, to: "x" } });
    expect(boundedDiff({ name: "x" }, null)).toEqual({ name: { from: "x", to: null } });
    expect(boundedDiff({ a: 1 }, { a: 1 })).toEqual({});
    // At most MAX_DIFF_FIELDS entries, then an ellipsis marker.
    const wide = Object.fromEntries(
      Array.from({ length: MAX_DIFF_FIELDS + 5 }, (_, i) => [`f${i}`, i]),
    );
    const capped = boundedDiff({}, wide);
    expect(Object.keys(capped)).toHaveLength(MAX_DIFF_FIELDS + 1);
    expect(capped["…"]).toEqual({ changed: true });
  });
});

describe("auditAdmin", () => {
  it("[TIO-ADMIN-002] records the administrator as actor with the target and a diff when either side is given, and no diff otherwise", () => {
    const a = auditor();
    const admin = { kind: "admin", id: "admin-1", subject: "user", token: {} };
    const c = {
      get: (key: string) => (key === "admin" ? admin : a),
    } as unknown as Parameters<typeof auditAdmin>[0];
    const deleted = auditAdmin(c, {
      type: "client.deleted",
      target: "c_old",
      client_id: "c_old",
      before: { client_name: "Old", client_secret_hash: "h" },
    });
    expect(deleted).toMatchObject({
      actor: { kind: "admin", id: "admin-1" },
      outcome: "success",
      user_id: null,
      client_id: "c_old",
      upstream: null,
      sid: null,
      reason: null,
      data: {
        target: "c_old",
        diff: { client_name: { from: "Old", to: null }, client_secret_hash: { changed: true } },
      },
    });
    const plain = auditAdmin(c, {
      type: "admin.import_batch",
      target: "batch-1",
      outcome: "failure",
      reason: "partial",
      data: { lines: 3 },
    });
    expect(plain.data).toEqual({ target: "batch-1", lines: 3 });
    expect(plain).toMatchObject({ outcome: "failure", reason: "partial" });
    expect(a.events).toHaveLength(2);
  });
});
