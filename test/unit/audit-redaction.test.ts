import { describe, expect, it } from "vitest";
import { AUDIT_CATALOG, AUDIT_TYPES } from "../../src/audit/catalog.ts";
import { Auditor } from "../../src/audit/events.ts";
import { REDACTED, redactData, redactReason } from "../../src/audit/redact.ts";
import { UuidV7 } from "../../src/crypto/uuid.ts";
import { Logger, type LogLine } from "../../src/obs/log.ts";
import { FakeClock } from "../support/clock.ts";

// Redaction (spec §11, TIO-AUDIT-002): every emitter is fed canary strings
// shaped like the things that must never be recorded, under allowed keys,
// forbidden keys, nested objects and arrays, and none of them reaches the log
// sink or the serialized event.

const CANARIES = {
  handle: "tio_rt_CANARYHANDLEcanaryhandleCANARYHANDLE00",
  jwt: "eyJCANARYHEADER.eyJDQU5BUllQQVlMT0FE.CANARYSIGNATURE00",
  secret: "CANARYSECRETcanarysecretCANARYSECRETcanary42",
  challenge: "CANARYCHALLENGE_canarychallenge_CANARY_0000",
  ipv4: "203.0.113.7",
  ipv6: "2001:db8::c4:7",
  userAgent: "Mozilla/5.0 (CANARY-UA) AppleWebKit/537.36 Chrome/128.0",
  email: "canaryperson@victim.example",
  upstreamDescription: "The upstream said: CANARYDESCRIPTION",
} as const;

const clock = new FakeClock(1_800_000_000);

function sink() {
  const lines: LogLine[] = [];
  return { lines, logger: new Logger((line) => lines.push(line), "debug") };
}

const auditor = () =>
  new Auditor(
    { request_id: "r", ip_hash: null, country: null, ua_family: null },
    new UuidV7(clock),
    clock,
  );

describe("audit redaction", () => {
  it("[TIO-AUDIT-002] no canary of any shape reaches a sink through any event type, whether under an allowed key, a forbidden key, nested or in the reason", () => {
    const a = auditor();
    const { lines, logger } = sink();
    // An upstream's prose travels only under its own key, which is redacted by name; every
    // other canary is recognized by shape wherever it lands.
    const { upstreamDescription, ...shaped } = CANARIES;
    const payload = Object.values(shaped);
    for (const type of AUDIT_TYPES) {
      const data: Record<string, unknown> = {
        token: CANARIES.jwt,
        error_description: upstreamDescription,
        nested: {
          deep: { code: CANARIES.secret, error_description: upstreamDescription, list: payload },
        },
        list: payload,
        smuggled: CANARIES.handle,
      };
      for (const key of AUDIT_CATALOG[type]) {
        data[key] = key === "diff" ? { email: { from: null, to: CANARIES.email } } : payload;
      }
      a.emit({
        type,
        outcome: "failure",
        actor: { kind: "user", id: "u" },
        reason: CANARIES.handle,
        data,
      });
    }
    a.flush(logger);
    const serialized = `${JSON.stringify(a.events)}\n${JSON.stringify(lines)}`;
    for (const [name, canary] of Object.entries(CANARIES)) {
      // The subject's own email may travel in a diff; every other canary is gone entirely.
      if (name === "email") continue;
      expect(serialized, name).not.toContain(canary);
    }
    // Outside a diff the address is masked; inside one it is the subject's own (TIO-AUDIT-002).
    for (const event of a.events) {
      const { diff: _diff, ...rest } = event.data;
      expect(JSON.stringify(rest), event.type).not.toContain("canaryperson");
    }
    expect(serialized).toContain("c***@victim.example");
    // What was dropped is reported once per event, never shipped.
    expect(a.dropped.every((d) => d.keys.includes("smuggled"))).toBe(true);
    expect(lines.filter((l) => l["msg"] === "audit data outside the catalog dropped")).toHaveLength(
      AUDIT_TYPES.length,
    );
  });

  it("[TIO-AUDIT-002] keeps what is harmless: identifiers, words, numbers, URLs, prefixed key thumbprints, and the subject's email inside a diff", () => {
    const kept = {
      target: "kid:5nXwHJ6l0nYqRk6Y2Jq6kU2fF8hE7XuT0qkZJ0m8fQw",
      kid: "kid:5nXwHJ6l0nYqRk6Y2Jq6kU2fF8hE7XuT0qkZJ0m8fQw",
      passkey_id: "01922e4a-1f5e-7c3d-8a9b-0c1d2e3f4a5b",
      issuer: "https://accounts.google.com",
      scopes: ["openid", "email"],
      lines: 12,
      ok: true,
      nothing: null,
      reason: "upstream:access_denied",
      diff: { email: { from: "old@example.com", to: "new@example.com" } },
    };
    expect(redactData(kept)).toEqual(kept);
    expect(redactData({ jti: "01922e4a-1f5e-7c3d-8a9b-0c1d2e3f4a5b" })).toEqual({
      jti: "01922e4a-1f5e-7c3d-8a9b-0c1d2e3f4a5b",
    });
    // A bare thumbprint, under any key, is an opaque secret.
    expect(redactData({ target: kept.kid.slice(4) })).toEqual({ target: REDACTED });
    expect(redactData({ contact: "someone@example.com" })).toEqual({
      contact: "s***@example.com",
    });
    expect(redactData({ ip: "10.0.0.1", where: "203.0.113.9", v6: "2001:db8::1" })).toEqual({
      ip: REDACTED,
      where: REDACTED,
      v6: REDACTED,
    });
    expect(redactReason(null)).toBeNull();
    expect(redactReason("id_token:nonce")).toBe("id_token:nonce");
    expect(redactReason(CANARIES.jwt)).toBe(REDACTED);
  });

  it("[TIO-AUDIT-001] an event of an unknown type ships no data and is reported", () => {
    const a = auditor();
    const event = a.emit({
      type: "made.up",
      outcome: "success",
      actor: { kind: "system", id: null },
      data: { anything: 1 },
    });
    expect(event.data).toEqual({});
    expect(a.dropped).toEqual([{ type: "made.up", keys: ["anything"] }]);
  });
});
