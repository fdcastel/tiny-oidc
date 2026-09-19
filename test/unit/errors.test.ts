import { describe, expect, it } from "vitest";
import { errorBody, sanitizeDescription } from "../../src/router/errors.ts";

describe("error model", () => {
  it("[TIO-ERR-001] descriptions are printable ASCII of at most 256 characters", () => {
    expect(sanitizeDescription("plain text")).toBe("plain text");
    expect(sanitizeDescription("tab\tand\nnewline and ünïcödé")).toBe(
      "tab?and?newline and ?n?c?d?",
    );
    expect(sanitizeDescription("x".repeat(300))).toHaveLength(256);
    expect(errorBody("rid", "invalid_request", "bad é")).toEqual({
      error: "invalid_request",
      error_description: "bad ?",
      request_id: "rid",
    });
  });
});
