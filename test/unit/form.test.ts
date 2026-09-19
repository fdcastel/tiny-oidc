import { describe, expect, it } from "vitest";
import { FORM_CONTENT_TYPE, readForm } from "../../src/router/form.ts";

// A string body would get a text/plain content type by default; bytes get none.
const post = (body: string, contentType: string | null = FORM_CONTENT_TYPE) =>
  new Request("https://auth.example.com/token", {
    method: "POST",
    body: new TextEncoder().encode(body),
    headers: contentType === null ? {} : { "content-type": contentType },
  });

describe("readForm", () => {
  it("[TIO-TOKEN-001] accepts only application/x-www-form-urlencoded (any charset parameter, any case) and rejects duplicate parameters", async () => {
    expect(await readForm(post("grant_type=code&code=abc%20d"))).toEqual({
      ok: true,
      params: new Map([
        ["grant_type", "code"],
        ["code", "abc d"],
      ]),
    });
    expect(
      (await readForm(post("a=1", "Application/X-WWW-Form-Urlencoded; charset=UTF-8"))).ok,
    ).toBe(true);
    expect(await readForm(post(""))).toEqual({ ok: true, params: new Map() });
    expect(await readForm(post("a=1&a=2"))).toEqual({ ok: false, reason: "duplicate parameter" });
    expect(await readForm(post("a=1&b=2&a=1"))).toEqual({
      ok: false,
      reason: "duplicate parameter",
    });
    for (const contentType of ["application/json", "text/plain", "multipart/form-data", null]) {
      expect(await readForm(post("a=1", contentType)), String(contentType)).toEqual({
        ok: false,
        reason: "unsupported content type",
      });
    }
  });
});
