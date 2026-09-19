import { describe, expect, it } from "vitest";
import {
  bindingCookieName,
  clearCookie,
  parseCookies,
  SESSION_COOKIE,
  setCookie,
} from "../../src/router/cookies.ts";

describe("cookies", () => {
  it("[TIO-SESS-001] [TIO-AUTHZ-020] sets __Host- cookies with Path=/, Secure, HttpOnly, SameSite=Lax and a Max-Age, and clears with Max-Age=0", () => {
    expect(setCookie(SESSION_COOKIE, "tio_ss_x", 2_592_000)).toBe(
      "__Host-tio_session=tio_ss_x; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000",
    );
    expect(clearCookie(SESSION_COOKIE)).toBe(
      "__Host-tio_session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
    );
    const id = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE";
    expect(bindingCookieName(id)).toBe("__Host-tio_ix_AbCdEfGhIjKlMnOp");
  });

  it("parses the Cookie header leniently: first occurrence wins, malformed pairs are skipped", () => {
    expect(parseCookies(null)).toEqual(new Map());
    expect(parseCookies("")).toEqual(new Map());
    expect(parseCookies("a=1; b=2=3; c; =d; a=9;  e = f ")).toEqual(
      new Map([
        ["a", "1"],
        ["b", "2=3"],
        ["e", "f"],
      ]),
    );
  });
});
