import { describe, expect, it } from "vitest";
import { concatBytes, decodeBase64Url, encodeBase64Url, utf8 } from "../../src/util/base64url.ts";

describe("base64url", () => {
  it("encodes without padding using the URL-safe alphabet", () => {
    expect(encodeBase64Url(new Uint8Array([]))).toBe("");
    expect(encodeBase64Url(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
    expect(encodeBase64Url(utf8("hello"))).toBe("aGVsbG8");
  });

  it("decodes canonical input and rejects padding, foreign alphabet, bad length and non-canonical bits", () => {
    expect(decodeBase64Url("aGVsbG8")).toEqual(utf8("hello"));
    expect(decodeBase64Url("")).toEqual(new Uint8Array([]));
    expect(decodeBase64Url("aGVsbG8=")).toBeNull();
    expect(decodeBase64Url("aGVs+G8")).toBeNull();
    expect(decodeBase64Url("aGVsb")).toBeNull();
    // "-_9" decodes to the same bytes as "-_8" but is not canonical.
    expect(decodeBase64Url("-_9")).toBeNull();
    expect(decodeBase64Url("-_8")).toEqual(new Uint8Array([0xfb, 0xff]));
  });

  it("concatenates byte arrays", () => {
    expect(concatBytes(new Uint8Array([1]), new Uint8Array([]), new Uint8Array([2, 3]))).toEqual(
      new Uint8Array([1, 2, 3]),
    );
  });
});
