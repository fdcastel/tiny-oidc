import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("router", () => {
  it("answers unknown paths with a JSON 404", async () => {
    const res = await SELF.fetch("https://tiny-oidc.example.workers.dev/nope");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not_found" });
  });
});
