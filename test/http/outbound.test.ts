import { describe, expect, it } from "vitest";
import { disableNetwork, mountOrigin } from "../support/fetch-allowlist.ts";
import { op } from "../support/op.ts";

describe("outbound guard fixture", () => {
  it("blocks every outbound request except mounted origins, which answer through a pure handler", async () => {
    disableNetwork();
    await expect(fetch("https://example.org/anything")).rejects.toThrow();
    mountOrigin("https://upstream.test", async (request) => {
      const url = new URL(request.url);
      return Response.json(
        { path: url.pathname, method: request.method, body: await request.text() },
        { headers: { "x-fixture": "1" } },
      );
    });
    const get = await fetch("https://upstream.test/discovery?x=1");
    expect(get.headers.get("x-fixture")).toBe("1");
    expect(await get.json()).toEqual({ path: "/discovery", method: "GET", body: "" });
    const post = await fetch("https://upstream.test/token", {
      method: "POST",
      body: "grant_type=code",
    });
    expect(await post.json()).toEqual({ path: "/token", method: "POST", body: "grant_type=code" });
    // The guard covers the Worker under test as well.
    expect((await op("/api/v1/health")).status).toBe(200);
    disableNetwork();
  });
});
