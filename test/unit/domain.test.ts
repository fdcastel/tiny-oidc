import { describe, expect, it } from "vitest";
import { registrableDomain, sameSite } from "../../src/util/domain.ts";

describe("registrable domain approximation", () => {
  it("takes the last two labels, three under known second-level suffixes, and keeps loopback hosts", () => {
    expect(registrableDomain("auth.example.com")).toBe("example.com");
    expect(registrableDomain("Example.COM.")).toBe("example.com");
    expect(registrableDomain("login.staging.example.co.uk")).toBe("example.co.uk");
    expect(registrableDomain("a.com.br")).toBe("a.com.br");
    expect(registrableDomain("co.uk")).toBe("co.uk");
    expect(registrableDomain("localhost")).toBe("localhost");
    expect(registrableDomain("127.0.0.1")).toBe("127.0.0.1");
    expect(registrableDomain("[::1]")).toBe("[::1]");
    expect(registrableDomain("x.company.com")).toBe("company.com");
  });

  it("same-site compares registrable domains", () => {
    expect(sameSite("auth.example.com", "login.example.com")).toBe(true);
    expect(sameSite("auth.example.com", "example.org")).toBe(false);
    expect(sameSite("a.example.workers.dev", "b.example.workers.dev")).toBe(true);
  });
});
