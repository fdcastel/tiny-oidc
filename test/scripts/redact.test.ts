import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PLACEHOLDER, redact, redactTree, registrableDomain } from "../../scripts/lib/redact.ts";

// The nightly's artifacts are public (a public repository): the staging
// hostnames the logs record are redacted before every upload.

describe("artifact redaction", () => {
  it("takes the registrable domain of a URL or host, three labels under a short country second level", () => {
    expect(registrableDomain("https://auth.staging.example.org/")).toBe("example.org");
    expect(registrableDomain("login.staging.example.org")).toBe("example.org");
    expect(registrableDomain("https://idp.example.com.br/x")).toBe("example.com.br");
    expect(registrableDomain("https://Example.ORG")).toBe("example.org");
    expect(registrableDomain("")).toBeNull();
    expect(registrableDomain("localhost")).toBeNull();
    expect(registrableDomain("http://[::1")).toBeNull();
  });

  it("replaces every host under the domains, encoded or not, in any case", () => {
    const text =
      'connect-src https://auth.staging.example.org; redirect_uri=https%3A%2F%2Fauth.staging.example.org%2Fcb "rp_id":"staging.EXAMPLE.org" other.example.net';
    expect(redact(text, ["example.org"])).toBe(
      `connect-src https://auth.staging.${PLACEHOLDER}; redirect_uri=https%3A%2F%2Fauth.staging.${PLACEHOLDER}%2Fcb "rp_id":"staging.${PLACEHOLDER}" other.example.net`,
    );
  });

  it("rewrites the text files of a tree in place and leaves other files alone", () => {
    const dir = mkdtempSync(join(tmpdir(), "redact-"));
    try {
      mkdirSync(join(dir, "logs"));
      writeFileSync(join(dir, "logs", "a.json"), '{"issuer":"https://auth.example.org"}');
      writeFileSync(join(dir, "server.log"), "GET https://login.example.org/");
      writeFileSync(join(dir, "clean.txt"), "nothing here");
      writeFileSync(join(dir, "shot.png"), "https://auth.example.org");
      const changed = redactTree(dir, ["example.org"]).map((f) => f.slice(dir.length + 1));
      expect(changed.sort()).toEqual([join("logs", "a.json"), "server.log"].sort());
      expect(readFileSync(join(dir, "logs", "a.json"), "utf8")).toBe(
        `{"issuer":"https://auth.${PLACEHOLDER}"}`,
      );
      expect(readFileSync(join(dir, "shot.png"), "utf8")).toBe("https://auth.example.org");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("runs before every artifact of the nightly that records staging traffic", () => {
    const nightly = readFileSync(".github/workflows/nightly.yml", "utf8");
    for (const name of ["conformance-results", "load-reports", "soak-reports"]) {
      const upload = nightly.indexOf(`name: ${name}`);
      const before = nightly.slice(0, upload);
      const lastUpload = before.lastIndexOf("upload-artifact");
      const redaction = before.lastIndexOf("scripts/redact-artifacts.ts");
      expect(redaction, name).toBeGreaterThan(-1);
      // The redaction sits between the previous upload and this one.
      expect(redaction, name).toBeGreaterThan(
        before.lastIndexOf("upload-artifact", lastUpload - 1),
      );
    }
    expect(nightly.match(/TIO_REDACT_URLS:/g)).toHaveLength(3);
  });
});
