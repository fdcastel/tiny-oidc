// Bundle budget and content checks (TIO-PERF-002, TIO-GEN-002): the uncompressed
// Worker bundle stays below 1.5 MB and contains no template engine, HTML
// sanitizer or UI framework.

export const BUNDLE_LIMIT_BYTES = 1_500_000;

/** Markers whose presence in the bundle means a forbidden dependency was pulled in. */
const FORBIDDEN_BUNDLE_MARKERS: { marker: RegExp; what: string }[] = [
  { marker: /\bhandlebars\b/i, what: "template engine (handlebars)" },
  { marker: /\bmustache\b/i, what: "template engine (mustache)" },
  { marker: /\bnunjucks\b/i, what: "template engine (nunjucks)" },
  { marker: /\bejs\b/, what: "template engine (ejs)" },
  { marker: /\bpug\b/, what: "template engine (pug)" },
  { marker: /\bDOMPurify\b/, what: "HTML sanitizer (DOMPurify)" },
  { marker: /\bsanitize-html\b/, what: "HTML sanitizer (sanitize-html)" },
  { marker: /\breact-dom\b|\bReactDOM\b/, what: "UI framework (React DOM)" },
  { marker: /\bpreact\b/, what: "UI framework (preact)" },
  { marker: /\bsvelte\b/i, what: "UI framework (svelte)" },
  { marker: /\bvue\.runtime\b|\b@vue\b/, what: "UI framework (vue)" },
  { marker: /<!doctype html/i, what: "an HTML document" },
];

export interface BundleReport {
  bytes: number;
  errors: string[];
}

export function checkBundle(files: Record<string, string>): BundleReport {
  const errors: string[] = [];
  let bytes = 0;
  for (const [path, source] of Object.entries(files)) {
    bytes += Buffer.byteLength(source, "utf8");
    for (const { marker, what } of FORBIDDEN_BUNDLE_MARKERS) {
      if (marker.test(source)) errors.push(`${path}: bundle contains ${what} (TIO-GEN-002)`);
    }
  }
  if (bytes > BUNDLE_LIMIT_BYTES)
    errors.push(
      `bundle is ${bytes} bytes, over the ${BUNDLE_LIMIT_BYTES} byte budget (TIO-PERF-002)`,
    );
  return { bytes, errors };
}
