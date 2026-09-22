import { readFileSync, writeFileSync } from "node:fs";
import { HANDLE_TYPES } from "../src/crypto/handle-types.ts";
import { ROUTES } from "../src/router/routes.ts";
import {
  REVIEW_NOTICE,
  SURFACE_PATH,
  type Surface,
  surfaceDiff,
  surfaceOf,
} from "./lib/threat-surface.ts";

// Prints what changed in the surface behind the threat model (§15), and with
// `--write` records the current one as reviewed. The test of the same name
// fails the build on a difference; this script is how the difference is read
// and, after the review, accepted.

const current = surfaceOf({
  routes: ROUTES,
  handles: HANDLE_TYPES,
  spec: readFileSync("doc/TINY_OIDC_SPEC.md", "utf8"),
});

if (process.argv.includes("--write")) {
  writeFileSync(SURFACE_PATH, `${JSON.stringify(current, null, 2)}\n`);
  console.log(
    `surface: ${SURFACE_PATH} written (${current.routes.length} routes, ${current.handles.length} handle kinds, ${Object.keys(current.threats).length} threat rows)`,
  );
} else {
  const reviewed = JSON.parse(readFileSync(SURFACE_PATH, "utf8")) as Surface;
  const changes = surfaceDiff(reviewed, current);
  for (const line of changes) console.log(line);
  console.log(
    changes.length === 0
      ? `surface: unchanged (${current.routes.length} routes, ${current.handles.length} handle kinds, ${Object.keys(current.threats).length} threat rows)`
      : `\n${REVIEW_NOTICE}`,
  );
  if (changes.length > 0) process.exitCode = 1;
}
