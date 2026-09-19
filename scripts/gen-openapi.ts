// Writes the committed OpenAPI 3.1 snapshot doc/openapi.json from the route
// definitions (spec §5.1, §14.1). CI regenerates it and fails on any diff.
import { writeFileSync } from "node:fs";
import { openApiDocument } from "../src/api/definitions.ts";

writeFileSync(
  "doc/openapi.json",
  `${JSON.stringify(openApiDocument(), null, 2)}
`,
);
console.log("gen-openapi: wrote doc/openapi.json");
