import { readFileSync } from "node:fs";
import ts from "typescript";
import { describe, expect, it } from "vitest";

// The reference login app must run under the conformance suite's browser
// (TIO-TEST-041): HtmlUnit 4.17, whose JavaScript engine is a Rhino fork
// without async/await, classes, generators, spread or rest syntax, optional
// catch bindings, trailing commas in argument lists, the exponent operator,
// regular-expression flags beyond g/i/m, Promise.prototype.finally or the
// Fetch API (only an opt-in polyfill the suite does not enable), and whose
// loops share one `let`/`const` binding across iterations: a function made
// inside the loop sees the last value (every upstream button started the last
// upstream, nightly 2026-09-23 to 09-26). A syntax
// error there stops the whole script, so nothing would render. The nightly
// conformance run is the proof that the app works there; this test keeps the
// constraints from creeping back between runs.

const SOURCE = "examples/login-app/app.js";

interface Violation {
  line: number;
  what: string;
}

function violationsOf(text: string): Violation[] {
  const file = ts.createSourceFile(SOURCE, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const found: Violation[] = [];
  const report = (node: ts.Node, what: string) => {
    found.push({ line: file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1, what });
  };
  const isAsync = (node: ts.Node) =>
    ts.canHaveModifiers(node) &&
    (ts.getModifiers(node) ?? []).some((m) => m.kind === ts.SyntaxKind.AsyncKeyword);
  const guardedFetch = (node: ts.Node): boolean => {
    // `fetch` may only be named inside `if (typeof fetch === "function") { … }`.
    for (let up = node.parent; up; up = up.parent) {
      if (ts.isIfStatement(up) && up.expression.getText(file).includes("typeof fetch")) return true;
    }
    return false;
  };
  const isFunctionLike = (node: ts.Node) =>
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node);
  const namesOf = (name: ts.BindingName, into: Set<string>) => {
    if (ts.isIdentifier(name)) into.add(name.text);
    else for (const e of name.elements) if (!ts.isOmittedExpression(e)) namesOf(e.name, into);
  };
  const closureOverLoopBinding = (
    loop: ts.ForStatement | ts.ForOfStatement | ts.ForInStatement,
  ) => {
    const init = loop.initializer;
    if (init === undefined || !ts.isVariableDeclarationList(init)) return;
    if ((init.flags & (ts.NodeFlags.Let | ts.NodeFlags.Const)) === 0) return;
    const names = new Set<string>();
    for (const d of init.declarations) namesOf(d.name, names);
    const uses = (node: ts.Node): boolean =>
      (ts.isIdentifier(node) && names.has(node.text)) || (ts.forEachChild(node, uses) ?? false);
    const inBody = (node: ts.Node) => {
      if (isFunctionLike(node)) {
        if (uses(node)) report(node, "closure over a loop binding");
        return;
      }
      ts.forEachChild(node, inBody);
    };
    inBody(loop.statement);
  };
  const visit = (node: ts.Node) => {
    if (ts.isForStatement(node) || ts.isForOfStatement(node) || ts.isForInStatement(node))
      closureOverLoopBinding(node);
    if (
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node)
    ) {
      if (isAsync(node)) report(node, "async function");
      if (!ts.isArrowFunction(node) && node.asteriskToken) report(node, "generator function");
      if (node.parameters.hasTrailingComma) report(node, "trailing comma in a parameter list");
      for (const p of node.parameters) if (p.dotDotDotToken) report(p, "rest parameter");
    }
    if (ts.isAwaitExpression(node)) report(node, "await");
    if (ts.isForOfStatement(node) && node.awaitModifier) report(node, "for await");
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) report(node, "class");
    if (ts.isSpreadElement(node) || ts.isSpreadAssignment(node)) report(node, "spread");
    if (ts.isBindingElement(node) && node.dotDotDotToken) report(node, "rest in destructuring");
    if (ts.isCatchClause(node) && !node.variableDeclaration)
      report(node, "catch without a binding");
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node) || ts.isExportAssignment(node))
      report(node, "module syntax");
    if ((ts.isCallExpression(node) || ts.isNewExpression(node)) && node.arguments?.hasTrailingComma)
      report(node, "trailing comma in an argument list");
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword)
      report(node, "dynamic import");
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.AsteriskAsteriskToken
    )
      report(node, "exponent operator");
    if (ts.isRegularExpressionLiteral(node)) {
      const flags = node.text.slice(node.text.lastIndexOf("/") + 1);
      if (/[^gim]/.test(flags)) report(node, `regular-expression flag "${flags}"`);
    }
    if (ts.isIdentifier(node) && node.text === "fetch" && !guardedFetch(node))
      report(node, "fetch outside its typeof guard");
    if (ts.isPropertyAccessExpression(node) && node.name.text === "finally")
      report(node, "Promise.prototype.finally");
    ts.forEachChild(node, visit);
  };
  visit(file);
  return found;
}

describe("reference login app under the conformance suite's browser (TIO-TEST-041)", () => {
  it("[TIO-TEST-041] examples/login-app/app.js uses no syntax or API HtmlUnit's Rhino lacks (async/await, classes, generators, spread, rest, bare catch, trailing argument commas, unguarded fetch, closures over loop bindings)", () => {
    const text = readFileSync(SOURCE, "utf8");
    expect(violationsOf(text)).toEqual([]);
    // The fallback transport exists, and fetch is only used behind its guard.
    expect(text).toContain("new XMLHttpRequest()");
    expect(text).toContain('typeof fetch === "function"');
  });

  it("the checker sees each forbidden construct", () => {
    const cases: [string, string][] = [
      ["async function f() {}", "async function"],
      ["const f = async () => 1;", "async function"],
      ["function f() { return g().then(async (x) => x); }", "async function"],
      ["function* g() {}", "generator function"],
      ["class A {}", "class"],
      ["const a = [1, ...b];", "spread"],
      ["const o = { ...p };", "spread"],
      ["f(...args);", "spread"],
      ["function f(...rest) {}", "rest parameter"],
      ["const [a, ...b] = c;", "rest in destructuring"],
      ["try { f(); } catch { g(); }", "catch without a binding"],
      ["f(a, b,);", "trailing comma in an argument list"],
      ["function f(a, b,) {}", "trailing comma in a parameter list"],
      ["const x = 2 ** 3;", "exponent operator"],
      ["const r = /a.b/s;", 'regular-expression flag "s"'],
      ["const r = /a/u;", 'regular-expression flag "u"'],
      ["fetch(url);", "fetch outside its typeof guard"],
      ["p.finally(() => 1);", "Promise.prototype.finally"],
      ["import x from 'y';", "module syntax"],
      ["const m = import('y');", "dynamic import"],
      ["for (const u of us) { b.on('click', () => go(u)); }", "closure over a loop binding"],
      [
        "for (let i = 0; i < n; i++) { f(function () { return i; }); }",
        "closure over a loop binding",
      ],
      ["for (const { a } of xs) { g(() => a); }", "closure over a loop binding"],
    ];
    for (const [snippet, what] of cases) {
      expect(
        violationsOf(snippet).map((v) => v.what),
        snippet,
      ).toContain(what);
    }
    // What the engine does have stays allowed.
    const allowed = [
      "const f = (a = 1) => `x${a}`;",
      "const { a, b } = c; const [d] = e;",
      "const v = o?.p ?? 2; for (const x of xs) {} let y = 0;",
      'if (typeof fetch === "function") { fetch(u).then((r) => r.json()); }',
      "const r = /a/gim; try { f(); } catch (e) { g(e); }",
      "const o = { a, b() {}, get c() { return 1; } };",
      "Object.assign({}, a, { b: 1 }); Array.from(list).map((x) => x);",
      "us.forEach(function (u) { b.on('click', () => go(u)); });",
      "for (const b of bs) { b.disabled = true; } for (const u of us) { f(() => other); }",
    ];
    for (const snippet of allowed) expect(violationsOf(snippet), snippet).toEqual([]);
  });
});
