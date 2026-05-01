#!/usr/bin/env node
// docs:check — extract every ts/typescript fenced block from ts/README.md,
// write them as standalone files under ts/.docs-check/, and run `tsc --noEmit`
// against them using a tsconfig that EXTENDS the project's ts/tsconfig.json.
//
// Pure Node stdlib only (fs, path, child_process, url). The project tsconfig
// is the single source of truth for compiler options — the generated config
// only overrides `include` so tsc sees the extracted blocks.
//
// Exit codes:
//   0  — all blocks compiled cleanly; .docs-check/ is removed
//   1  — at least one block failed; .docs-check/ is preserved for inspection
//   2  — preconditions not met (e.g., dist/ missing)

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const TS_DIR = resolve(SCRIPT_DIR, "..");
const README_PATH = resolve(TS_DIR, "README.md");
const DIST_DIR = resolve(TS_DIR, "dist");
const DOCS_CHECK_DIR = resolve(TS_DIR, ".docs-check");
const TSCONFIG_PATH = resolve(DOCS_CHECK_DIR, "tsconfig.json");

// Extract every ```ts or ```typescript fenced block from markdown.
// Returns an array of block bodies in document order.
function extractBlocks(markdown) {
  const blocks = [];
  const fenceRe = /^```(ts|typescript)\s*\n([\s\S]*?)^```/gm;
  let match;
  while ((match = fenceRe.exec(markdown)) !== null) {
    blocks.push(match[2]);
  }
  return blocks;
}

// Parse tsc diagnostic output and group error lines by block-N.ts file name.
// Diagnostics look like:  block-3.ts(12,5): error TS2304: Cannot find name 'foo'.
function groupErrorsByBlock(tscOutput, blockCount) {
  const counts = new Map();
  for (let i = 1; i <= blockCount; i++) {
    counts.set(`block-${i}.ts`, 0);
  }
  if (!tscOutput) return counts;
  const diagRe = /(^|[\s/\\])(block-\d+\.ts)\(/gm;
  let match;
  while ((match = diagRe.exec(tscOutput)) !== null) {
    const file = match[2];
    if (counts.has(file)) {
      counts.set(file, counts.get(file) + 1);
    }
  }
  return counts;
}

function main() {
  if (!existsSync(README_PATH)) {
    console.error(`docs:check: README not found at ${README_PATH}`);
    process.exit(2);
  }

  if (!existsSync(DIST_DIR)) {
    console.error("docs:check: dist/ not found — run 'npm run build' first");
    process.exit(2);
  }

  const markdown = readFileSync(README_PATH, "utf8");
  const blocks = extractBlocks(markdown);

  if (blocks.length === 0) {
    console.log("docs:check: no ts/typescript code blocks found in README.md");
    process.exit(0);
  }

  // Always start from a clean .docs-check/ to avoid stale block files when
  // the README has fewer blocks than a previous run.
  if (existsSync(DOCS_CHECK_DIR)) {
    rmSync(DOCS_CHECK_DIR, { recursive: true, force: true });
  }
  mkdirSync(DOCS_CHECK_DIR, { recursive: true });

  blocks.forEach((body, idx) => {
    const filePath = resolve(DOCS_CHECK_DIR, `block-${idx + 1}.ts`);
    writeFileSync(filePath, body, "utf8");
  });

  // The project tsconfig pins rootDir to ./src, which would make tsc reject
  // the extracted blocks under .docs-check/ with TS6059. We override rootDir
  // (and disable emit) only to make the include path resolve — every strict
  // check (strict, noUnusedLocals, noUnusedParameters, verbatimModuleSyntax,
  // etc.) is inherited unchanged from ../tsconfig.json.
  const tsconfig = {
    extends: "../tsconfig.json",
    compilerOptions: {
      rootDir: ".",
      noEmit: true,
    },
    include: ["./block-*.ts"],
  };
  writeFileSync(TSCONFIG_PATH, `${JSON.stringify(tsconfig, null, 2)}\n`, "utf8");

  console.log(`docs:check: extracted ${blocks.length} block(s) to .docs-check/`);

  const result = spawnSync(
    "npx",
    ["tsc", "--noEmit", "-p", ".docs-check/tsconfig.json"],
    {
      cwd: TS_DIR,
      stdio: "pipe",
      encoding: "utf8",
      shell: process.platform === "win32",
    },
  );

  const combinedOutput = `${result.stdout || ""}${result.stderr || ""}`;
  const errorCounts = groupErrorsByBlock(combinedOutput, blocks.length);

  let failed = 0;
  console.log("");
  for (let i = 1; i <= blocks.length; i++) {
    const name = `block-${i}.ts`;
    const errs = errorCounts.get(name) ?? 0;
    if (errs === 0) {
      console.log(`  ${name}: PASS`);
    } else {
      failed++;
      console.log(`  ${name}: FAIL (${errs} error${errs === 1 ? "" : "s"})`);
    }
  }
  console.log("");

  // tsc may emit errors that aren't tied to a specific block file (e.g., a
  // tsconfig-level problem). If tsc exited non-zero but every block looked
  // clean, treat it as a failure and dump tsc output so the developer can see.
  const tscFailed = result.status !== 0;
  const overallFailed = failed > 0 || tscFailed;

  if (overallFailed) {
    if (combinedOutput.trim().length > 0) {
      console.log("--- tsc output ---");
      console.log(combinedOutput.trim());
      console.log("------------------");
    }
    console.error(
      `docs:check: ${failed} of ${blocks.length} block(s) failed. .docs-check/ preserved for inspection.`,
    );
    console.error(
      `Run manually: npx tsc --noEmit -p .docs-check/tsconfig.json (from ${TS_DIR})`,
    );
    process.exit(1);
  }

  rmSync(DOCS_CHECK_DIR, { recursive: true, force: true });
  console.log(`docs:check: all ${blocks.length} block(s) passed.`);
  process.exit(0);
}

main();
