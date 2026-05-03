import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Structural tests for the TypeScript CI workflow.
 *
 * The workflow file is consumed by GitHub Actions, not by application code, so
 * these tests parse the raw YAML text and assert on its shape. Every assertion
 * here corresponds to a published acceptance contract: the README docs:check
 * gate must run on every Node matrix version, after Test and before the
 * artifact upload, with no per-step working-directory override (it inherits
 * the job-level default of `ts`).
 */

const here = dirname(fileURLToPath(import.meta.url));
const WORKFLOW_PATH = resolve(here, '..', '..', '..', '.github', 'workflows', 'ts-ci.yml');

function loadWorkflow(): string {
  return readFileSync(WORKFLOW_PATH, 'utf8');
}

/**
 * Extract step blocks from the steps: list. A step block starts with
 * `      - name:` (6 spaces, dash, space) and continues until the next step
 * header or end-of-file. Returns the blocks in source order.
 */
function extractSteps(text: string): { name: string; block: string; startLine: number }[] {
  const lines = text.split('\n');
  const stepHeaderRe = /^ {6}- name:\s*(.+?)\s*$/;
  const steps: { name: string; block: string; startLine: number }[] = [];
  let current: { name: string; lines: string[]; startLine: number } | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const match = stepHeaderRe.exec(line);
    if (match) {
      if (current) {
        steps.push({
          name: current.name,
          block: current.lines.join('\n'),
          startLine: current.startLine,
        });
      }
      current = { name: match[1], lines: [line], startLine: i + 1 };
    } else if (current) {
      // A step ends when we reach a less-indented non-empty line that is not
      // part of the step (e.g., a sibling top-level key). All step content is
      // indented at least 8 spaces or is blank.
      const isStepContent = line === '' || /^ {8,}/.test(line) || /^ {6}[^-]/.test(line);
      if (isStepContent) {
        current.lines.push(line);
      } else {
        steps.push({
          name: current.name,
          block: current.lines.join('\n'),
          startLine: current.startLine,
        });
        current = null;
      }
    }
  }
  if (current) {
    steps.push({
      name: current.name,
      block: current.lines.join('\n'),
      startLine: current.startLine,
    });
  }
  return steps;
}

describe('TypeScript CI workflow — docs:check step', () => {
  it('declares a step named "Check README code blocks"', () => {
    const steps = extractSteps(loadWorkflow());
    const names = steps.map((s) => s.name);
    expect(names).toContain('Check README code blocks');
  });

  it('runs `npm run docs:check`', () => {
    const steps = extractSteps(loadWorkflow());
    const docsStep = steps.find((s) => s.name === 'Check README code blocks');
    expect(docsStep, 'docs:check step must be present').toBeDefined();
    expect(docsStep!.block).toMatch(/^ {8}run:\s*npm run docs:check\s*$/m);
  });

  it('is positioned after Test and before Upload dist', () => {
    const steps = extractSteps(loadWorkflow());
    const names = steps.map((s) => s.name);
    const testIdx = names.indexOf('Test');
    const docsIdx = names.indexOf('Check README code blocks');
    const uploadIdx = names.findIndex((n) => n.startsWith('Upload dist'));
    expect(testIdx, 'Test step must be present').toBeGreaterThanOrEqual(0);
    expect(docsIdx, 'docs:check step must be present').toBeGreaterThanOrEqual(0);
    expect(uploadIdx, 'Upload dist step must be present').toBeGreaterThanOrEqual(0);
    expect(docsIdx).toBeGreaterThan(testIdx);
    expect(uploadIdx).toBeGreaterThan(docsIdx);
  });

  it('does not override the job-level working-directory', () => {
    const steps = extractSteps(loadWorkflow());
    const docsStep = steps.find((s) => s.name === 'Check README code blocks');
    expect(docsStep).toBeDefined();
    expect(docsStep!.block).not.toMatch(/working-directory:/);
  });

  it('has no `if:` condition (runs on every matrix Node version)', () => {
    const steps = extractSteps(loadWorkflow());
    const docsStep = steps.find((s) => s.name === 'Check README code blocks');
    expect(docsStep).toBeDefined();
    expect(docsStep!.block).not.toMatch(/^ {8}if:/m);
  });

  it('inherits the job-level working-directory: ts default', () => {
    const text = loadWorkflow();
    expect(text).toMatch(/^ {4}defaults:\s*$/m);
    expect(text).toMatch(/^ {6}run:\s*$/m);
    expect(text).toMatch(/^ {8}working-directory:\s*ts\s*$/m);
  });

  it('paths filter on push covers ts/README.md via ts/** glob', () => {
    const text = loadWorkflow();
    const pushBlockMatch = /^ {2}push:\s*$([\s\S]*?)(?=^ {2}pull_request:|^[a-z])/m.exec(text);
    expect(pushBlockMatch, 'push: block must exist').not.toBeNull();
    expect(pushBlockMatch![1]).toMatch(/- 'ts\/\*\*'/);
  });

  it('paths filter on pull_request covers ts/README.md via ts/** glob', () => {
    const text = loadWorkflow();
    const prBlockMatch = /^ {2}pull_request:\s*$([\s\S]*?)(?=^[a-z])/m.exec(text);
    expect(prBlockMatch, 'pull_request: block must exist').not.toBeNull();
    expect(prBlockMatch![1]).toMatch(/- 'ts\/\*\*'/);
  });
});
