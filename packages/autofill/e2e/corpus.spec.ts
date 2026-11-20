import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { expect, test } from '@playwright/test';

import type { CorpusResult, GoldForm } from './harness/corpus.ts';
import { writeMetrics } from './metrics.ts';
import { PAGE_ORIGIN } from './ports.ts';
import { distScript } from './support.ts';

type Golden = Record<string, { forms: GoldForm[]; path: string; lang: string }>;

const here = dirname(fileURLToPath(import.meta.url));
const golden = JSON.parse(
  readFileSync(join(here, '..', 'corpus', 'golden.json'), 'utf8'),
) as Golden;
const LOGIN_KINDS = new Set(['login', 'username-only', 'password-only']);
const LOGIN_PURPOSES = new Set(['username', 'password']);
const MIN_PRECISION = 0.995;
const MIN_RECALL = 0.95;

test('corpus: login precision and recall gate, form kind accuracy', async ({ page }, info) => {
  await page.addInitScript(distScript('corpus'));
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let formsOk = 0;
  let formsTotal = 0;
  const misses: string[] = [];
  for (const [name, entry] of Object.entries(golden)) {
    await page.goto(`${PAGE_ORIGIN}/corpus${entry.path}/page.html?n=${name}`);
    const result: CorpusResult = await page.evaluate((g) => window.haspCorpus(g), {
      forms: entry.forms,
    });
    for (const f of result.forms) {
      formsTotal += 1;
      if (f.expected === f.predicted) formsOk += 1;
      else misses.push(`${name}: form ${f.expected} -> ${f.predicted}`);
    }
    for (const f of result.fields) {
      const goldLogin =
        LOGIN_PURPOSES.has(f.expected) && LOGIN_KINDS.has(entry.forms[0]?.kind ?? '');
      const predictedLogin = LOGIN_PURPOSES.has(f.predicted) && LOGIN_KINDS.has(f.predictedKind);
      if (goldLogin && predictedLogin && f.expected === f.predicted) tp += 1;
      else {
        if (goldLogin) {
          fn += 1;
          misses.push(`${name}: ${f.selector} ${f.expected} -> ${f.predicted}/${f.predictedKind}`);
        }
        if (predictedLogin) {
          fp += 1;
          misses.push(`${name}: ${f.selector} false login ${f.predicted}`);
        }
      }
    }
    for (const s of result.strays) {
      formsTotal += s.purpose === 'form' ? 1 : 0;
      if (s.purpose !== 'form' && LOGIN_KINDS.has(s.kind)) {
        fp += 1;
        misses.push(`${name}: stray ${s.purpose} in ${s.kind}`);
      } else if (s.purpose === 'form') {
        misses.push(`${name}: stray form ${s.kind}`);
      }
    }
  }
  const precision = tp / (tp + fp);
  const recall = tp / (tp + fn);
  const accuracy = formsOk / formsTotal;
  writeMetrics('corpus', info.project.name, {
    pages: Object.keys(golden).length,
    precision,
    recall,
    kindAccuracy: accuracy,
    tp,
    fp,
    fn,
    misses,
  });
  expect(precision).toBeGreaterThanOrEqual(MIN_PRECISION);
  expect(recall).toBeGreaterThanOrEqual(MIN_RECALL);
  expect(accuracy).toBeGreaterThanOrEqual(MIN_RECALL);
});
