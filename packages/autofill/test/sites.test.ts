import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { pageConfigFor, siteFileSchema } from '../src/sites/site-rule.ts';
import type { SiteEntry } from '../src/sites/site-rule.ts';

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '..', '..', '..', 'data', 'sites', 'hasp');
const files = readdirSync(dir).filter((f) => f.endsWith('.json'));

const entries: { file: string; entry: SiteEntry }[] = files.flatMap((file) => {
  const parsed = siteFileSchema.parse(JSON.parse(readFileSync(join(dir, file), 'utf8')));
  return parsed.entries.map((entry) => ({ file, entry }));
});

describe('data/sites/hasp', () => {
  it.each(files)('%s parses against the schema', (file) => {
    expect(() =>
      siteFileSchema.parse(JSON.parse(readFileSync(join(dir, file), 'utf8'))),
    ).not.toThrow();
  });

  it('has no duplicate match domains', () => {
    const seen = new Set<string>();
    for (const { entry } of entries) {
      const key = `${entry.match.domain}${entry.match.paths?.join(',') ?? ''}`;
      expect(seen.has(key)).toBe(false);
      seen.add(key);
    }
  });

  it('keeps related groups symmetric where both sides are listed', () => {
    const byDomain = new Map(entries.map(({ entry }) => [entry.match.domain, entry]));
    const asymmetric = entries.flatMap(({ entry }) =>
      (entry.related ?? []).flatMap((other) => {
        const peer = byDomain.get(other);
        return peer !== undefined && !(peer.related ?? []).includes(entry.match.domain)
          ? [`${entry.match.domain} -> ${other}`]
          : [];
      }),
    );
    expect(asymmetric).toEqual([]);
  });

  it('gives every entry at least one https source', () => {
    for (const { entry } of entries) {
      expect(entry.sources.length).toBeGreaterThan(0);
      for (const s of entry.sources) expect(s.startsWith('https://')).toBe(true);
    }
  });

  it('never lists the entry domain as related to itself', () => {
    for (const { entry } of entries) expect(entry.related ?? []).not.toContain(entry.match.domain);
  });
});

describe('page config lookup', () => {
  const dataset: SiteEntry[] = [
    {
      match: { domain: 'example.kr' },
      flow: { pages: [{ path: '/login', username: '#id', password: '#pw', advance: '#next' }] },
      quirks: { per_char_events: true, blocks_autofill: true },
      related: ['example.co.kr'],
      sources: ['https://example.kr/help'],
    },
  ];

  it('returns quirks, selectors and related domains for the page', () => {
    const config = pageConfigFor(dataset, 'example.kr', '/login/step1', { otp: '#code' });
    expect(config.quirks).toEqual({ per_char_events: true, blocks_autofill: true });
    expect(config.selectors).toEqual({ username: '#id', password: '#pw', advance: '#next' });
    expect(config.userSelectors).toEqual({ otp: '#code' });
    expect(config.relatedDomains).toEqual(['example.co.kr']);
  });

  it('returns an empty config for an unknown site', () => {
    expect(pageConfigFor(dataset, 'other.test', '/', {}).quirks).toEqual({});
  });
});
