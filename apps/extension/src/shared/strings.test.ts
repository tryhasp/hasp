import { describe, expect, it } from 'vitest';

import { messages, translate } from './strings.ts';
import type { MessageKey } from './strings.ts';

const placeholders = (text: string): string[] =>
  [...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1] ?? '').toSorted();

describe('strings', () => {
  const keys = Object.keys(messages) as MessageKey[];

  it.each(keys)('%s has the same placeholders in Korean and English', (key) => {
    expect(placeholders(messages[key].ko)).toEqual(placeholders(messages[key].en));
    expect(messages[key].ko).not.toBe('');
    expect(messages[key].en).not.toBe('');
  });

  it('fills named placeholders', () => {
    expect(translate('en', 'popup.matches', { count: 3 })).toBe('3 match');
    expect(translate('ko', 'locked.retry', { seconds: 12 })).toBe(
      '12초 뒤에 다시 시도할 수 있어요',
    );
  });
});
