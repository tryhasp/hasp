import { glyphPaths } from '@hasp/autofill/glyphs';
import type { ReactNode } from 'react';

import type { SecretTagView } from '../messages/ui.ts';

export const glyphCount = glyphPaths.length;

export type GlyphProps = { glyph: number };

export const Glyph = ({ glyph }: GlyphProps): ReactNode => (
  <svg viewBox="0 0 12 12" aria-hidden="true" focusable="false">
    <path d={glyphPaths[glyph] ?? glyphPaths[0]} fillRule="evenodd" />
  </svg>
);

export type SecretTagProps = { tag: SecretTagView; label: string };

export const SecretTag = ({ tag, label }: SecretTagProps): ReactNode => (
  <span className="tag" title={label} data-testid="secret-tag">
    <Glyph glyph={tag.glyph} />
    {tag.word}
  </span>
);
