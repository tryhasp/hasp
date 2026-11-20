import type { CSSProperties, ReactNode } from 'react';

const hueOf = (text: string): number => {
  let hash = 0;
  for (const char of text) hash = (hash * 31 + (char.codePointAt(0) ?? 0)) % 360;
  return hash;
};

const initialOf = (text: string): string => {
  const code = text.codePointAt(0);
  return code === undefined ? '' : String.fromCodePoint(code).toUpperCase();
};

export type TileProps = { title: string; selected?: boolean };

export const Tile = ({ title, selected = false }: TileProps): ReactNode => {
  const hue = hueOf(title);
  const style: CSSProperties = {
    background: `hsl(${hue} var(--tile-background-saturation) var(--tile-background-lightness))`,
    color: `hsl(${hue} var(--tile-foreground-saturation) var(--tile-foreground-lightness))`,
  };
  const chosen: CSSProperties = {
    background: 'var(--color-accent)',
    color: 'var(--color-on-accent)',
  };
  return (
    <div className="tile" style={selected ? chosen : style} aria-hidden="true">
      {initialOf(title)}
    </div>
  );
};
