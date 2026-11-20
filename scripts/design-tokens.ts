import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import raw from '../design/tokens.json' with { type: 'json' };

type ColorValue = string | { hex: string; alpha: number };
type Colors = Record<string, ColorValue>;
type Tone = Record<string, number>;
type TextRole = {
  size: number;
  weight: string;
  lineHeight: number;
  letterSpacing: number;
  family: string;
  tabularNums: boolean;
};
type Duration = { milliseconds?: number; seconds?: number };
type Tokens = {
  color: { light: Colors; dark: Colors; fixed: Colors };
  tile: { light: Tone; dark: Tone };
  font: {
    family: Record<string, string[]>;
    weight: Record<string, number>;
    pretendard: { file: string; weightMin: number; weightMax: number };
  };
  type: Record<string, TextRole>;
  space: Tone;
  radius: Tone;
  border: Tone;
  size: Tone;
  motion: Record<string, Duration>;
};

const tokens: Tokens = raw;
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const swiftPath = 'apps/apple/Packages/Hasp/Sources/HaspDesign/Tokens.swift';
const cssPath = 'packages/design/tokens.css';

const kebab = (name: string): string => name.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
const hexOf = (value: ColorValue): string => (typeof value === 'string' ? value : value.hex);
const alphaOf = (value: ColorValue): number => (typeof value === 'string' ? 1 : value.alpha);
const durationMs = (value: Duration): number =>
  value.milliseconds ?? (value.seconds === undefined ? 0 : value.seconds * 1000);

function cssColor(value: ColorValue): string {
  const hex = hexOf(value);
  const alpha = alphaOf(value);
  if (alpha === 1) return hex;
  const channels = [1, 3, 5].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16));
  return `rgb(${channels.join(' ')} / ${alpha})`;
}

function cssFamily(names: string[]): string {
  return names.map((name) => (name.includes(' ') ? `"${name}"` : name)).join(', ');
}

function cssDeclarations(prefix: string, values: Tone, unit: string): string[] {
  return Object.entries(values).map(
    ([key, value]) => `  --${prefix}-${kebab(key)}: ${value}${unit};`,
  );
}

function cssLightBlock(): string {
  const lines: string[] = [];
  const { color, tile, font } = tokens;
  for (const [key, value] of Object.entries(color.light)) {
    lines.push(`  --color-${kebab(key)}: ${cssColor(value)};`);
  }
  for (const [key, value] of Object.entries(color.fixed)) {
    lines.push(`  --color-${kebab(key)}: ${cssColor(value)};`);
  }
  lines.push(...cssDeclarations('tile', tile.light, '%'));
  for (const [key, names] of Object.entries(font.family)) {
    lines.push(`  --font-family-${key}: ${cssFamily(names)};`);
  }
  lines.push(...cssDeclarations('font-weight', font.weight, ''));
  for (const [role, spec] of Object.entries(tokens.type)) {
    const name = `type-${kebab(role)}`;
    const letterSpacing = spec.letterSpacing === 0 ? '0' : `${spec.letterSpacing}em`;
    lines.push(
      `  --${name}-size: ${spec.size}px;`,
      `  --${name}-weight: ${font.weight[spec.weight] ?? 0};`,
      `  --${name}-line-height: ${spec.lineHeight};`,
      `  --${name}-letter-spacing: ${letterSpacing};`,
      `  --${name}-family: var(--font-family-${spec.family});`,
      `  --${name}-numeric: ${spec.tabularNums ? 'tabular-nums' : 'normal'};`,
    );
  }
  lines.push(...cssDeclarations('space', tokens.space, 'px'));
  lines.push(...cssDeclarations('radius', tokens.radius, 'px'));
  lines.push(...cssDeclarations('border', tokens.border, 'px'));
  lines.push(...cssDeclarations('size', tokens.size, 'px'));
  for (const [key, value] of Object.entries(tokens.motion)) {
    lines.push(`  --motion-${kebab(key)}: ${durationMs(value)}ms;`);
  }
  return `:root {\n${lines.join('\n')}\n}`;
}

function cssDarkBlock(): string {
  const lines = Object.entries(tokens.color.dark).map(
    ([key, value]) => `  --color-${kebab(key)}: ${cssColor(value)};`,
  );
  lines.push(...cssDeclarations('tile', tokens.tile.dark, '%'));
  return `:root.dark {\n${lines.join('\n')}\n}`;
}

function renderCss(): string {
  return `${cssLightBlock()}\n\n${cssDarkBlock()}\n`;
}

function swiftRGBA(value: ColorValue): string {
  const hex = `0x${hexOf(value).slice(1).toLowerCase()}`;
  const alpha = alphaOf(value);
  return alpha === 1 ? `HaspRGBA(${hex})` : `HaspRGBA(${hex}, alpha: ${alpha})`;
}

function swiftEnum(name: string, members: string[]): string {
  return `public enum ${name} {\n${members.map((line) => `  ${line}`).join('\n')}\n}\n`;
}

function swiftCGFloats(name: string, values: Tone): string {
  return swiftEnum(
    name,
    Object.entries(values).map(([key, value]) => `public static let ${key}: CGFloat = ${value}`),
  );
}

const swiftWeights: Record<string, string> = {
  regular: '.regular',
  medium: '.medium',
  semibold: '.semibold',
  bold: '.bold',
};

function swiftTextStyle(spec: TextRole): string {
  const weight = swiftWeights[spec.weight] ?? '.regular';
  return `HaspTextStyle(size: ${spec.size}, weight: ${weight}, lineHeight: ${spec.lineHeight}, letterSpacing: ${spec.letterSpacing}, monospaced: ${spec.family === 'mono'}, tabularNums: ${spec.tabularNums})`;
}

function swiftTone(tone: Tone): string {
  const fraction = (key: string): number => (tone[key] ?? 0) / 100;
  return `HaspTileTone(backgroundSaturation: ${fraction('backgroundSaturation')}, backgroundLightness: ${fraction('backgroundLightness')}, foregroundSaturation: ${fraction('foregroundSaturation')}, foregroundLightness: ${fraction('foregroundLightness')})`;
}

function swiftDuration(value: Duration): string {
  return value.milliseconds === undefined
    ? `.seconds(${value.seconds ?? 0})`
    : `.milliseconds(${value.milliseconds})`;
}

function renderSwift(): string {
  const { color, tile } = tokens;
  const pairs = Object.keys(color.light).map(
    (key) =>
      `public static let ${key} = HaspColorPair(light: ${swiftRGBA(color.light[key] ?? '#000000')}, dark: ${swiftRGBA(color.dark[key] ?? '#000000')})`,
  );
  const dynamic = Object.keys(color.light).map(
    (key) => `public static let ${key} = Color(HaspColorValues.${key})`,
  );
  const fixed = Object.entries(color.fixed).map(
    ([key, value]) => `public static let ${key} = Color(${swiftRGBA(value)})`,
  );
  const fonts = Object.entries(tokens.type).map(
    ([key, spec]) => `public static let ${key} = ${swiftTextStyle(spec)}`,
  );
  const motion = Object.entries(tokens.motion).map(
    ([key, value]) => `public static let ${key}: Duration = ${swiftDuration(value)}`,
  );
  const sections = [
    'public import SwiftUI\n',
    swiftEnum('HaspColorValues', pairs),
    swiftEnum('HaspColor', [...dynamic, ...fixed]),
    swiftEnum('HaspTile', [
      `public static let light = ${swiftTone(tile.light)}`,
      `public static let dark = ${swiftTone(tile.dark)}`,
    ]),
    swiftEnum('HaspFont', fonts),
    swiftCGFloats('HaspSpace', tokens.space),
    swiftCGFloats('HaspRadius', tokens.radius),
    swiftCGFloats('HaspBorder', tokens.border),
    swiftCGFloats('HaspSize', tokens.size),
    swiftEnum('HaspMotion', motion),
  ];
  return sections.join('\n');
}

function write(base: string, relative: string, contents: string): void {
  const target = resolve(base, relative);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, contents);
}

function formatSwift(base: string): void {
  const result = spawnSync(
    'swift',
    [
      'format',
      'format',
      '--in-place',
      '--configuration',
      resolve(root, 'apps/apple/.swift-format'),
      resolve(base, swiftPath),
    ],
    { stdio: 'inherit' },
  );
  if (result.status !== 0) {
    throw new Error('swift format failed');
  }
}

function generate(base: string): void {
  write(base, cssPath, renderCss());
  write(base, swiftPath, renderSwift());
  formatSwift(base);
}

function check(): void {
  const scratch = mkdtempSync(join(tmpdir(), 'hasp-design-'));
  try {
    generate(scratch);
    const drifted = [cssPath, swiftPath].filter(
      (relative) =>
        readFileSync(resolve(scratch, relative), 'utf8') !==
        readFileSync(resolve(root, relative), 'utf8'),
    );
    if (drifted.length > 0) {
      process.stderr.write(
        `design tokens out of date, run mise run design-tokens: ${drifted.join(', ')}\n`,
      );
      process.exitCode = 1;
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv.includes('--check')) {
  check();
} else {
  generate(root);
}
