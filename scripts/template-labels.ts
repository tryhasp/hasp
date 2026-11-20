import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

type Localized = { en: string; ko: string };
type Template = {
  id: string;
  sections: { fields: { label: Localized }[] }[];
};

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const templates = join(root, 'crates/core/templates');
const output = join(root, 'apps/apple/App/Mac/Resources/TemplateLabels.xcstrings');

function parseTemplate(text: string): Template {
  const raw: unknown = JSON.parse(text);
  if (typeof raw !== 'object' || raw === null || !('id' in raw) || !('sections' in raw)) {
    throw new Error('a template needs an id and sections');
  }
  const { id, sections } = raw;
  if (typeof id !== 'string' || !Array.isArray(sections)) throw new Error('bad template');
  const checked: Template['sections'] = [];
  for (const section of sections as unknown[]) {
    if (typeof section !== 'object' || section === null || !('fields' in section)) continue;
    const fields: Template['sections'][number]['fields'] = [];
    for (const field of Array.isArray(section.fields) ? (section.fields as unknown[]) : []) {
      if (typeof field !== 'object' || field === null || !('label' in field)) continue;
      const { label } = field;
      if (typeof label !== 'object' || label === null) continue;
      if (!('en' in label) || !('ko' in label)) continue;
      if (typeof label.en === 'string' && typeof label.ko === 'string') {
        fields.push({ label: { en: label.en, ko: label.ko } });
      }
    }
    checked.push({ fields });
  }
  return { id, sections: checked };
}

function unit(value: string) {
  return { stringUnit: { state: 'translated', value } };
}

function render(): string {
  const strings: Record<string, unknown> = {};
  const add = (key: string, text: Localized) => {
    strings[key] = {
      extractionState: 'manual',
      localizations: { en: unit(text.en), ko: unit(text.ko) },
    };
  };
  for (const file of readdirSync(templates)
    .filter((name) => name.endsWith('.json'))
    .toSorted()) {
    const template = parseTemplate(readFileSync(join(templates, file), 'utf8'));
    for (const section of template.sections) {
      for (const field of section.fields) add(`${template.id}/${field.label.en}`, field.label);
    }
  }
  const sorted = Object.fromEntries(
    Object.entries(strings).toSorted(([a], [b]) => a.localeCompare(b)),
  );
  return `${JSON.stringify({ sourceLanguage: 'en', strings: sorted, version: '1.0' }, null, 2)}\n`;
}

const rendered = render();
if (process.argv.includes('--check')) {
  if (readFileSync(output, 'utf8') !== rendered) {
    process.stderr.write('TemplateLabels.xcstrings is stale: run mise run template-labels\n');
    process.exitCode = 1;
  }
} else {
  writeFileSync(output, rendered);
}
