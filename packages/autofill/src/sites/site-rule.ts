import { z } from 'zod';

import type { FieldId } from '../brand.ts';
import type { PurposeOverrides } from '../classify/classify.ts';
import type { Natives } from '../snapshot/natives.ts';
import type { ElementRegistry } from '../snapshot/registry.ts';

const domainPattern = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const cssSchema = z.string().min(1).max(300);

export const selectorsSchema = z.strictObject({
  username: cssSchema.optional(),
  password: cssSchema.optional(),
  otp: cssSchema.optional(),
  advance: cssSchema.optional(),
});
export type Selectors = z.infer<typeof selectorsSchema>;

export const quirksSchema = z.strictObject({
  append_2fa: z.boolean().optional(),
  no_autosubmit: z.boolean().optional(),
  per_char_events: z.boolean().optional(),
  skip_save: z.boolean().optional(),
  iframe_login: z.boolean().optional(),
  blocks_autofill: z.boolean().optional(),
});
export type Quirks = z.infer<typeof quirksSchema>;

export const siteEntrySchema = z.strictObject({
  match: z.strictObject({
    domain: z.string().regex(domainPattern),
    paths: z.array(z.string().startsWith('/')).optional(),
  }),
  flow: z
    .strictObject({
      pages: z.array(selectorsSchema.extend({ path: z.string().startsWith('/') })),
    })
    .optional(),
  password_rules: z.string().optional(),
  change_password_url: z.string().startsWith('https://').optional(),
  quirks: quirksSchema.optional(),
  related: z.array(z.string().regex(domainPattern)).optional(),
  sources: z.array(z.string().startsWith('https://')).min(1),
});
export type SiteEntry = z.infer<typeof siteEntrySchema>;

export const siteFileSchema = z.strictObject({
  version: z.literal(1),
  entries: z.array(siteEntrySchema),
});

export const pageConfigSchema = z.strictObject({
  quirks: quirksSchema,
  selectors: selectorsSchema,
  userSelectors: selectorsSchema,
  passwordRules: z.string().optional(),
  relatedDomains: z.array(z.string()),
});
export type PageConfig = z.infer<typeof pageConfigSchema>;

export const emptyPageConfig: PageConfig = {
  quirks: {},
  selectors: {},
  userSelectors: {},
  relatedDomains: [],
};

const pathApplies = (entry: SiteEntry, pathname: string): boolean =>
  entry.match.paths === undefined || entry.match.paths.some((p) => pathname.startsWith(p));

export const pageConfigFor = (
  entries: readonly SiteEntry[],
  registrable: string,
  pathname: string,
  userSelectors: Selectors,
): PageConfig => {
  const entry = entries.find((e) => e.match.domain === registrable && pathApplies(e, pathname));
  if (entry === undefined) return { ...emptyPageConfig, userSelectors };
  const page = entry.flow?.pages.find((p) => pathname.startsWith(p.path));
  const selectors: Selectors = {};
  if (page?.username !== undefined) selectors.username = page.username;
  if (page?.password !== undefined) selectors.password = page.password;
  if (page?.otp !== undefined) selectors.otp = page.otp;
  if (page?.advance !== undefined) selectors.advance = page.advance;
  return {
    quirks: entry.quirks ?? {},
    selectors,
    userSelectors,
    ...(entry.password_rules === undefined ? {} : { passwordRules: entry.password_rules }),
    relatedDomains: entry.related ?? [],
  };
};

const pick = (
  natives: Natives,
  registry: ElementRegistry,
  root: Document,
  selector: string | undefined,
): FieldId | undefined => {
  if (selector === undefined) return undefined;
  try {
    const hit = natives.querySelectorAll(root, selector)[0];
    return hit === undefined ? undefined : registry.idOf(hit);
  } catch {
    return undefined;
  }
};

export const resolveOverrides = (
  natives: Natives,
  registry: ElementRegistry,
  root: Document,
  config: PageConfig,
): PurposeOverrides => {
  const merged: Selectors = { ...config.selectors, ...config.userSelectors };
  const overrides: PurposeOverrides = {};
  const username = pick(natives, registry, root, merged.username);
  const password = pick(natives, registry, root, merged.password);
  const otp = pick(natives, registry, root, merged.otp);
  if (username !== undefined) overrides.username = username;
  if (password !== undefined) overrides.password = password;
  if (otp !== undefined) overrides.otp = otp;
  return overrides;
};
