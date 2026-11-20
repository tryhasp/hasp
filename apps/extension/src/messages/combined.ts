import { contentRequestSchema, frameRequestSchema } from '@hasp/autofill';
import { z } from 'zod';

import { uiRequestSchema } from './ui.ts';

export const backgroundRequestSchema = z.union([
  contentRequestSchema,
  frameRequestSchema,
  uiRequestSchema,
]);
export type BackgroundRequest = z.infer<typeof backgroundRequestSchema>;
