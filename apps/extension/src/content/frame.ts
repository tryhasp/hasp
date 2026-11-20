import { createFrameBackground, mountMenuFrame } from '@hasp/autofill';

import { report } from '../platform/log.ts';
import { request } from '../platform/messaging.ts';

export const startMenuFrame = async (): Promise<void> => {
  const controller = new AbortController();
  await mountMenuFrame({
    win: window,
    background: createFrameBackground(request),
    nowMs: () => Date.now(),
    report,
    signal: controller.signal,
  });
};
