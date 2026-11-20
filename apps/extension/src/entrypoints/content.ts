import { defineContentScript } from 'wxt/utils/define-content-script';

import { startContent } from '../content/start.ts';
import { spawn } from '../platform/spawn.ts';

export default defineContentScript({
  matches: ['https://*/*', 'http://localhost/*'],
  allFrames: true,
  runAt: 'document_start',
  main: (context) => {
    spawn(startContent({ signal: context.signal }));
  },
});
