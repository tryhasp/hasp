import { installPasskeyHook } from '@hasp/autofill';
import { defineContentScript } from 'wxt/utils/define-content-script';

export default defineContentScript({
  matches: ['https://*/*', 'http://localhost/*'],
  allFrames: true,
  runAt: 'document_start',
  world: 'MAIN',
  exclude: ['safari'],
  main: () => {
    installPasskeyHook(window);
  },
});
