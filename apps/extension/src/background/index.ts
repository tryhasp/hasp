import { backgroundRequestSchema } from '../messages/combined.ts';
import type { BackgroundRequest } from '../messages/combined.ts';
import { api, familyOf, targetBrowser } from '../platform/browser.ts';
import { CLIPBOARD_ALARM, clearClipboardWhenDue } from '../platform/clipboard.ts';
import { listen } from '../platform/messaging.ts';
import type { Handlers } from '../platform/messaging.ts';
import { watchDesktop as connectDesktop } from '../platform/native.ts';
import { spawn } from '../platform/spawn.ts';
import { readKey, protectSession, writeKey } from '../platform/storage.ts';
import { idleTick, lockNow, lockOnTrigger } from './account.ts';
import { contentHandlers, frameHandlers } from './autofill.ts';
import { openMenuOnActiveTab } from './command.ts';
import { activePageHost, fillOnActiveTab } from './desktop.ts';
import { deviceKey, tickCountKey } from './keys.ts';
import { createHints, runSync, watchEvents } from './sync.ts';
import type { Hints } from './sync.ts';
import { createUiHandlers } from './ui.ts';

const TICK_ALARM = 'hasp-tick';
const SYNC_EVERY_TICKS = 5;

const nextTick = async (): Promise<number> => {
  const stored = await readKey(tickCountKey);
  const next = (stored.ok && stored.value !== undefined ? stored.value : 0) + 1;
  await writeKey(tickCountKey, next);
  return next;
};

const tick = async (hints: Hints, watchDesktop: () => Promise<void>): Promise<void> => {
  const ticks = await nextTick();
  await clearClipboardWhenDue();
  await idleTick();
  await hints.ensure();
  await watchDesktop();
  if (ticks % SYNC_EVERY_TICKS === 0) await runSync();
};

export const startBackground = (): void => {
  const hints = createHints();
  const events = new AbortController();

  const desktop = { isWatching: false };
  const watchDesktop = async (): Promise<void> => {
    if (desktop.isWatching) return;
    const device = await readKey(deviceKey);
    if (!device.ok || device.value === undefined) return;
    desktop.isWatching = true;
    connectDesktop(
      {
        onLock: () => {
          spawn(lockNow());
        },
        onPageQuery: activePageHost,
        onFillRequest: fillOnActiveTab,
      },
      () => {
        desktop.isWatching = false;
      },
      events.signal,
    );
  };

  const afterUnlock = async (): Promise<void> => {
    await hints.ensure();
    await watchDesktop();
    spawn(watchEvents(events.signal));
    spawn(runSync());
  };

  const handlers: Handlers<BackgroundRequest> = {
    ...contentHandlers,
    ...frameHandlers,
    ...createUiHandlers({ afterUnlock }),
  };
  listen(backgroundRequestSchema, handlers);

  api.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === CLIPBOARD_ALARM) spawn(clearClipboardWhenDue());
    if (alarm.name === TICK_ALARM) spawn(tick(hints, watchDesktop));
  });

  api.commands.onCommand.addListener((command) => {
    if (command === 'open-menu') spawn(openMenuOnActiveTab());
  });

  if (familyOf(targetBrowser()) !== 'safari') {
    api.idle.onStateChanged.addListener((idleState) => {
      if (idleState === 'locked') spawn(lockOnTrigger('screen-lock'));
    });
  }

  const boot = async (): Promise<void> => {
    await protectSession();
    await api.alarms.create(TICK_ALARM, { periodInMinutes: 1 });
    await hints.ensure();
    await watchDesktop();
    await watchEvents(events.signal);
  };
  spawn(boot());

  api.runtime.onStartup.addListener(() => {
    spawn(lockNow());
  });
};
