import { readKey, writeKey, removeKey } from '../platform/storage.ts';
import { openConfirmWindow } from '../platform/tabs.ts';
import { confirmCooldownKey, confirmKey } from './keys.ts';
import { randomHex } from './random.ts';

const CONFIRM_TTL_MS = 120_000;
const COOLDOWN_MS = 10_000;

export type ConfirmInput = {
  tabId: number;
  frameId: number;
  vault: string;
  item: string;
  title: string;
  subtitle: string;
  savedHost: string;
  currentHost: string;
  origin: string;
};

export const requestConfirm = async (input: ConfirmInput): Promise<void> => {
  const cooldown = await readKey(confirmCooldownKey(input.tabId));
  if (cooldown.ok && cooldown.value !== undefined && Date.now() - cooldown.value < COOLDOWN_MS)
    return;
  await writeKey(confirmCooldownKey(input.tabId), Date.now());
  const id = randomHex(16);
  await writeKey(confirmKey(id), { ...input, expiresMs: Date.now() + CONFIRM_TTL_MS });
  const opened = await openConfirmWindow(id);
  if (!opened) await removeKey(confirmKey(id));
};
