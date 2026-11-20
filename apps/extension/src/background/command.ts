import { pushToFrame } from '../platform/messaging.ts';
import { activeTab } from '../platform/tabs.ts';

export const openMenuOnActiveTab = async (): Promise<void> => {
  const tab = await activeTab();
  if (tab === undefined) return;
  await pushToFrame(tab.id, 0, { kind: 'open-menu' });
};
