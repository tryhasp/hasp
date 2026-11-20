import { api } from './browser.ts';
import { pushToFrame } from './messaging.ts';

export type ActiveTab = { id: number; url: string | undefined; windowId: number };

export const activeTab = async (): Promise<ActiveTab | undefined> => {
  try {
    const [tab] = await api.tabs.query({ active: true, lastFocusedWindow: true });
    if (tab?.id === undefined) return undefined;
    return { id: tab.id, url: tab.url, windowId: tab.windowId };
  } catch {
    return undefined;
  }
};

export type TabFacts = { isActive: boolean; isWindowFocused: boolean };

export const tabFacts = async (tabId: number): Promise<TabFacts | undefined> => {
  try {
    const tab = await api.tabs.get(tabId);
    const window = await api.windows.get(tab.windowId);
    return { isActive: tab.active, isWindowFocused: window.focused };
  } catch {
    return undefined;
  }
};

export const isLastFocusedWindowFocused = async (): Promise<boolean> => {
  try {
    const window = await api.windows.getLastFocused();
    return window.focused;
  } catch {
    return false;
  }
};

export const pushToAllTabs = async (message: object): Promise<void> => {
  try {
    const tabs = await api.tabs.query({});
    await Promise.all(
      tabs.flatMap((tab) =>
        tab.id === undefined ? [] : [pushToFrame(tab.id, undefined, message)],
      ),
    );
  } catch {
    return;
  }
};

export const openConfirmWindow = async (id: string): Promise<boolean> => {
  try {
    const url = `${api.runtime.getURL('/confirm.html')}?id=${id}`;
    await api.windows.create({ url, type: 'popup', width: 452, height: 600, focused: true });
    return true;
  } catch {
    return false;
  }
};

export const openPasskeyWindow = async (id: string): Promise<number | undefined> => {
  try {
    const url = `${api.runtime.getURL('/passkey.html')}?id=${id}`;
    const created = await api.windows.create({
      url,
      type: 'popup',
      width: 452,
      height: 560,
      focused: true,
    });
    return created?.id;
  } catch {
    return undefined;
  }
};

export const openCodeWindow = async (id: string): Promise<number | undefined> => {
  try {
    const url = `${api.runtime.getURL('/code.html')}?id=${id}`;
    const created = await api.windows.create({
      url,
      type: 'popup',
      width: 452,
      height: 420,
      focused: true,
    });
    return created?.id;
  } catch {
    return undefined;
  }
};

export const onWindowClosed = (windowId: number, listener: () => void): (() => void) => {
  const handler = (closed: number): void => {
    if (closed === windowId) listener();
  };
  api.windows.onRemoved.addListener(handler);
  return () => {
    api.windows.onRemoved.removeListener(handler);
  };
};

export const closeWindow = async (windowId: number): Promise<void> => {
  try {
    await api.windows.remove(windowId);
  } catch {
    return;
  }
};

export const openOptionsPage = async (): Promise<void> => {
  await api.runtime.openOptionsPage();
};

export const closeThisWindow = async (): Promise<void> => {
  const current = await api.windows.getCurrent();
  if (current.id !== undefined) await api.windows.remove(current.id);
};

export const uiLocale = (): 'ko' | 'en' =>
  api.i18n.getUILanguage().startsWith('ko') ? 'ko' : 'en';

// Why: Firefox rejects a match pattern that carries a port; the permission then covers every port of the host
export const originPattern = (origin: string): string => {
  const url = new URL(origin);
  return `${url.protocol}//${url.hostname}/*`;
};

export const hasOriginPermission = async (origin: string): Promise<boolean> => {
  try {
    return await api.permissions.contains({ origins: [originPattern(origin)] });
  } catch {
    return false;
  }
};

export const requestOriginPermission = async (origin: string): Promise<boolean> => {
  try {
    return await api.permissions.request({ origins: [originPattern(origin)] });
  } catch {
    return false;
  }
};
