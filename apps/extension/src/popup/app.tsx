import type { ReactNode } from 'react';

import type { AppState } from '../messages/ui.ts';
import { callUi } from '../ui/client.ts';
import { LocaleProvider } from '../ui/i18n.tsx';
import { useRemote } from '../ui/remote.ts';
import { LockedScreen } from './locked-screen.tsx';
import { MainScreen } from './main-screen.tsx';
import { SignInScreen } from './sign-in-screen.tsx';

const loadState = async (): Promise<AppState | undefined> => {
  const reply = await callUi({ kind: 'ui-state' });
  return reply.ok ? reply.value : undefined;
};

export const App = (): ReactNode => {
  const { state, reload } = useRemote(loadState, 4000);
  if (state.status !== 'ready') return null;
  const app = state.value;
  return (
    <LocaleProvider locale={app.locale}>
      {app.account === 'empty' ? <SignInScreen onChanged={reload} /> : null}
      {app.account === 'locked' ? <LockedScreen state={app} onChanged={reload} /> : null}
      {app.account === 'unlocked' ? <MainScreen state={app} onChanged={reload} /> : null}
    </LocaleProvider>
  );
};
