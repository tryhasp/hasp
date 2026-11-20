import { useCallback } from 'react';
import type { ReactNode } from 'react';

import type { CodeView } from '../messages/ui.ts';
import { callUi } from '../ui/client.ts';
import { LocaleProvider, useT } from '../ui/i18n.tsx';
import { useRemote } from '../ui/remote.ts';

export type CodeAppProps = { id: string };

const Card = ({ view }: { view: CodeView }): ReactNode => {
  const t = useT();
  return (
    <main className="card" data-testid="code-card">
      <div className="head">
        <h1>{view.kind === 'pair' ? t('code.titlePair') : t('code.titleUnlock')}</h1>
      </div>
      <p className="body">{t('code.body')}</p>
      <div className="code-value" data-testid="code-value">
        {view.code}
      </div>
    </main>
  );
};

export const CodeApp = ({ id }: CodeAppProps): ReactNode => {
  const load = useCallback(async (): Promise<CodeView | undefined> => {
    const reply = await callUi({ kind: 'code-get', id });
    return reply.ok ? reply.value : undefined;
  }, [id]);
  const { state } = useRemote(load, 0);
  if (state.status !== 'ready') return null;
  return (
    <LocaleProvider locale={state.value.locale}>
      <Card view={state.value} />
    </LocaleProvider>
  );
};
