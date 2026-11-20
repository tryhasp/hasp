import { useCallback, useEffect, useRef } from 'react';
import type { ReactNode } from 'react';

import type { ConfirmView } from '../messages/ui.ts';
import { spawn } from '../platform/spawn.ts';
import { closeThisWindow } from '../platform/tabs.ts';
import { callUi } from '../ui/client.ts';
import { LocaleProvider, useT } from '../ui/i18n.tsx';
import { OriginLine } from '../ui/origin-line.tsx';
import { useRemote } from '../ui/remote.ts';
import { SecretTag } from '../ui/secret-tag.tsx';

export type ConfirmAppProps = { id: string };

type CardProps = { id: string; view: ConfirmView };

const Card = ({ id, view }: CardProps): ReactNode => {
  const t = useT();
  const cancelRef = useRef<HTMLButtonElement>(null);

  const answer = (approve: boolean): void => {
    const run = async (): Promise<void> => {
      await callUi({ kind: 'confirm-answer', id, approve });
      await closeThisWindow();
    };
    spawn(run());
  };

  useEffect(() => {
    cancelRef.current?.focus();
    const handleKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') answer(false);
    };
    window.addEventListener('keydown', handleKey);
    return () => {
      window.removeEventListener('keydown', handleKey);
    };
  });

  return (
    <main className="card" data-testid="confirm-card">
      <div className="top-line">
        {view.secretTag === undefined ? null : (
          <SecretTag tag={view.secretTag} label={t('settings.tagTitle')} />
        )}
      </div>
      <div className="head">
        <div className="warn-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" focusable="false">
            <path d="M12 4l9 16H3zM12 10v4M12 17v.01" />
          </svg>
        </div>
        <h1>{view.isSameHost ? t('confirm.titleFirst') : t('confirm.title')}</h1>
      </div>
      <p className="body">
        {t('confirm.body', { saved: view.savedHost, current: view.currentHost })}
      </p>
      <div className="host-box">
        <span className="label">{t('confirm.saved')}</span>
        <OriginLine host={view.savedHost} against={view.currentHost} />
      </div>
      <div className="host-box current">
        <span className="label">{t('confirm.current')}</span>
        <OriginLine host={view.currentHost} against={view.savedHost} />
      </div>
      <div className="what">
        <span className="label caption">{t('confirm.what')}</span>
        <div>
          {view.title} · {view.subtitle}
        </div>
      </div>
      <div className="buttons">
        <button
          ref={cancelRef}
          type="button"
          className="btn ink"
          autoFocus
          data-testid="confirm-cancel"
          aria-keyshortcuts="Escape"
          onClick={() => {
            answer(false);
          }}
        >
          {t('confirm.cancel')}
          <kbd>esc</kbd>
        </button>
        <button
          type="button"
          className="btn secondary"
          data-testid="confirm-fill"
          onClick={() => {
            answer(true);
          }}
        >
          {t('confirm.fill')}
        </button>
      </div>
    </main>
  );
};

export const ConfirmApp = ({ id }: ConfirmAppProps): ReactNode => {
  const load = useCallback(async (): Promise<ConfirmView | undefined> => {
    const reply = await callUi({ kind: 'confirm-get', id });
    return reply.ok ? reply.value : undefined;
  }, [id]);
  const { state } = useRemote(load, 0);
  if (state.status !== 'ready') return null;
  return (
    <LocaleProvider locale={state.value.locale}>
      <Card id={id} view={state.value} />
    </LocaleProvider>
  );
};
