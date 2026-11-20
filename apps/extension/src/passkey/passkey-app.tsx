import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode, SyntheticEvent } from 'react';

import type { PasskeyView } from '../messages/ui.ts';
import { spawn } from '../platform/spawn.ts';
import { closeThisWindow } from '../platform/tabs.ts';
import { callUi } from '../ui/client.ts';
import { LocaleProvider, useT } from '../ui/i18n.tsx';
import { OriginLine } from '../ui/origin-line.tsx';
import { useRemote } from '../ui/remote.ts';
import { SecretTag } from '../ui/secret-tag.tsx';

export type PasskeyAppProps = { id: string };

type CardProps = { id: string; view: PasskeyView };

type Problem = 'passkey.wrong' | 'passkey.gone' | undefined;

const Card = ({ id, view }: CardProps): ReactNode => {
  const t = useT();
  const declineRef = useRef<HTMLButtonElement>(null);
  const [picked, setPicked] = useState(view.candidates[0]?.credentialId);
  const [password, setPassword] = useState('');
  const [problem, setProblem] = useState<Problem>(undefined);
  const [isBusy, setIsBusy] = useState(false);

  const decline = useCallback((): void => {
    const run = async (): Promise<void> => {
      await callUi({ kind: 'passkey-answer', id, choice: 'decline' });
      await closeThisWindow();
    };
    spawn(run());
  }, [id]);

  useEffect(() => {
    declineRef.current?.focus();
    const handleKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') decline();
    };
    window.addEventListener('keydown', handleKey);
    return () => {
      window.removeEventListener('keydown', handleKey);
    };
  }, [decline]);

  const use = (event: SyntheticEvent): void => {
    event.preventDefault();
    setIsBusy(true);
    setProblem(undefined);
    const run = async (): Promise<void> => {
      const reply = await callUi({
        kind: 'passkey-answer',
        id,
        choice: 'use',
        ...(picked === undefined ? {} : { credentialId: picked }),
        ...(view.reauth === 'password' && view.isReauthNeeded ? { password } : {}),
      });
      setIsBusy(false);
      if (!reply.ok || reply.value.status === 'expired') {
        setProblem('passkey.gone');
        return;
      }
      if (reply.value.status === 'ok') {
        setPassword('');
        await closeThisWindow();
        return;
      }
      setProblem('passkey.wrong');
    };
    spawn(run());
  };

  const isCreate = view.op === 'create';
  return (
    <main className="card" data-testid="passkey-card">
      <div className="top-line">
        {view.secretTag === undefined ? null : (
          <SecretTag tag={view.secretTag} label={t('settings.tagTitle')} />
        )}
      </div>
      <div className="head">
        <div className="warn-icon accent-icon" aria-hidden="true">
          P
        </div>
        <h1>{isCreate ? t('passkey.titleCreate') : t('passkey.titleGet')}</h1>
      </div>
      <p className="body">
        {t(isCreate ? 'passkey.bodyCreate' : 'passkey.bodyGet', { site: view.rpId })}
      </p>
      <div className="host-box current">
        <span className="label">{t('passkey.site')}</span>
        <OriginLine host={view.host} />
      </div>
      <form className="passkey-form" onSubmit={use}>
        {isCreate ? (
          <div className="what">
            <span className="label caption">{t('passkey.account')}</span>
            <div data-testid="passkey-account">{view.userName}</div>
          </div>
        ) : (
          <div className="passkey-list" role="radiogroup">
            {view.candidates.map((candidate) => (
              <button
                key={candidate.credentialId}
                type="button"
                role="radio"
                aria-checked={candidate.credentialId === picked}
                className="passkey-option"
                data-testid="passkey-option"
                onClick={() => {
                  setPicked(candidate.credentialId);
                }}
              >
                <span>
                  {candidate.displayName === '' ? candidate.userName : candidate.displayName}
                </span>
                <span className="caption">{candidate.title}</span>
              </button>
            ))}
          </div>
        )}
        {view.isReauthNeeded && view.reauth === 'password' ? (
          <>
            <p className="caption">{t('passkey.reauthPassword')}</p>
            <label className="field">
              <input
                type="password"
                value={password}
                placeholder={t('passkey.password')}
                aria-label={t('passkey.password')}
                autoComplete="off"
                data-testid="passkey-password"
                onChange={(event) => {
                  setPassword(event.target.value);
                }}
              />
            </label>
          </>
        ) : null}
        {view.isReauthNeeded && view.reauth === 'desktop' ? (
          <p className="caption">{t('passkey.reauthDesktop')}</p>
        ) : null}
        {problem === undefined ? null : (
          <p className="error" role="alert">
            {t(problem)}
          </p>
        )}
        <div className="buttons">
          <button
            ref={declineRef}
            type="button"
            className="btn ink"
            data-testid="passkey-decline"
            aria-keyshortcuts="Escape"
            onClick={decline}
          >
            {t('passkey.other')}
          </button>
          <button
            type="submit"
            className="btn secondary"
            disabled={isBusy || (!isCreate && picked === undefined)}
            data-testid="passkey-use"
          >
            {t(isCreate ? 'passkey.save' : 'passkey.use')}
          </button>
        </div>
      </form>
    </main>
  );
};

export const PasskeyApp = ({ id }: PasskeyAppProps): ReactNode => {
  const load = useCallback(async (): Promise<PasskeyView | undefined> => {
    const reply = await callUi({ kind: 'passkey-get', id });
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
