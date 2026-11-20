import { useState } from 'react';
import type { ReactNode, SyntheticEvent } from 'react';

import type { UnlockResult } from '../messages/ui.ts';
import { spawn } from '../platform/spawn.ts';
import { requestOriginPermission } from '../platform/tabs.ts';
import { callUi } from '../ui/client.ts';
import { useT } from '../ui/i18n.tsx';
import { MarkIcon } from './lock-icon.tsx';

export type SignInScreenProps = { onChanged: () => void };

const originOf = (text: string): string | undefined => {
  try {
    return new URL(text.trim()).origin;
  } catch {
    return undefined;
  }
};

const normalized = (text: string): string => text.replaceAll(/[^0-9a-z]/gi, '').toLowerCase();

type Step = 'server' | 'fingerprint' | 'account';

export const SignInScreen = ({ onChanged }: SignInScreenProps): ReactNode => {
  const t = useT();
  const [server, setServer] = useState('');
  const [login, setLogin] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [password, setPassword] = useState('');
  const [step, setStep] = useState<Step>('server');
  const [shown, setShown] = useState('');
  const [typed, setTyped] = useState('');
  const [failure, setFailure] = useState<
    | 'signin.failed'
    | 'signin.pairFailed'
    | 'signin.permission'
    | 'signin.wrongFingerprint'
    | 'signin.fingerprintUnreachable'
    | undefined
  >(undefined);
  const [isBusy, setIsBusy] = useState(false);

  const finish = (result: UnlockResult, failedKey: 'signin.failed' | 'signin.pairFailed'): void => {
    setIsBusy(false);
    if (result.kind === 'done') {
      setPassword('');
      setSecretKey('');
      onChanged();
    } else if (result.kind === 'wrong-fingerprint') {
      setFailure('signin.wrongFingerprint');
    } else {
      setFailure(failedKey);
    }
  };

  const checkServer = async (): Promise<void> => {
    const origin = originOf(server);
    if (origin === undefined || !(await requestOriginPermission(origin))) {
      setIsBusy(false);
      setFailure('signin.permission');
      return;
    }
    const reply = await callUi({ kind: 'ui-server-fingerprint', server: origin });
    setIsBusy(false);
    if (!reply.ok) {
      setFailure('signin.fingerprintUnreachable');
      return;
    }
    setShown(reply.value.fingerprint);
    setTyped('');
    setStep('fingerprint');
  };

  const run = async (kind: 'sign-in' | 'pair'): Promise<void> => {
    const origin = originOf(server);
    if (origin === undefined || !(await requestOriginPermission(origin))) {
      setIsBusy(false);
      setFailure('signin.permission');
      return;
    }
    const reply =
      kind === 'sign-in'
        ? await callUi({
            kind: 'ui-sign-in',
            server: origin,
            login,
            secretKey,
            password,
            serverFingerprint: typed.trim(),
          })
        : await callUi({ kind: 'ui-pair-desktop', server: origin });
    finish(
      reply.ok ? reply.value : { kind: 'failed' },
      kind === 'sign-in' ? 'signin.failed' : 'signin.pairFailed',
    );
  };

  const handleNext = (event: SyntheticEvent): void => {
    event.preventDefault();
    setIsBusy(true);
    setFailure(undefined);
    spawn(checkServer());
  };

  const handleConfirm = (event: SyntheticEvent): void => {
    event.preventDefault();
    setFailure(undefined);
    setStep('account');
  };

  const handleSubmit = (event: SyntheticEvent): void => {
    event.preventDefault();
    setIsBusy(true);
    setFailure(undefined);
    spawn(run('sign-in'));
  };

  const handlePair = (): void => {
    setIsBusy(true);
    setFailure(undefined);
    spawn(run('pair'));
  };

  const goBack = (): void => {
    setFailure(undefined);
    setStep(step === 'account' ? 'fingerprint' : 'server');
  };

  const isSame = typed.trim() !== '' && normalized(typed) === normalized(shown);

  return (
    <main className="gate" data-testid="sign-in">
      <div className="mark">
        <MarkIcon />
      </div>
      <h1>{step === 'fingerprint' ? t('signin.fingerprintTitle') : t('signin.title')}</h1>
      {step === 'server' ? (
        <form onSubmit={handleNext}>
          <label className="field">
            <input
              value={server}
              placeholder={t('signin.server')}
              aria-label={t('signin.server')}
              data-testid="signin-server"
              onChange={(event) => {
                setServer(event.target.value);
              }}
            />
          </label>
          <button
            type="submit"
            className="btn primary"
            disabled={isBusy || server === ''}
            data-testid="signin-next"
          >
            {t('signin.next')}
          </button>
          <button
            type="button"
            className="btn secondary"
            disabled={isBusy || server === ''}
            onClick={handlePair}
            data-testid="signin-pair"
          >
            {t('signin.pair')}
          </button>
        </form>
      ) : null}
      {step === 'fingerprint' ? (
        <form onSubmit={handleConfirm}>
          <p className="caption">{t('signin.fingerprintBody')}</p>
          <p className="caption">{t('signin.fingerprintShown')}</p>
          <p className="fingerprint" data-testid="signin-fingerprint-shown">
            {shown}
          </p>
          <label className="field">
            <input
              value={typed}
              placeholder={t('signin.fingerprintTyped')}
              aria-label={t('signin.fingerprintTyped')}
              autoComplete="off"
              spellCheck={false}
              data-testid="signin-fingerprint"
              onChange={(event) => {
                setTyped(event.target.value);
              }}
            />
          </label>
          {typed === '' ? null : (
            <p className={isSame ? 'caption' : 'error'} data-testid="signin-fingerprint-state">
              {isSame ? t('signin.fingerprintSame') : t('signin.fingerprintDifferent')}
            </p>
          )}
          <button
            type="submit"
            className="btn primary"
            disabled={!isSame}
            data-testid="signin-confirm"
          >
            {t('signin.next')}
          </button>
          <button type="button" className="btn secondary" onClick={goBack}>
            {t('signin.back')}
          </button>
        </form>
      ) : null}
      {step === 'account' ? (
        <form onSubmit={handleSubmit}>
          <label className="field">
            <input
              value={login}
              placeholder={t('signin.login')}
              aria-label={t('signin.login')}
              autoComplete="off"
              data-testid="signin-login"
              onChange={(event) => {
                setLogin(event.target.value);
              }}
            />
          </label>
          <label className="field">
            <input
              type="password"
              value={secretKey}
              placeholder={t('signin.secretKey')}
              aria-label={t('signin.secretKey')}
              autoComplete="off"
              data-testid="signin-secret-key"
              onChange={(event) => {
                setSecretKey(event.target.value);
              }}
            />
          </label>
          <label className="field">
            <input
              type="password"
              value={password}
              placeholder={t('signin.password')}
              aria-label={t('signin.password')}
              autoComplete="off"
              data-testid="signin-password"
              onChange={(event) => {
                setPassword(event.target.value);
              }}
            />
          </label>
          <button
            type="submit"
            className="btn primary"
            disabled={isBusy}
            data-testid="signin-submit"
          >
            {t('signin.submit')}
          </button>
          <button type="button" className="btn secondary" onClick={goBack}>
            {t('signin.back')}
          </button>
        </form>
      ) : null}
      {failure === undefined ? null : (
        <p className="error" role="alert">
          {t(failure)}
        </p>
      )}
    </main>
  );
};
