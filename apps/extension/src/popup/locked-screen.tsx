import { useState } from 'react';
import type { ReactNode, SyntheticEvent } from 'react';

import type { AppState, UnlockResult } from '../messages/ui.ts';
import { spawn } from '../platform/spawn.ts';
import { callUi } from '../ui/client.ts';
import { useT } from '../ui/i18n.tsx';
import { MarkIcon } from './lock-icon.tsx';

export type LockedScreenProps = { state: AppState; onChanged: () => void };

const failureKey = (result: UnlockResult): 'locked.wrong' | 'locked.failed' =>
  result.kind === 'wrong-password' ? 'locked.wrong' : 'locked.failed';

export const LockedScreen = ({ state, onChanged }: LockedScreenProps): ReactNode => {
  const t = useT();
  const [password, setPassword] = useState('');
  const [failure, setFailure] = useState<UnlockResult | undefined>(undefined);
  const [isBusy, setIsBusy] = useState(false);

  const finish = (result: UnlockResult): void => {
    setIsBusy(false);
    if (result.kind === 'done') {
      setPassword('');
      onChanged();
    } else {
      setFailure(result);
    }
  };

  const run = async (
    call: Promise<{ ok: true; value: UnlockResult } | { ok: false }>,
  ): Promise<void> => {
    setIsBusy(true);
    const reply = await call;
    finish(reply.ok ? reply.value : { kind: 'failed' });
  };

  const handleSubmit = (event: SyntheticEvent): void => {
    event.preventDefault();
    spawn(run(callUi({ kind: 'ui-unlock-password', password })));
  };

  const handleDesktop = (): void => {
    spawn(run(callUi({ kind: 'ui-unlock-desktop' })));
  };

  return (
    <main className="gate" data-testid="locked">
      <div className="mark">
        <MarkIcon />
      </div>
      <h1>{t('locked.title')}</h1>
      <p className="caption">
        {state.unlockMode === 'password-only' ? t('locked.passwordOnly') : t('locked.subtitle')}
      </p>
      <form onSubmit={handleSubmit}>
        <label className="field">
          <input
            type="password"
            value={password}
            autoFocus
            autoComplete="off"
            aria-label={t('locked.password')}
            data-testid="unlock-password"
            onChange={(event) => {
              setPassword(event.target.value);
            }}
          />
        </label>
        <button
          type="submit"
          className="btn primary"
          disabled={isBusy || password === '' || state.retryAfter > 0}
          data-testid="unlock-submit"
        >
          {t('locked.unlock')}
        </button>
        {state.isPaired ? (
          <button
            type="button"
            className="btn secondary"
            disabled={isBusy || !state.isDesktopAvailable}
            onClick={handleDesktop}
            data-testid="unlock-desktop"
          >
            {t('locked.desktop')}
          </button>
        ) : null}
      </form>
      {failure === undefined ? null : (
        <p className="error" role="alert">
          {failure.kind === 'locked-out'
            ? t('locked.retry', { seconds: failure.retryAfter })
            : t(failureKey(failure))}
        </p>
      )}
      {state.retryAfter > 0 ? (
        <p className="error" role="alert">
          {t('locked.retry', { seconds: state.retryAfter })}
        </p>
      ) : null}
    </main>
  );
};
