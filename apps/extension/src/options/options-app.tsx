import { useCallback, useState } from 'react';
import type { ReactNode } from 'react';

import type { AppState, SettingsView } from '../messages/ui.ts';
import { spawn } from '../platform/spawn.ts';
import type { MessageKey } from '../shared/strings.ts';
import { callUi } from '../ui/client.ts';
import { LocaleProvider, useT } from '../ui/i18n.tsx';
import { OriginLine } from '../ui/origin-line.tsx';
import { useRemote } from '../ui/remote.ts';
import { Glyph, SecretTag, glyphCount } from '../ui/secret-tag.tsx';

const signOut = async (reload: () => void): Promise<void> => {
  await callUi({ kind: 'ui-sign-out' });
  reload();
};

const glyphIndexes = Array.from({ length: glyphCount }, (_unused, index) => index);

const glyphKey = (glyph: number): MessageKey => {
  switch (glyph) {
    case 0:
      return 'glyph.0';
    case 1:
      return 'glyph.1';
    case 2:
      return 'glyph.2';
    case 3:
      return 'glyph.3';
    case 4:
      return 'glyph.4';
    case 5:
      return 'glyph.5';
    case 6:
      return 'glyph.6';
    case 7:
      return 'glyph.7';
    case 8:
      return 'glyph.8';
    case 9:
      return 'glyph.9';
    case 10:
      return 'glyph.10';
    default:
      return 'glyph.11';
  }
};

type FormProps = { app: AppState; settings: SettingsView; onChanged: () => void };

const SettingsForm = ({ app, settings, onChanged }: FormProps): ReactNode => {
  const t = useT();
  const [word, setWord] = useState(settings.secretTag?.word ?? '');
  const [glyph, setGlyph] = useState(settings.secretTag?.glyph ?? 0);
  const [idle, setIdle] = useState(settings.lock.idleMinutes);
  const [clipboard, setClipboard] = useState(settings.lock.clipboardClearSeconds);
  const [lockSleep, setLockSleep] = useState(settings.lock.lockOnSleep);
  const [lockScreen, setLockScreen] = useState(settings.lock.lockOnScreenLock);
  const [isSaved, setIsSaved] = useState(false);

  const save = async (): Promise<void> => {
    const reply = await callUi({
      kind: 'ui-settings-set',
      patch: {
        lock: {
          ...settings.lock,
          idleMinutes: idle,
          clipboardClearSeconds: clipboard,
          lockOnSleep: lockSleep,
          lockOnScreenLock: lockScreen,
        },
        ...(word.trim() === '' ? {} : { secretTag: { word: word.trim().slice(0, 12), glyph } }),
      },
    });
    setIsSaved(reply.ok);
    onChanged();
  };

  return (
    <>
      <section data-testid="tag-section">
        <h2>{t('settings.tagTitle')}</h2>
        <p className="caption">{t('settings.tagBody')}</p>
        <div className="line">
          <label className="key" htmlFor="tag-word">
            {t('settings.tagWord')}
          </label>
          <label className="field">
            <input
              id="tag-word"
              value={word}
              maxLength={12}
              data-testid="tag-word"
              onChange={(event) => {
                setWord(event.target.value);
              }}
            />
          </label>
          <span className="caption num">{word.length}/12</span>
        </div>
        <div className="line">
          <span className="key">{t('settings.tagGlyph')}</span>
          <div className="glyphs" role="radiogroup" aria-label={t('settings.tagGlyph')}>
            {glyphIndexes.map((index) => (
              <button
                type="button"
                key={index}
                className="glyph"
                role="radio"
                aria-checked={glyph === index}
                aria-label={t(glyphKey(index))}
                data-testid={`glyph-${String(index)}`}
                onClick={() => {
                  setGlyph(index);
                }}
              >
                <Glyph glyph={index} />
              </button>
            ))}
          </div>
        </div>
        <div className="preview">
          <span className="caption">{t('settings.tagPreview')}</span>
          <SecretTag
            tag={{ word: word === '' ? ' ' : word, glyph }}
            label={t('settings.tagTitle')}
          />
          {app.server === undefined ? null : <OriginLine host={new URL(app.server).hostname} />}
        </div>
        <p className="caption">{t('settings.tagNote')}</p>
      </section>
      <section>
        <h2>{t('settings.lockPolicy')}</h2>
        <div className="line">
          <label className="key" htmlFor="idle">
            {t('settings.idle')}
          </label>
          <label className="field">
            <input
              id="idle"
              type="number"
              min={0}
              max={1440}
              value={idle}
              data-testid="idle-minutes"
              onChange={(event) => {
                setIdle(Number(event.target.value));
              }}
            />
          </label>
        </div>
        <div className="line">
          <label className="key" htmlFor="clip">
            {t('settings.clipboard')}
          </label>
          <label className="field">
            <input
              id="clip"
              type="number"
              min={0}
              max={600}
              value={clipboard}
              onChange={(event) => {
                setClipboard(Number(event.target.value));
              }}
            />
          </label>
        </div>
        <label className="line">
          <input
            type="checkbox"
            checked={lockSleep}
            onChange={(event) => {
              setLockSleep(event.target.checked);
            }}
          />
          {t('settings.lockSleep')}
        </label>
        <label className="line">
          <input
            type="checkbox"
            checked={lockScreen}
            onChange={(event) => {
              setLockScreen(event.target.checked);
            }}
          />
          {t('settings.lockScreen')}
        </label>
      </section>
      <div className="line">
        <button
          type="button"
          className="btn primary"
          data-testid="settings-save"
          onClick={() => {
            spawn(save());
          }}
        >
          {t('settings.save')}
        </button>
        {isSaved ? <span className="caption">{t('settings.saved')}</span> : null}
      </div>
    </>
  );
};

type PageProps = { app: AppState; reload: () => void };

const Page = ({ app, reload }: PageProps): ReactNode => {
  const t = useT();
  const load = useCallback(async (): Promise<SettingsView | undefined> => {
    if (app.account !== 'unlocked') return undefined;
    const reply = await callUi({ kind: 'ui-settings' });
    return reply.ok ? reply.value : undefined;
  }, [app.account]);
  const { state, reload: reloadSettings } = useRemote(load, 0);
  const settings = state.status === 'ready' ? state.value : undefined;
  return (
    <>
      <h1>{t('settings.title')}</h1>
      <section data-testid="account-section">
        <h2>{t('settings.server')}</h2>
        <p data-testid="server">{app.server ?? t('settings.notSignedIn')}</p>
        {app.login === undefined ? null : (
          <p className="caption">
            {t('settings.account')}: {app.login}
          </p>
        )}
        <div className="line">
          <span className="caption" data-testid="pairing">
            {t('settings.pairing')}: {app.isPaired ? t('settings.paired') : t('settings.notPaired')}
          </span>
        </div>
        {app.account === 'empty' ? null : (
          <div className="line">
            <button
              type="button"
              className="btn secondary"
              data-testid="sign-out"
              onClick={() => {
                spawn(signOut(reload));
              }}
            >
              {t('settings.signOut')}
            </button>
          </div>
        )}
      </section>
      {settings === undefined ? (
        app.account === 'empty' ? null : (
          <p className="caption">{t('settings.tagLocked')}</p>
        )
      ) : (
        <SettingsForm app={app} settings={settings} onChanged={reloadSettings} />
      )}
    </>
  );
};

const loadState = async (): Promise<AppState | undefined> => {
  const reply = await callUi({ kind: 'ui-state' });
  return reply.ok ? reply.value : undefined;
};

export const OptionsApp = (): ReactNode => {
  const { state, reload } = useRemote(loadState, 5000);
  if (state.status !== 'ready') return null;
  return (
    <LocaleProvider locale={state.value.locale}>
      <Page app={state.value} reload={reload} />
    </LocaleProvider>
  );
};
