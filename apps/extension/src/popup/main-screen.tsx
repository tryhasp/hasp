import { useCallback, useState } from 'react';
import type { ReactNode } from 'react';

import type { AppState, CurrentSite, GeneratedView, ItemView } from '../messages/ui.ts';
import { spawn } from '../platform/spawn.ts';
import { openOptionsPage } from '../platform/tabs.ts';
import { callUi } from '../ui/client.ts';
import { useT } from '../ui/i18n.tsx';
import { OriginLine } from '../ui/origin-line.tsx';
import { useRemote } from '../ui/remote.ts';
import { SecretTag } from '../ui/secret-tag.tsx';
import { ItemRow } from './item-row.tsx';
import type { CopyField } from './item-row.tsx';
import { LockIcon } from './lock-icon.tsx';

export type MainScreenProps = { state: AppState; onChanged: () => void };

const loadSite = async (): Promise<CurrentSite | undefined> => {
  const reply = await callUi({ kind: 'ui-current-site' });
  return reply.ok ? reply.value : undefined;
};

const loadGenerated = async (): Promise<GeneratedView[] | undefined> => {
  const reply = await callUi({ kind: 'ui-generated' });
  return reply.ok ? reply.value : undefined;
};

const fillItem = async (item: ItemView): Promise<void> => {
  await callUi({ kind: 'ui-fill', vault: item.vault, item: item.id });
  window.close();
};

const TOAST_MS = 2500;

const handleFill = (item: ItemView): void => {
  spawn(fillItem(item));
};

export const MainScreen = ({ state, onChanged }: MainScreenProps): ReactNode => {
  const t = useT();
  const [text, setText] = useState('');
  const [toast, setToast] = useState<string | undefined>(undefined);
  const loadResults = useCallback(async (): Promise<ItemView[] | undefined> => {
    const reply = await callUi({ kind: 'ui-search', text });
    return reply.ok ? reply.value : undefined;
  }, [text]);
  const found = useRemote(loadResults, 0);
  const site = useRemote(loadSite, 0);
  const generated = useRemote(loadGenerated, 3000);

  const showToast = (message: string): void => {
    setToast(message);
    setTimeout(() => {
      setToast(undefined);
    }, TOAST_MS);
  };

  const copyWith = async (
    call: Promise<{ ok: true; value: { clearAfterSeconds: number } } | { ok: false }>,
  ): Promise<void> => {
    const reply = await call;
    if (reply.ok) showToast(t('popup.copied', { seconds: reply.value.clearAfterSeconds }));
  };

  const handleCopy = (item: ItemView, field: CopyField): void => {
    spawn(copyWith(callUi({ kind: 'ui-copy', vault: item.vault, item: item.id, field })));
  };

  const handleCopyGenerated = (id: string): void => {
    spawn(copyWith(callUi({ kind: 'ui-copy-generated', id })));
  };

  const lock = async (): Promise<void> => {
    await callUi({ kind: 'ui-lock' });
    onChanged();
  };

  const sync = async (): Promise<void> => {
    await callUi({ kind: 'ui-sync' });
    site.reload();
    found.reload();
  };

  const matches = site.state.status === 'ready' ? site.state.value : undefined;
  const generatedItems = generated.state.status === 'ready' ? generated.state.value : [];
  const results = found.state.status === 'ready' ? found.state.value : [];
  const isSearching = text.trim() !== '';

  return (
    <>
      <header className="header">
        {state.secretTag === undefined ? null : (
          <SecretTag tag={state.secretTag} label={t('settings.tagTitle')} />
        )}
        <span className="caption status">{t('popup.unlocked')}</span>
      </header>
      <div className="top">
        <label className="field">
          <input
            value={text}
            placeholder={t('popup.search')}
            aria-label={t('popup.search')}
            data-testid="search"
            onChange={(event) => {
              setText(event.target.value);
            }}
          />
        </label>
        <button
          type="button"
          className="icon-button"
          aria-label={t('popup.lock')}
          data-testid="lock"
          onClick={() => {
            spawn(lock());
          }}
        >
          <LockIcon />
        </button>
      </div>
      {matches?.host === undefined ? null : (
        <>
          <div className="section">
            <OriginLine host={matches.host} />
            <span data-testid="match-count">
              {t('popup.matches', { count: matches.items.length })}
            </span>
          </div>
          <div className="rows" data-testid="site-matches">
            {matches.items.length === 0 ? (
              <p className="caption" style={{ padding: 'var(--space-s8) var(--space-s12)' }}>
                {t('popup.noMatch')}
              </p>
            ) : (
              matches.items.map((item) => (
                <ItemRow
                  key={`${item.vault}${item.id}`}
                  item={item}
                  canFill={true}
                  onFill={handleFill}
                  onCopy={handleCopy}
                />
              ))
            )}
          </div>
        </>
      )}
      <div className="section">
        <h2>{isSearching ? t('popup.results') : t('popup.recent')}</h2>
      </div>
      <div className="rows" data-testid="results">
        {results.length === 0 ? (
          <p className="caption" style={{ padding: 'var(--space-s8) var(--space-s12)' }}>
            {t('popup.empty')}
          </p>
        ) : (
          results.map((item) => (
            <ItemRow
              key={`${item.vault}${item.id}`}
              item={item}
              canFill={false}
              onFill={handleFill}
              onCopy={handleCopy}
            />
          ))
        )}
      </div>
      {generatedItems.length === 0 ? null : (
        <>
          <div className="section">
            <h2>{t('popup.generated')}</h2>
          </div>
          <div className="rows" data-testid="generated">
            {generatedItems.map((entry) => (
              <div className="row" key={entry.id}>
                <span className="text">
                  <div className="name">
                    {entry.isSaved ? entry.site : t('popup.unsaved', { site: entry.site })}
                  </div>
                </span>
                <button
                  type="button"
                  className="mini"
                  data-testid="copy-generated"
                  onClick={() => {
                    handleCopyGenerated(entry.id);
                  }}
                >
                  {t('popup.copyGenerated')}
                </button>
              </div>
            ))}
          </div>
        </>
      )}
      <div className="bar">
        <button
          type="button"
          className="btn secondary"
          onClick={() => {
            spawn(openOptionsPage());
          }}
        >
          {t('popup.settings')}
        </button>
        <button
          type="button"
          className="btn secondary"
          data-testid="sync"
          onClick={() => {
            spawn(sync());
          }}
        >
          {t('popup.sync')}
        </button>
      </div>
      {toast === undefined ? null : (
        <div className="toast" role="status">
          {toast}
        </div>
      )}
    </>
  );
};
