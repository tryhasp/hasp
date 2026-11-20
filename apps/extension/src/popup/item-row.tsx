import type { ReactNode } from 'react';

import type { ItemView } from '../messages/ui.ts';
import { useT } from '../ui/i18n.tsx';
import { Tile } from './tile.tsx';

export type CopyField = 'username' | 'password' | 'otp';

export type ItemRowProps = {
  item: ItemView;
  canFill: boolean;
  onFill: (item: ItemView) => void;
  onCopy: (item: ItemView, field: CopyField) => void;
};

export const ItemRow = ({ item, canFill, onFill, onCopy }: ItemRowProps): ReactNode => {
  const t = useT();
  return (
    <div className="row" data-testid="item-row" aria-current={canFill ? 'true' : undefined}>
      <Tile title={item.title} selected={canFill} />
      <span className="text">
        <div className="name">{item.title}</div>
        <div className="sub">{item.subtitle}</div>
      </span>
      <span className="actions">
        {canFill ? (
          <button
            type="button"
            className="mini primary"
            data-testid="item-fill"
            onClick={() => {
              onFill(item);
            }}
          >
            {t('popup.fill')}
          </button>
        ) : null}
        <button
          type="button"
          className="mini"
          aria-label={t('popup.copyUser')}
          data-testid="copy-username"
          onClick={() => {
            onCopy(item, 'username');
          }}
        >
          {t('popup.copyUser')}
        </button>
        <button
          type="button"
          className="mini"
          aria-label={t('popup.copyPassword')}
          data-testid="copy-password"
          onClick={() => {
            onCopy(item, 'password');
          }}
        >
          {t('popup.copyPassword')}
        </button>
        {item.hasTotp ? (
          <button
            type="button"
            className="mini"
            aria-label={t('popup.copyOtp')}
            data-testid="copy-otp"
            onClick={() => {
              onCopy(item, 'otp');
            }}
          >
            {t('popup.copyOtp')}
          </button>
        ) : null}
      </span>
    </div>
  );
};
