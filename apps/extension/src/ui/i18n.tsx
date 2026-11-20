import { createContext, useContext } from 'react';
import type { ReactNode } from 'react';

import { translate } from '../shared/strings.ts';
import type { Locale, MessageKey } from '../shared/strings.ts';

export type Translate = (
  key: MessageKey,
  values?: Readonly<Record<string, string | number>>,
) => string;

const LocaleContext = createContext<Locale>('ko');

export type LocaleProviderProps = { locale: Locale; children: ReactNode };

export const LocaleProvider = ({ locale, children }: LocaleProviderProps): ReactNode => (
  <LocaleContext value={locale}>{children}</LocaleContext>
);

export const useT = (): Translate => {
  const locale = useContext(LocaleContext);
  return (key, values) => translate(locale, key, values);
};
