import type { ReactNode } from 'react';

import { splitHost } from '../shared/host.ts';
import { useWasmReady } from './wasm-ready.ts';

export type OriginLineProps = { host: string; against?: string };

const differs = (label: string, against: string | undefined): boolean => {
  if (against === undefined) return false;
  const others = against.split('.');
  return !others.slice(0, -1).includes(label);
};

const labelsOf = (text: string, against: string | undefined, hasTld: boolean): ReactNode[] => {
  const labels = text.split('.');
  return labels.flatMap((label, index) => [
    ...(index === 0 ? [] : ['.']),
    differs(label, against) && !(hasTld && index === labels.length - 1) ? (
      <u key={`${label}-${String(index)}`}>{label}</u>
    ) : (
      label
    ),
  ]);
};

export const OriginLine = ({ host, against }: OriginLineProps): ReactNode => {
  useWasmReady();
  const { subdomain, registrable } = splitHost(host);
  return (
    <span className="origin">
      {subdomain === '' ? null : (
        <span className="dim">{labelsOf(subdomain, against, false)}.</span>
      )}
      <b>{labelsOf(registrable, against, true)}</b>
    </span>
  );
};
