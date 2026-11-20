import { registrableDomain } from '@hasp/wasm';

export type SplitHost = { subdomain: string; registrable: string };

const whole = (host: string): SplitHost => ({ subdomain: '', registrable: host });

const isIpLiteral = (host: string): boolean => /^[0-9.]+$/.test(host) || host.includes(':');

export const splitHost = (host: string): SplitHost => {
  if (isIpLiteral(host)) return whole(host);
  let registrable: string | undefined;
  try {
    registrable = registrableDomain(host);
  } catch {
    return whole(host);
  }
  if (registrable === undefined || !host.endsWith(`.${registrable}`)) return whole(host);
  return { subdomain: host.slice(0, host.length - registrable.length - 1), registrable };
};

export const hostOfUrl = (url: string): string | undefined => {
  try {
    return new URL(url).hostname;
  } catch {
    return undefined;
  }
};
