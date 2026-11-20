export const normalizeServer = (text: string): string | undefined => {
  try {
    const url = new URL(text.trim());
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return undefined;
    return url.origin;
  } catch {
    return undefined;
  }
};

export const wsUrlOf = (origin: string): string => {
  const url = new URL('/v1/ws', origin);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  return url.toString();
};
