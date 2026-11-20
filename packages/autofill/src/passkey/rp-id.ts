export const isRpIdSuffixOfHost = (hostname: string, rpId: string): boolean => {
  const host = hostname.toLowerCase();
  const rp = rpId.toLowerCase();
  if (rp === '' || rp.includes('/') || rp.includes(':')) return false;
  if (host === rp) return true;
  return host.endsWith(`.${rp}`) && rp.includes('.');
};
