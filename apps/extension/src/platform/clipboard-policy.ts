export const sha256Hex = async (text: string): Promise<string> => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
};

export const shouldClear = async (
  current: string | undefined,
  secretDigest: string,
): Promise<boolean> => current === undefined || (await sha256Hex(current)) === secretDigest;
