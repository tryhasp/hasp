export type SaveKind = 'new' | 'update' | 'none';

export type SaveSuppression =
  | 'never-save'
  | 'skip-save-quirk'
  | 'appends-2fa'
  | 'cross-origin-frame'
  | 'generated-unverified';

export type SaveInput = {
  username: string | undefined;
  isChangeForm: boolean;
  matches: readonly { username: string; isSamePassword: boolean }[];
  suppression: SaveSuppression | undefined;
};

export const decideSaveKind = (i: SaveInput): SaveKind => {
  if (i.suppression !== undefined) return 'none';
  const same =
    i.username === undefined ? undefined : i.matches.find((m) => m.username === i.username);
  if (same !== undefined) return same.isSamePassword && !i.isChangeForm ? 'none' : 'update';
  if (i.isChangeForm && i.matches.length === 1) return 'update';
  return 'new';
};
