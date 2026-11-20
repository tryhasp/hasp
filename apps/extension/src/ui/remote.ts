import { useCallback, useEffect, useState } from 'react';

import { spawn } from '../platform/spawn.ts';

export type Remote<T> =
  | { status: 'loading' }
  | { status: 'ready'; value: T }
  | { status: 'failed' };

export type RemoteHandle<T> = { state: Remote<T>; reload: () => void };

export const useRemote = <T>(
  load: () => Promise<T | undefined>,
  refreshMs: number,
): RemoteHandle<T> => {
  const [state, setState] = useState<Remote<T>>({ status: 'loading' });
  const reload = useCallback((): void => {
    const run = async (): Promise<void> => {
      try {
        const value = await load();
        setState(value === undefined ? { status: 'failed' } : { status: 'ready', value });
      } catch {
        setState({ status: 'failed' });
      }
    };
    spawn(run());
  }, [load]);
  useEffect(() => {
    reload();
    if (refreshMs <= 0) return undefined;
    const timer = setInterval(reload, refreshMs);
    return () => {
      clearInterval(timer);
    };
  }, [reload, refreshMs]);
  return { state, reload };
};
