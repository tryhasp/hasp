import { report } from './log.ts';

export const spawn = (promise: Promise<unknown>): void => {
  promise.catch((cause: unknown) => {
    report(cause instanceof Error ? cause.name : 'unknown');
  });
};
