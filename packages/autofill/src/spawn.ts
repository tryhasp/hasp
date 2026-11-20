export type Report = (code: string) => void;

export const spawn = (promise: Promise<unknown>, report: Report): void => {
  promise.catch((cause: unknown) => {
    report(cause instanceof Error ? cause.name : 'unknown');
  });
};
