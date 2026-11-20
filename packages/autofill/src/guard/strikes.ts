export const MAX_STRIKES = 3;

export type Strikes = { count: number; isDisabled: boolean; isNoticeDue: boolean };

export const noStrikes: Strikes = { count: 0, isDisabled: false, isNoticeDue: false };

export const addStrike = (s: Strikes): Strikes => {
  const count = Math.min(s.count + 1, MAX_STRIKES);
  const isDisabled = count >= MAX_STRIKES;
  return { count, isDisabled, isNoticeDue: isDisabled && !s.isDisabled };
};
