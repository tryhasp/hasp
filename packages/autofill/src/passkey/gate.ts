export const MAX_IN_FLIGHT = 1;
export const FALLBACK_DELAY_MS = 1500;

export type GateInput = {
  op: 'create' | 'get';
  mediation: string | undefined;
  isActivationActive: boolean;
  inFlight: number;
};

export const shouldAsk = (input: GateInput): boolean => {
  if (input.inFlight >= MAX_IN_FLIGHT) return false;
  if (input.op === 'get' && input.mediation === 'conditional') return true;
  return input.isActivationActive;
};

export const fallbackWaitMs = (elapsedMs: number): number =>
  Math.max(0, FALLBACK_DELAY_MS - Math.max(0, elapsedMs));
