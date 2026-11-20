export type ReportCode = string;

export const report = (code: ReportCode): void => {
  // oxlint-disable-next-line eslint/no-console -- the single sink; codes only, never payloads
  console.warn(`hasp:${code}`);
};
