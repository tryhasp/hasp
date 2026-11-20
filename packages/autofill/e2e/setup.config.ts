import { buildHarness } from './build.ts';

export default async function globalSetup(): Promise<void> {
  await buildHarness();
}
