/*
  End-to-end tests of the plugin in a real Headlamp (server mode, in Docker) against a kind
  cluster with Kubescape: e2e/setup-kind.sh, e2e/build-plugin.sh, e2e/headlamp.sh and
  e2e/wait-for-scans.sh prepare them; `npm run e2e` runs them. The test files are *.e2e.ts, as
  Vitest, which `headlamp-plugin test` runs with Headlamp's config, collects every *.spec.ts and
  *.test.ts of the checkout.
*/
import { defineConfig, devices } from '@playwright/test';

const headlampUrl =
  process.env.HEADLAMP_URL ?? `http://localhost:${process.env.HEADLAMP_PORT ?? 4488}`;

export default defineConfig({
  testDir: './tests',
  testMatch: '**/*.e2e.ts',
  outputDir: './test-results',
  globalSetup: './global-setup.ts',
  // the pages read the scans of the whole cluster, and some tests wait for the operator
  timeout: 5 * 60_000,
  expect: { timeout: 60_000 },
  fullyParallel: false,
  workers: Number(process.env.E2E_WORKERS ?? 2),
  retries: process.env.CI ? 1 : 0,
  forbidOnly: !!process.env.CI,
  reporter: [['list'], ['html', { outputFolder: './playwright-report', open: 'never' }]],
  use: {
    baseURL: headlampUrl,
    viewport: { width: 1600, height: 1000 },
    actionTimeout: 30_000,
    navigationTimeout: 60_000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1600, height: 1000 } },
    },
  ],
});
