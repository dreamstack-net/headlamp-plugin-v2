/*
  The test function of the end-to-end tests: every page starts with the plugin settings of the
  tests in localStorage, where Headlamp keeps plugin settings (pluginConfigs, by plugin name), and
  fails on errors the page did not catch.
*/
import { expect, Locator, Page, test as base } from '@playwright/test';
import { alertmanagerAddress, prometheusAddress } from './helpers';

export { expect };

export type PluginSettings = Record<string, unknown>;

export const defaultPluginSettings: PluginSettings = {
  framework: '',
  activeFrameworks: [],
  pageSize: 50,
  alertmanagerUrl: alertmanagerAddress,
  prometheusUrl: prometheusAddress,
};

export const test = base.extend<{
  // the settings of the plugin when a page opens; null leaves Headlamp's localStorage alone
  pluginSettings: PluginSettings | null;
  pageErrors: string[];
}>({
  pluginSettings: [defaultPluginSettings, { option: true }],

  context: async ({ context, pluginSettings }, use) => {
    if (pluginSettings) {
      // only before the first page of the test, so that what a test saves stays
      await context.addInitScript(settings => {
        if (sessionStorage.getItem('e2e-settings')) return;
        sessionStorage.setItem('e2e-settings', '1');
        const configs = JSON.parse(localStorage.getItem('pluginConfigs') || '{}');
        configs['kubescape-plugin'] = settings;
        localStorage.setItem('pluginConfigs', JSON.stringify(configs));
      }, pluginSettings);
    }
    await use(context);
  },

  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on('pageerror', error => errors.push(`${error.name}: ${error.message}`));
      await use(errors);
      expect(errors, 'errors the page did not catch').toEqual([]);
    },
    { auto: true },
  ],
});

/**
 * Reloads the page until check passes: Kubescape writes some data, such as runtime alerts, while
 * the tests run, and the pages read it once. The expectations of check need short timeouts.
 */
export async function reloadUntil(
  page: Page,
  check: () => Promise<void>,
  { timeout = 10 * 60_000 }: { timeout?: number } = {}
) {
  let first = true;
  await expect(async () => {
    if (!first) await page.reload();
    first = false;
    await check();
  }).toPass({ timeout, intervals: [5_000] });
}

/**
 * Collects the errors of watches of the Kubescape storage: it refuses to watch some kinds, such
 * as the summaries of a namespace (405), and Headlamp then opens the watch again and again.
 */
export function storageWatchErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('console', message => {
    const text = message.text();
    if (
      message.type() === 'error' &&
      text.includes('spdx.softwarecomposition.kubescape.io') &&
      /WebSocket|api stream/.test(text)
    ) {
      errors.push(text);
    }
  });
  return errors;
}

/** Types into the search of a Headlamp table in scope, which pages its rows. */
export async function searchTable(scope: Locator, text: string) {
  const search = scope.getByPlaceholder(/^Search/);
  if (!(await search.isVisible())) {
    await scope.getByRole('button', { name: 'Show/Hide search' }).click();
  }
  await search.fill(text);
  // the table applies the search, and writes it to the URL, after a debounce; a link clicked
  // before would get the search in its URL
  await scope.page().waitForTimeout(600);
}

/**
 * Makes the plugin save files through a download, which Playwright can read, instead of the save
 * dialog of the File System Access API, which it cannot answer.
 */
export async function withoutSaveFilePicker(page: Page) {
  await page.addInitScript(() => {
    Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true });
  });
}
