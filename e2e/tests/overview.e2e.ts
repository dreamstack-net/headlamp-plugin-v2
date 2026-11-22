import { expect, Locator, Page } from '@playwright/test';
import { reloadUntil, test } from './fixtures';
import { alertmanagerAddress, kubescapePath, prometheusAddress } from './helpers';

/** The value (dd) of a term (dt) of the overview, such as 'Failed checks'. */
function definition(scope: Locator, term: string | RegExp): Locator {
  return scope
    .getByRole('term')
    .filter({ hasText: term })
    .locator('xpath=following-sibling::dd[1]');
}

async function expectTrends(page: Page) {
  const main = page.getByRole('main');
  await expect(main.getByRole('heading', { name: 'Trends', level: 2 })).toBeVisible();
  // a chart of each, with the latest value next to its key
  for (const chart of ['Failed controls', 'CVEs']) {
    await expect(main.getByRole('heading', { name: chart, level: 3 })).toBeVisible();
  }
  await expect(main.locator('.recharts-surface')).toHaveCount(2);
  await expect(main.locator('.recharts-line').first()).toBeVisible();
  // the table of the same values per day
  await main.getByRole('button', { name: 'Show table' }).click();
  const table = main.getByRole('table').filter({ hasText: 'Critical failed controls' });
  await expect(table.getByRole('row')).not.toHaveCount(1);
  await expect(table.getByRole('row').nth(1).getByRole('cell').nth(3)).toHaveText(/^\d[\d,.]*$/);
  await main
    .getByRole('group', { name: 'Time range' })
    .getByRole('button', { name: 'Last 7 days' })
    .click();
  await expect(
    main.getByRole('group', { name: 'Time range' }).getByRole('button', { name: 'Last 7 days' })
  ).toHaveAttribute('aria-pressed', 'true');
  await expect(main.getByText(/Unable to read the trends/)).toHaveCount(0);
}

test.describe('Overview', () => {
  test('shows the compliance scores and CVE counts of the cluster', async ({ page }) => {
    await page.goto(kubescapePath('overview'));
    const main = page.getByRole('main');
    await expect(main.getByRole('heading', { name: 'Kubescape', level: 1 })).toBeVisible();

    // Compliance: the resources scanned link to the Compliance page, a score per framework
    await expect(definition(main, 'Resources scanned')).toHaveText(/^[1-9]\d*$/);
    await expect(definition(main, 'Failed checks')).toHaveText(/^[1-9][\d,]*$/);
    const scores = main.getByRole('term').filter({ hasText: / compliance$/ });
    await expect(scores.first()).toBeVisible();
    expect(await scores.count()).toBeGreaterThanOrEqual(1);
    for (const term of await scores.allTextContents()) {
      await expect(definition(main, term)).toHaveText(/^\d{1,3}%$/);
    }

    // Vulnerabilities: the counts of the test workloads' old images
    await expect(definition(main, 'Workloads scanned')).toHaveText(/^[1-9]\d*$/);
    await expect(definition(main, 'Critical CVEs')).toHaveText(
      /^[1-9][\d,]* \([\d,]+ with a fix\)$/
    );
    await expect(definition(main, 'High CVEs')).toHaveText(/^[1-9][\d,]* \([\d,]+ with a fix\)$/);
    const upgrades = main.getByRole('table').filter({ hasText: 'Upgrade' });
    await expect(upgrades.getByRole('link', { name: /nginx:1\.21\.6/ })).toBeVisible();

    // the links of the counts open their pages
    await definition(main, 'Resources scanned').getByRole('link').click();
    await expect(page).toHaveURL(new RegExp(`${kubescapePath('compliance')}$`));
    await expect(page.getByRole('heading', { name: 'Compliance', level: 1 })).toBeVisible();
    await page.goBack();
    await main.getByRole('link', { name: 'All upgrades' }).click();
    await expect(page).toHaveURL(/\/kubescape\/vulnerabilities\?tab=upgrades/);
    await expect(page.getByRole('tab', { name: 'Upgrades' })).toHaveAttribute(
      'aria-selected',
      'true'
    );
  });

  test('shows the trends of the Kubescape exporter from Prometheus', async ({ page }) => {
    await page.goto(kubescapePath('overview'));
    await expectTrends(page);
  });

  test('lists the runtime alerts of Alertmanager', async ({ page }) => {
    await page.goto(kubescapePath('overview'));
    const main = page.getByRole('main');
    await expect(main.getByRole('heading', { name: 'Runtime alerts', level: 2 })).toBeVisible();
    await expect(main.getByText('Alertmanager is not configured')).toHaveCount(0);
    // the node-agent alerts on the intruder some minutes after the learning period
    await reloadUntil(page, async () => {
      await expect(main.getByRole('link', { name: /^All \d+ alerts?$/ })).toBeVisible({
        timeout: 30_000,
      });
    });
    await expect(main.getByText(/Unable to read the runtime alerts/)).toHaveCount(0);
    await main.getByRole('link', { name: /^All \d+ alerts?$/ }).click();
    await expect(page).toHaveURL(new RegExp(`${kubescapePath('applicationprofiles')}`));
    await expect(page.getByRole('tab', { name: 'Alerts' })).toHaveAttribute(
      'aria-selected',
      'true'
    );
  });
});

test.describe('Plugin settings', () => {
  // starts without the addresses of Alertmanager and Prometheus
  test.use({ pluginSettings: { framework: '', activeFrameworks: [], pageSize: 50 } });

  test('saves the Alertmanager and Prometheus addresses the overview reads', async ({ page }) => {
    await page.goto(kubescapePath('overview'));
    const main = page.getByRole('main');
    await expect(
      main.getByText(/Set the address of Prometheus in the Kubescape plugin settings/)
    ).toBeVisible();
    await expect(main.getByText('Alertmanager is not configured')).toBeVisible();

    await page.goto('/settings/plugins/kubescape-plugin');
    await expect(page.getByRole('heading', { name: 'kubescape-plugin', level: 1 })).toBeVisible();
    // Detect finds the services of the monitoring stack in the cluster
    const alertmanager = page.getByRole('textbox', { name: 'Alertmanager Service Address' });
    await alertmanager.fill('not an address');
    await expect(page.getByText('Invalid format. Use: namespace/service-name:port')).toBeVisible();
    await alertmanager.fill(alertmanagerAddress);
    await page.getByRole('button', { name: 'Test Connection' }).click();
    await expect(
      page.getByRole('alert').filter({ hasText: 'Connection successful!' })
    ).toBeVisible();
    await page.getByRole('textbox', { name: 'Prometheus Service Address' }).fill(prometheusAddress);
    await page.getByRole('button', { name: 'Save' }).click();
    // Headlamp keeps plugin settings in localStorage, written half a second after a change
    await expect
      .poll(() =>
        page.evaluate(
          () => JSON.parse(localStorage.getItem('pluginConfigs') ?? '{}')['kubescape-plugin']
        )
      )
      .toMatchObject({ alertmanagerUrl: alertmanagerAddress, prometheusUrl: prometheusAddress });

    await page.goto(kubescapePath('overview'));
    await expect(main.getByText('Alertmanager is not configured')).toHaveCount(0);
    await expectTrends(page);
  });

  test('detects Prometheus in the cluster', async ({ page }) => {
    await page.goto('/settings/plugins/kubescape-plugin');
    const prometheus = page.getByRole('textbox', { name: 'Prometheus Service Address' });
    await expect(prometheus).toHaveValue('');
    // the Detect button next to the Prometheus address
    await prometheus
      .locator('xpath=ancestor::div[contains(@class,"MuiBox-root")][1]')
      .getByRole('button', { name: 'Detect' })
      .click();
    await page.getByRole('button', { name: prometheusAddress }).click();
    await expect(prometheus).toHaveValue(prometheusAddress);
  });
});
