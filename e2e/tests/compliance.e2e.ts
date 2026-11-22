import { Page } from '@playwright/test';
import { expect, searchTable, test, withoutSaveFilePicker } from './fixtures';
import { cluster, kubescapePath } from './helpers';

/** The value (dd) of a term (dt) of a details table, such as 'Passed'. */
function definition(page: Page, term: string) {
  return page
    .getByRole('main')
    .getByRole('term')
    .filter({ hasText: new RegExp(`^${term}$`) })
    .locator('xpath=following-sibling::dd[1]');
}

/** Downloads the fixed YAML of the fix page that is open and returns it. */
async function downloadFix(page: Page): Promise<string> {
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download fixed YAML' }).click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/-fixed\.yaml$/);
  const stream = await file.createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

test.describe('Compliance', () => {
  test('shows the score of each framework and filters the controls by framework', async ({
    page,
  }) => {
    await page.goto(kubescapePath('compliance'));
    const main = page.getByRole('main');
    await expect(main.getByRole('heading', { name: 'Compliance', level: 1 })).toBeVisible();
    await expect(
      main.getByText(/^\d[\d,]* total checks, \d[\d,]* configuration issues/)
    ).toBeVisible();

    // a button with the score of each framework of the scans
    const frameworks = main.getByRole('radiogroup');
    await expect(frameworks.getByRole('radio', { name: 'Show all' })).toBeChecked();
    for (const framework of ['NSA', 'MITRE']) {
      await expect(
        frameworks.getByRole('radio', { name: new RegExp(`^\\d+% ${framework}$`) })
      ).toBeVisible();
    }

    const panel = main.getByRole('tabpanel', { name: 'Controls' });
    const controls = panel.getByRole('table');
    // the table pages its rows; its search finds C-0057, as the api deployment runs privileged
    await searchTable(panel, 'C-0057');
    await expect(controls.getByRole('link', { name: 'C-0057', exact: true })).toBeVisible();
    await expect(controls.getByRole('link', { name: 'C-0002', exact: true })).toHaveCount(0);
    await searchTable(panel, '');

    // NSA has no control C-0004 (memory limits), which fails in the combined view
    await expect(controls.getByRole('link', { name: 'C-0004', exact: true })).toBeVisible();
    await frameworks.getByRole('radio', { name: /^\d+% NSA$/ }).check();
    await expect(frameworks.getByRole('radio', { name: /^\d+% NSA$/ })).toBeChecked();
    await expect(controls.getByRole('link', { name: 'C-0002', exact: true })).toBeVisible();
    await expect(controls.getByRole('link', { name: 'C-0004', exact: true })).toHaveCount(0);
    // the choice is kept in the plugin settings
    await expect
      .poll(() =>
        page.evaluate(
          () =>
            JSON.parse(localStorage.getItem('pluginConfigs') ?? '{}')['kubescape-plugin']?.framework
        )
      )
      .toBe('NSA');
    await frameworks.getByRole('radio', { name: 'Show all' }).check();
    await expect(controls.getByRole('link', { name: 'C-0004', exact: true })).toBeVisible();

    // the other tabs list the scanned resources, namespaces and the cluster
    await main.getByRole('tab', { name: 'Resources' }).click();
    await expect(
      main
        .getByRole('tabpanel', { name: 'Resources' })
        .getByRole('link', { name: 'web', exact: true })
        .first()
    ).toBeVisible();
    await main.getByRole('tab', { name: 'Namespaces' }).click();
    await expect(
      main
        .getByRole('tabpanel', { name: 'Namespaces' })
        .getByRole('link', { name: 'shop', exact: true })
        .first()
    ).toBeVisible();
    await main.getByRole('tab', { name: 'Clusters' }).click();
    await expect(
      main.getByRole('tabpanel', { name: 'Clusters' }).getByText('kind-kubescape-e2e').first()
    ).toBeVisible();
  });

  test('opens a control with the resources it failed in and their fix', async ({ page }) => {
    await withoutSaveFilePicker(page);
    await page.goto(kubescapePath('compliance'));
    const panel = page.getByRole('tabpanel', { name: 'Controls' });
    await searchTable(panel, 'C-0016');
    await panel.getByRole('table').getByRole('link', { name: 'C-0016', exact: true }).click();

    await expect(page).toHaveURL(new RegExp(`${kubescapePath('compliance/controls/C-0016')}$`));
    await expect(
      page.getByRole('heading', { name: 'C-0016: Allow privilege escalation' })
    ).toBeVisible();
    await expect(definition(page, 'Passed')).toHaveText(/^\d+ of [1-9]\d*/);
    const resources = page.getByRole('table').filter({ hasText: 'Scan name' });
    // the api deployment runs privileged
    const api = resources
      .getByRole('row')
      .filter({ has: page.getByRole('link', { name: 'api', exact: true }) });
    await expect(api).toBeVisible();
    await expect(api.getByRole('cell').first()).toHaveText(/failed/i);

    await api.getByRole('link', { name: 'Fix' }).click();
    await expect(page).toHaveURL(
      /\/kubescape\/compliance\/kind-kubescape-e2e\/namespaces\/shop\/deployment-api\/C-0016$/
    );
    await expect(page.getByRole('heading', { name: 'Allow privilege escalation' })).toBeVisible();
    await expect(page.locator('.monaco-diff-editor')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Apply fix' })).toBeEnabled();
    const fixed = await downloadFix(page);
    expect(fixed).toMatch(/kind: Deployment/);
    expect(fixed).toMatch(/allowPrivilegeEscalation: false/);
    expect(fixed).toMatch(/privileged: false/);
  });

  test('says that Kubescape gives no fix for a control without one', async ({ page }) => {
    // C-0057 (privileged container) fails in the api deployment, and Kubescape gives no path to
    // fix it
    await page.goto(kubescapePath(`compliance/${cluster}/namespaces/shop/deployment-api/C-0057`));
    await expect(page.getByRole('heading', { name: 'Privileged container' })).toBeVisible();
    await expect(
      page.getByText(
        'Kubescape gives no automatic fix for this control in Deployment shop/api: change it by hand, as the remediation above describes.'
      )
    ).toBeVisible();
    await expect(definition(page, 'Remediation')).toContainText('securityContext.privileged');
    // no diff without changes, and no Apply fix that cannot be used
    await expect(page.locator('.monaco-diff-editor')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Apply fix' })).toHaveCount(0);
  });

  test('opens a workload with its controls and previews a fix', async ({ page }) => {
    await withoutSaveFilePicker(page);
    await page.goto(kubescapePath('compliance/controls/C-0017'));
    await expect(
      page.getByRole('heading', { name: 'C-0017: Immutable container filesystem' })
    ).toBeVisible();
    const resources = page.getByRole('table').filter({ hasText: 'Scan name' });
    await resources.getByRole('link', { name: 'web', exact: true }).click();

    await expect(page).toHaveURL(
      /\/kubescape\/compliance\/kind-kubescape-e2e\/shop\/deployment-web$/
    );
    await expect(page.getByRole('heading', { name: 'Workload Configuration Scan' })).toBeVisible();
    await expect(definition(page, 'Name')).toHaveText('web');
    await expect(definition(page, 'Kind')).toHaveText('Deployment');
    await expect(definition(page, 'Results')).toHaveText(/^Failed [1-9]\d*, Passed \d+/);
    const controls = page.getByRole('table').filter({ hasText: 'Remediation' });
    const immutable = controls
      .getByRole('row')
      .filter({ has: page.getByRole('link', { name: 'C-0017', exact: true }) });
    await expect(immutable.getByRole('cell').first()).toHaveText('failed');

    await immutable.getByRole('link', { name: 'Fix' }).click();
    await expect(page).toHaveURL(/\/namespaces\/shop\/deployment-web\/C-0017$/);
    await expect(
      page.getByRole('heading', { name: 'Immutable container filesystem' })
    ).toBeVisible();
    await expect(page.locator('.monaco-diff-editor')).toBeVisible();
    // the modified side of the diff has the lines the fix adds
    await expect(page.locator('.monaco-diff-editor .editor.modified')).toContainText(
      'kind: Deployment'
    );
    const fixed = await downloadFix(page);
    expect(fixed).toMatch(/readOnlyRootFilesystem: true/);

    // Apply fix asks first; cancelling changes nothing
    await page.getByRole('button', { name: 'Apply fix' }).click();
    const dialog = page.getByRole('dialog', { name: /Apply fix to Deployment shop\/web/ });
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
  });
});
