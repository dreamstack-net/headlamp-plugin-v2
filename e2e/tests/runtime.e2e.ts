import { Locator, Page } from '@playwright/test';
import { expect, reloadUntil, searchTable, test } from './fixtures';
import { kubectl, kubescapePath } from './helpers';

/** The value (dd) of a term (dt) in scope, such as 'Workload'. */
function definition(scope: Locator, term: string) {
  return scope
    .getByRole('term')
    .filter({ hasText: new RegExp(`^${term}$`) })
    .locator('xpath=following-sibling::dd[1]');
}

/** Waits for an alert of the intruder in the Alerts tab, reloading until Alertmanager has it. */
async function intruderAlert(page: Page, message: RegExp): Promise<Locator> {
  const main = page.getByRole('main');
  const row = main
    .getByRole('row')
    .filter({ hasText: 'tools' })
    .filter({ hasText: message })
    .first();
  await reloadUntil(page, async () => {
    await searchTable(main, 'intruder');
    await expect(row).toBeVisible({ timeout: 20_000 });
  });
  return row;
}

test.describe('Runtime Detection', () => {
  test('lists the alerts of the intruder and shows the details of one', async ({ page }) => {
    await page.goto(kubescapePath('applicationprofiles'));
    const main = page.getByRole('main');
    await expect(main.getByRole('heading', { name: 'Runtime Detection' })).toBeVisible();
    await expect(main.getByRole('tab', { name: 'Alerts' })).toHaveAttribute(
      'aria-selected',
      'true'
    );

    // the intruder starts ls, cat and nslookup after the learning period
    const row = await intruderAlert(page, /Unexpected process launched: (ls|cat|nslookup)/);
    await expect(row).toContainText('Unexpected process launched');
    await expect(row.getByRole('button', { name: 'Silence' })).toBeVisible();

    // a click on the row opens the details
    await row
      .getByRole('cell')
      .filter({ hasText: /Unexpected process launched: / })
      .click();
    const dialog = page.getByRole('dialog', { name: /Unexpected process launched/ });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText(/Unexpected process launched: (ls|cat|nslookup)/);
    await expect(definition(dialog, 'Namespace')).toHaveText('tools');
    await expect(definition(dialog, 'Workload')).toHaveText('intruder');
    await expect(definition(dialog, 'Pod').getByRole('link', { name: /^intruder-/ })).toBeVisible();
    await expect(definition(dialog, 'Container')).toHaveText('intruder');
    // what the rule detects, from the Rules objects of the cluster
    await expect(
      dialog.getByText('Detects unexpected process launches that are not in the baseline.')
    ).toBeVisible();
    await dialog.getByRole('button', { name: 'Close' }).first().click();
    await expect(dialog).toBeHidden();
  });

  test('shows the domain of a DNS alert next to the domains the profile learned', async ({
    page,
  }) => {
    await page.goto(kubescapePath('applicationprofiles'));
    const row = await intruderAlert(page, /Unexpected domain communication: kubescape\.io/);
    await row
      .getByRole('cell')
      .filter({ hasText: /Unexpected domain communication/ })
      .click();
    const dialog = page.getByRole('dialog', { name: /DNS Anomalies in container/ });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText('kubescape.io');
    await expect(definition(dialog, 'Workload')).toHaveText('intruder');
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
  });

  test('lists the learned profiles and opens the profile of a workload', async ({ page }) => {
    await page.goto(kubescapePath('applicationprofiles'));
    const main = page.getByRole('main');
    await main.getByRole('tab', { name: 'Application Profiles' }).click();
    await searchTable(main, 'intruder');
    // the profile of the running intruder pod, learned from its start
    const replicaSet = kubectl([
      'get',
      'replicaset',
      '-n',
      'tools',
      '-l',
      'app=intruder',
      '--sort-by=.metadata.creationTimestamp',
      '-o',
      'jsonpath={.items[-1:].metadata.name}',
    ]).trim();
    const profile = main
      .getByRole('row')
      .filter({ has: page.locator(`a[href*="replicaset-${replicaSet}-intruder"]`) });
    await expect(profile).toBeVisible();
    await expect(profile).toContainText('Deployment');
    await expect(profile).toContainText(/completed/);
    await expect(profile.getByRole('button', { name: 'Relearn' })).toBeVisible();

    await profile.getByRole('link', { name: 'intruder' }).click();
    await expect(page).toHaveURL(
      new RegExp(`/kubescape/runtimedetection/tools/replicaset-${replicaSet}-intruder-`)
    );
    await expect(
      main.getByRole('heading', { name: 'Application Profile', level: 1 })
    ).toBeVisible();
    await expect(definition(main, 'Workload')).toHaveText('intruder');
    await expect(definition(main, 'Kind')).toHaveText('Deployment');
    await expect(definition(main, 'Status')).toHaveText('completed');
    // the intruder ran sh while it was learned, and opened its libraries
    await expect(definition(main, 'Execs')).toHaveText(/^[1-9]\d*$/);
    await expect(definition(main, 'Opens')).toHaveText(/^[1-9]\d*$/);
    await main.getByRole('tab', { name: 'Full YAML' }).click();
    const fullYaml = main.getByRole('tabpanel', { name: 'Full YAML' });
    await expect(fullYaml).toContainText('kind: ContainerProfile');
    // the editor only draws the lines in view, and the execs come after the metadata: its
    // search scrolls to them
    const lines = fullYaml.locator('.monaco-editor .view-lines');
    await lines.click();
    await page.keyboard.press('ControlOrMeta+f');
    await page.keyboard.type('/bin/sh');
    await expect(lines).toContainText('/bin/sh');
  });

  test('lists the rules and the rule bindings', async ({ page }) => {
    await page.goto(kubescapePath('applicationprofiles'));
    const main = page.getByRole('main');
    await main.getByRole('tab', { name: 'Rules' }).click();
    const rules = main
      .getByRole('row')
      .filter({ has: page.getByRole('link', { name: 'default-rules' }) });
    await expect(rules).toBeVisible();
    await expect(rules.getByRole('cell').nth(1)).toHaveText('kubescape');
    await expect(rules.getByRole('cell').nth(2)).toHaveText(/^[1-9]\d*$/);
    await expect(main.getByRole('button', { name: 'Add new rule' })).toBeVisible();

    await main.getByRole('tab', { name: 'Rule Bindings' }).click();
    const binding = main
      .getByRole('row')
      .filter({ has: page.getByRole('link', { name: 'all-rules-all-pods' }) });
    await expect(binding).toBeVisible();
    await expect(binding).toContainText('Unexpected process launched');
    await binding.getByRole('link', { name: 'all-rules-all-pods' }).click();
    await expect(page).toHaveURL(new RegExp(`${kubescapePath('rulebinding/all-rules-all-pods')}$`));
    await expect(main.getByRole('heading', { name: 'Edit Rule Binding' })).toBeVisible();
    await expect(main.getByRole('textbox', { name: 'Name' })).toHaveValue('all-rules-all-pods');
    await expect(main.getByRole('combobox', { name: 'Rule Name' }).first()).toHaveValue(
      'Unexpected process launched'
    );
  });

  test('tests a default rule in the playground of the rule editor', async ({ page }) => {
    await page.goto(kubescapePath('applicationprofiles'));
    const main = page.getByRole('main');
    await main.getByRole('tab', { name: 'Rules' }).click();
    await main.getByRole('link', { name: 'default-rules' }).click();
    await expect(page).toHaveURL(new RegExp(`${kubescapePath('rule/kubescape/default-rules')}$`));
    await expect(main.getByText('Edit Rule', { exact: true })).toBeVisible();
    await expect(main.getByText(/is system-managed and cannot be edited here/)).toBeVisible();

    await main.getByRole('button', { name: 'Test rule in playground' }).click();
    const dialog = page.getByRole('dialog', { name: /Test Rules/ });
    await expect(dialog).toBeVisible();
    // an exec event against an empty profile: the process was not learned
    await expect(dialog.getByRole('combobox', { name: 'Event type' })).toHaveText('exec');
    await dialog.getByRole('button', { name: 'Evaluate' }).click();
    const results = dialog.getByRole('table');
    const unexpected = results.getByRole('row').filter({
      has: page.getByRole('cell', { name: 'Unexpected process launched', exact: true }),
    });
    await expect(unexpected).toBeVisible();
    await expect(unexpected.getByRole('cell').nth(1)).toHaveText('fired');
    await expect(unexpected.getByRole('cell').nth(2)).not.toBeEmpty();
    await expect(dialog.getByRole('alert')).toHaveCount(0);
    // rules of other event types do not apply to an exec event, and are hidden at first
    await expect(results.getByRole('cell', { name: 'N/A', exact: true })).toHaveCount(0);
    await dialog.getByRole('button', { name: 'Show N/A' }).click();
    await expect(results.getByRole('cell', { name: 'N/A', exact: true }).first()).toBeVisible();
    await dialog.getByRole('button', { name: 'Hide N/A' }).click();
    await expect(results.getByRole('cell', { name: 'N/A', exact: true })).toHaveCount(0);
    await expect(unexpected).toBeVisible();
  });
});
