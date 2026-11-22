import { Page } from '@playwright/test';
import { expect, searchTable, test } from './fixtures';
import { deleteIfExists, exists, kubectlJson, kubescapePath } from './helpers';

// C-0013 (non-root containers) fails for the test workloads; no other test reads it
const control = 'C-0013';
// the name the form suggests for an exception of the control in the whole cluster
const exceptionName = 'c-0013-cluster';
const resource = 'clustersecurityexceptions.kubescape.io';

/** The value (dd) of a term (dt) of a details table, such as 'Passed'. */
function definition(page: Page, term: string) {
  return page
    .getByRole('main')
    .getByRole('term')
    .filter({ hasText: new RegExp(`^${term}$`) })
    .locator('xpath=following-sibling::dd[1]');
}

test.describe('Exceptions', () => {
  test.beforeEach(() => deleteIfExists(resource, exceptionName));
  test.afterEach(() => deleteIfExists(resource, exceptionName));

  test('excludes a control in the whole cluster and deletes the exception again', async ({
    page,
  }) => {
    await page.goto(kubescapePath(`compliance/controls/${control}`));
    await expect(definition(page, 'Passed')).toHaveText(/^\d+ of [1-9]\d*$/);
    const passedBefore = await definition(page, 'Passed').textContent();

    // the Exclude button of the control in the Compliance table
    await page.goto(kubescapePath('compliance'));
    const panel = page.getByRole('tabpanel', { name: 'Controls' });
    await searchTable(panel, control);
    const row = panel
      .getByRole('row')
      .filter({ has: page.getByRole('link', { name: control, exact: true }) });
    await expect(row.getByRole('cell').nth(6)).toHaveText('0');
    await row.getByRole('button', { name: 'Exclude control cluster-wide' }).click();

    const dialog = page.getByRole('dialog', { name: 'Exclude Control Cluster-wide' });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('textbox', { name: 'Name' })).toHaveValue(exceptionName);
    await dialog.getByRole('textbox', { name: 'Reason' }).fill('end-to-end test');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(dialog).toBeHidden();

    // the exception as the cluster has it, with the author and its history
    await expect.poll(() => exists(resource, exceptionName)).toBe(true);
    const created = kubectlJson(['get', resource, exceptionName]);
    expect(created.spec.posture).toEqual([{ controlID: control, action: 'ignore' }]);
    expect(created.spec.reason).toBe('end-to-end test');
    expect(created.spec.author).toBeTruthy();
    expect(created.metadata.annotations?.['headlamp.kubescape.io/history']).toBeTruthy();

    // the page applies it, as the riskAcceptance capability of the operator is off: the control
    // leaves the failed controls, and all controls show it excluded
    await expect(row).toHaveCount(0);
    await expect(
      page.getByText(/excluding \d+ resources? and [1-9]\d* control results?$/)
    ).toBeVisible();
    await page.getByRole('main').getByRole('checkbox', { name: 'Failed controls' }).uncheck();
    await expect(row.getByRole('cell').nth(6)).toHaveText(/^[1-9]\d*$/);
    await page.goto(kubescapePath(`compliance/controls/${control}`));
    await expect(definition(page, 'Passed')).toHaveText(/excluded by exceptions$/);

    // the Exceptions page lists it and deletes it after asking
    await page.goto(kubescapePath('exceptions'));
    const main = page.getByRole('main');
    const listed = main
      .getByRole('row')
      .filter({ has: page.getByRole('link', { name: exceptionName, exact: true }) });
    await expect(listed).toBeVisible();
    await expect(listed).toContainText('end-to-end test');
    await listed.getByRole('button', { name: 'Delete' }).click();
    const confirm = page.getByRole('dialog', { name: 'Delete ClusterSecurityException?' });
    await expect(confirm).toBeVisible();
    await expect(confirm).toContainText(exceptionName);
    await confirm.getByRole('button', { name: 'Delete' }).click();
    await expect(confirm).toBeHidden();
    await expect(listed).toHaveCount(0);
    await expect.poll(() => exists(resource, exceptionName)).toBe(false);

    await page.goto(kubescapePath(`compliance/controls/${control}`));
    await expect(definition(page, 'Passed')).toHaveText(passedBefore!);
  });

  test('opens the page of an exception with its history', async ({ page }) => {
    await page.goto(kubescapePath('compliance'));
    const panel = page.getByRole('tabpanel', { name: 'Controls' });
    await searchTable(panel, control);
    await panel
      .getByRole('row')
      .filter({ has: page.getByRole('link', { name: control, exact: true }) })
      .getByRole('button', { name: 'Exclude control cluster-wide' })
      .click();
    const dialog = page.getByRole('dialog', { name: 'Exclude Control Cluster-wide' });
    await dialog.getByRole('textbox', { name: 'Reason' }).fill('end-to-end test');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(dialog).toBeHidden();

    await page.goto(kubescapePath('exceptions'));
    await page.getByRole('main').getByRole('link', { name: exceptionName, exact: true }).click();
    await expect(page).toHaveURL(
      new RegExp(`${kubescapePath(`exceptions/cluster/${exceptionName}`)}$`)
    );
    const main = page.getByRole('main');
    await expect(main.getByText(exceptionName).first()).toBeVisible();
    await expect(main.getByText(control).first()).toBeVisible();
    await expect(main.getByText('end-to-end test').first()).toBeVisible();
    // the history annotation: created by the user of the kubeconfig
    await expect(main.getByText(/created/i).first()).toBeVisible();
  });
});
