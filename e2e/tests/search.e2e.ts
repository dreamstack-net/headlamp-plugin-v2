import { Page } from '@playwright/test';
import { expect, test } from './fixtures';
import { kubescapePath } from './helpers';

// a CVE of busybox 1.36.0, the image of the sidecars and of the api and intruder deployments
const cve = 'CVE-2022-48174';

/** Opens the Kubescape search of the top bar and types query; returns the dialog. */
async function search(page: Page, query: string) {
  await page
    .getByRole('navigation', { name: 'Appbar Tools' })
    .getByRole('button', { name: 'Search Kubescape' })
    .click();
  const dialog = page.getByRole('dialog', { name: 'Search Kubescape' });
  await expect(dialog).toBeVisible();
  const input = dialog.getByRole('textbox', { name: 'Search Kubescape' });
  await expect(input).toBeFocused();
  await input.fill(query);
  return dialog;
}

test.describe('Kubescape search', () => {
  test('finds a CVE and opens it with a click', async ({ page }) => {
    await page.goto(kubescapePath('overview'));
    const dialog = await search(page, cve);
    // the first search of a session reads the vulnerability reports
    const result = dialog.getByRole('link', { name: new RegExp(cve) }).first();
    await expect(result).toBeVisible({ timeout: 120_000 });
    await result.click();

    await expect(page).toHaveURL(new RegExp(`${kubescapePath(`vulnerabilities/cves/${cve}`)}$`));
    await expect(dialog).toBeHidden();
    await expect(page.getByRole('heading', { name: cve, level: 2 })).toBeVisible();
  });

  test('opens the first result with Enter', async ({ page }) => {
    await page.goto(kubescapePath('compliance'));
    const dialog = await search(page, cve);
    await expect(dialog.getByRole('link', { name: new RegExp(cve) }).first()).toBeVisible({
      timeout: 120_000,
    });
    await dialog.getByRole('textbox', { name: 'Search Kubescape' }).press('Enter');

    await expect(page).toHaveURL(new RegExp(`${kubescapePath(`vulnerabilities/cves/${cve}`)}$`));
    await expect(dialog).toBeHidden();
    await expect(page.getByRole('heading', { name: cve, level: 2 })).toBeVisible();
  });

  test('finds a control and a workload', async ({ page }) => {
    await page.goto(kubescapePath('overview'));
    let dialog = await search(page, 'C-0057');
    // controls can be searched while the reports are read
    const control = dialog.getByRole('link', { name: /C-0057/ }).first();
    await expect(control).toBeVisible();
    await control.click();
    await expect(page).toHaveURL(new RegExp(`${kubescapePath('compliance/controls/C-0057')}$`));
    await expect(dialog).toBeHidden();
    await expect(page.getByRole('heading', { name: 'C-0057: Privileged container' })).toBeVisible();

    dialog = await search(page, 'intruder');
    const workload = dialog.getByRole('link', { name: /intruder/ }).first();
    await expect(workload).toBeVisible({ timeout: 120_000 });
    await workload.click();
    await expect(dialog).toBeHidden();
    await expect(page).toHaveURL(
      /\/kubescape\/vulnerabilities\/namespaces\/tools\/deployment-intruder-intruder$/
    );
    await expect(
      page
        .getByRole('main')
        .getByRole('term')
        .filter({ hasText: /^Workload$/ })
    ).toBeVisible();
  });

  test('closes with Escape and says when nothing is found', async ({ page }) => {
    await page.goto(kubescapePath('overview'));
    const dialog = await search(page, 'no-such-package-e2e');
    await expect(dialog.getByText(/^Nothing found for “no-such-package-e2e”/)).toBeVisible({
      timeout: 120_000,
    });
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(page).toHaveURL(new RegExp(`${kubescapePath('overview')}$`));
  });
});
