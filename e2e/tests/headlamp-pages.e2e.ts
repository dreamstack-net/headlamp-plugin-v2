/*
  What the plugin adds to Headlamp's own pages: the Kubescape columns of the workload lists and
  the Kubescape sections of the pages of a workload and a namespace.
*/
import { Locator } from '@playwright/test';
import { expect, storageWatchErrors, test } from './fixtures';
import { cluster } from './helpers';

/** The value (dd) of the term (dt) with a link named name. */
function linkedDefinition(scope: Locator, name: string | RegExp) {
  return scope
    .getByRole('term')
    .filter({ has: scope.page().getByRole('link', { name }) })
    .locator('xpath=following-sibling::dd[1]');
}

/** The Kubescape section of a Headlamp details page. */
function kubescapeSection(main: Locator) {
  return main
    .getByRole('heading', { name: 'Kubescape', level: 2 })
    .locator('xpath=ancestor::*[.//dl][1]');
}

test.describe('Headlamp pages', () => {
  test('adds the CVEs and failed controls of each workload to the list of deployments', async ({
    page,
  }) => {
    await page.goto(`/c/${cluster}/deployments?namespace=shop`);
    const main = page.getByRole('main');
    await expect(main.getByRole('columnheader', { name: /^CVEs/ })).toBeVisible();
    await expect(main.getByRole('columnheader', { name: /^Failed controls/ })).toBeVisible();
    const web = main
      .getByRole('row')
      .filter({ has: page.getByRole('link', { name: 'web', exact: true }) });
    // nginx 1.21.6 has critical CVEs; web runs as root without limits
    await expect(
      web.getByRole('link', { name: /^[1-9]\d* Critical findings$/ }).first()
    ).toBeVisible();
    await expect(web.getByRole('link', { name: /^\d+ High findings$/ }).last()).toBeVisible();
  });

  test('shows the Kubescape section on the page of a deployment', async ({ page }) => {
    const watchErrors = storageWatchErrors(page);
    await page.goto(`/c/${cluster}/deployments/shop/web`);
    const main = page.getByRole('main');
    const section = kubescapeSection(main);
    await expect(section.getByRole('link', { name: 'Compliance' })).toBeVisible();
    // web runs as root without limits, which fails controls of high severity
    await expect(linkedDefinition(section, 'Compliance')).toHaveText(
      /\d+ Critical\s*[1-9]\d* High/
    );
    await expect(linkedDefinition(section, 'Vulnerabilities / nginx')).toHaveText(
      /^[1-9]\d* Critical/
    );
    await expect(linkedDefinition(section, 'Vulnerabilities / sidecar')).toBeVisible();
    // the section reads the configuration scan once: a watch of the storage would replace it
    // with one without its controls
    await page.waitForTimeout(5_000);
    await expect(linkedDefinition(section, 'Compliance')).toHaveText(
      /\d+ Critical\s*[1-9]\d* High/
    );
    expect.soft(watchErrors, 'failed watches of the Kubescape storage').toEqual([]);

    await section.getByRole('link', { name: 'Vulnerabilities / nginx' }).click();
    await expect(page).toHaveURL(
      /\/kubescape\/vulnerabilities\/namespaces\/shop\/deployment-web-nginx$/
    );
    await expect(main.getByRole('heading', { name: 'Vulnerabilities', level: 2 })).toBeVisible();
    await page.goBack();
    await kubescapeSection(main).getByRole('link', { name: 'Compliance' }).click();
    await expect(page).toHaveURL(
      /\/kubescape\/compliance\/kind-kubescape-e2e\/shop\/deployment-web$/
    );
    await expect(main.getByRole('heading', { name: 'Workload Configuration Scan' })).toBeVisible();
  });

  test('shows the Kubescape section on the page of a namespace', async ({ page }) => {
    const watchErrors = storageWatchErrors(page);
    await page.goto(`/c/${cluster}/namespaces/shop`);
    const main = page.getByRole('main');
    const section = kubescapeSection(main);
    await expect(linkedDefinition(section, 'Configuration scan')).toHaveText(
      /\d+ Critical\s*[1-9]\d* High/
    );
    await expect(linkedDefinition(section, 'Vulnerabilities')).toHaveText(/^[1-9]\d* Critical/);
    await page.waitForTimeout(5_000);
    await expect(linkedDefinition(section, 'Vulnerabilities')).toHaveText(/^[1-9]\d* Critical/);
    expect.soft(watchErrors, 'failed watches of the Kubescape storage').toEqual([]);

    await section.getByRole('link', { name: 'Vulnerabilities' }).click();
    await expect(page).toHaveURL(/\/kubescape\/vulnerabilities\/shop$/);
    // the vulnerabilities of the namespace: the scans of its containers
    await expect(main.getByRole('link', { name: 'web-nginx', exact: true })).toBeVisible();
    await page.waitForTimeout(5_000);
    await expect(main.getByRole('link', { name: 'web-nginx', exact: true })).toBeVisible();
    expect.soft(watchErrors, 'failed watches of the Kubescape storage').toEqual([]);
  });
});
