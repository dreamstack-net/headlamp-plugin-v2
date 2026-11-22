import { Locator, Page } from '@playwright/test';
import { expect, searchTable, test } from './fixtures';
import { kubescapePath } from './helpers';

/** The value (dd) of a term (dt) of a details table, such as 'Workload'. */
function definition(page: Page, term: string) {
  return page
    .getByRole('main')
    .getByRole('term')
    .filter({ hasText: new RegExp(`^${term}$`) })
    .locator('xpath=following-sibling::dd[1]');
}

/** The number in a heading such as '7 workload scans, 752 CVE issues'. */
async function countIn(heading: Locator, pattern: RegExp): Promise<number> {
  const match = pattern.exec((await heading.textContent()) ?? '');
  expect(match, `${pattern} in the heading`).not.toBeNull();
  return Number(match![1].replaceAll(',', ''));
}

/** The number in the heading once the page read all scans: it stays the same for two seconds. */
async function stableCount(heading: Locator, pattern: RegExp): Promise<number> {
  let count = -1;
  await expect(async () => {
    const before = await countIn(heading, pattern);
    await heading.page().waitForTimeout(2_000);
    count = await countIn(heading, pattern);
    expect(count).toBe(before);
  }).toPass({ timeout: 120_000 });
  return count;
}

/**
 * Checks that what a page shows stays: Headlamp's useApiGet reads an object and then watches it,
 * and a watch of the Kubescape storage sends the object without the data of its spec.
 */
async function expectToStay(locator: Locator) {
  await locator.page().waitForTimeout(5_000);
  await expect(locator).toBeVisible({ timeout: 1_000 });
}

/** The rows of the body of a table, without the header row. */
function bodyRows(table: Locator) {
  return table.locator('tbody tr, [role="rowgroup"]:last-child [role="row"]');
}

test.describe('Vulnerabilities', () => {
  test('lists the CVEs and shows only the relevant ones with the Relevant switch', async ({
    page,
  }) => {
    await page.goto(kubescapePath('vulnerabilities'));
    const main = page.getByRole('main');
    await expect(main.getByRole('tab', { name: 'CVEs' })).toHaveAttribute('aria-selected', 'true');
    const panel = main.getByRole('tabpanel', { name: 'CVEs' });
    const heading = panel.getByRole('heading', {
      name: /^\d+ workload scans?, [\d,]+ CVE issues?$/,
    });
    await expect(heading).toBeVisible();
    const all = await stableCount(heading, /, ([\d,]+) CVE issue/);
    expect(all).toBeGreaterThan(0);
    await expect(panel.getByRole('link', { name: /^(CVE|GHSA)-/ }).first()).toBeVisible();
    // busybox 1.36.0 of the sidecars, which run nothing but sleep
    await searchTable(panel, 'CVE-2022-48174');
    const busybox = panel
      .getByRole('row')
      .filter({ has: page.getByRole('link', { name: 'CVE-2022-48174' }) });
    await expect(busybox).toBeVisible();
    await expect(busybox).toContainText('busybox 1.36.0');
    await searchTable(panel, '');

    // the relevant reports leave out the CVEs of packages the workloads were not seen to use
    await panel.getByRole('checkbox', { name: 'Relevant' }).check();
    await expect(async () => {
      expect(await countIn(heading, /, ([\d,]+) CVE issue/)).toBeLessThan(all);
    }).toPass({ timeout: 30_000 });
    await panel.getByRole('checkbox', { name: 'Relevant' }).uncheck();
    await expect(async () => {
      expect(await countIn(heading, /, ([\d,]+) CVE issue/)).toBe(all);
    }).toPass({ timeout: 30_000 });

    // a CVE opens the workloads that have it
    await searchTable(panel, 'CVE-2022-48174');
    await busybox.getByRole('link', { name: 'CVE-2022-48174' }).click();
    await expect(page).toHaveURL(
      new RegExp(`${kubescapePath('vulnerabilities/cves/CVE-2022-48174')}$`)
    );
    await expect(main.getByRole('heading', { name: 'CVE-2022-48174', level: 2 })).toBeVisible();
    const workloads = main.getByRole('table');
    await expect(
      workloads.getByRole('row').filter({ hasText: 'shop' }).filter({ hasText: 'sidecar' })
    ).toBeVisible();
    await expect(workloads.getByRole('row').filter({ hasText: 'tools' }).first()).toBeVisible();
  });

  test('lists the resources and opens the findings of a workload', async ({ page }) => {
    await page.goto(kubescapePath('vulnerabilities'));
    const main = page.getByRole('main');
    await main.getByRole('tab', { name: 'Resources' }).click();
    const panel = main.getByRole('tabpanel', { name: 'Resources' });
    await expect(panel.getByRole('heading', { name: /^\d+ resources?$/ })).toBeVisible();
    const nginx = panel.getByRole('row').filter({ hasText: 'docker.io/library/nginx:1.21.6' });
    await expect(nginx).toBeVisible();
    await expect(nginx.getByRole('link', { name: /^[1-9]\d* Critical findings$/ })).toBeVisible();

    // the critical findings of the workload only
    await nginx.getByRole('link', { name: /Critical findings$/ }).click();
    await expect(page).toHaveURL(
      /\/vulnerabilities\/namespaces\/shop\/deployment-web-nginx\?severity=Critical$/
    );
    await expect(main.getByRole('heading', { name: 'Vulnerabilities', level: 2 })).toBeVisible();
    await expect(definition(page, 'Workload')).toHaveText('web');
    await expect(definition(page, 'Container')).toHaveText('nginx');
    await expect(
      definition(page, 'Image').getByRole('link', { name: 'docker.io/library/nginx:1.21.6' })
    ).toBeVisible();
    await expect(definition(page, 'CVE')).toContainText('Critical');
    const findings = main.getByRole('table').filter({ hasText: 'Fix in version' });
    await expect(findings.getByRole('link', { name: /^(CVE|GHSA)-/ }).first()).toBeVisible();
    await expectToStay(findings.getByRole('link', { name: /^(CVE|GHSA)-/ }).first());
    const severities = await findings.getByRole('row').locator('td:nth-child(2)').allTextContents();
    expect(severities.length).toBeGreaterThan(0);
    expect(new Set(severities)).toEqual(new Set(['Critical']));

    // the link of the image opens its page
    await definition(page, 'Image')
      .getByRole('link', { name: 'docker.io/library/nginx:1.21.6' })
      .click();
    await expect(page).toHaveURL(
      /\/vulnerabilities\/images\/kubescape\/docker\.io-library-nginx-1\.21\.6-/
    );
    await expect(
      main.getByRole('heading', { name: 'Image Vulnerabilities', level: 2 })
    ).toBeVisible();
  });

  test('lists the images and opens the page of an image with its workloads and findings', async ({
    page,
  }) => {
    await page.goto(kubescapePath('vulnerabilities?tab=images'));
    const main = page.getByRole('main');
    const panel = main.getByRole('tabpanel', { name: 'Images' });
    await expect(panel.getByRole('heading', { name: /^\d+ image scans?$/ })).toBeVisible();
    // one busybox image in four workloads of two namespaces
    const busybox = panel
      .getByRole('row')
      .filter({ has: page.getByRole('link', { name: 'docker.io/library/busybox:1.36.0' }) });
    await expect(busybox).toBeVisible();
    await expect(busybox.getByRole('link', { name: 'SBOM' })).toBeVisible();

    await busybox.getByRole('link', { name: 'docker.io/library/busybox:1.36.0' }).click();
    await expect(page).toHaveURL(
      /\/vulnerabilities\/images\/kubescape\/docker\.io-library-busybox-1\.36\.0-/
    );
    await expect(
      main.getByRole('heading', { name: 'Image Vulnerabilities', level: 2 })
    ).toBeVisible();
    await expect(definition(page, 'Image')).toContainText('docker.io/library/busybox:1.36.0');
    const workloads = main.getByRole('table').filter({ hasText: 'Container' });
    for (const [workload, namespace] of [
      ['web', 'shop'],
      ['api', 'shop'],
      ['toolbox', 'tools'],
      ['intruder', 'tools'],
    ]) {
      await expect(
        workloads
          .getByRole('row')
          .filter({ has: page.getByRole('link', { name: workload, exact: true }) })
          .filter({ hasText: namespace })
      ).toBeVisible();
    }
    // the findings of the image report: busybox 1.36.0 has known CVEs, such as CVE-2022-48174
    const findings = main.getByRole('table').filter({ hasText: 'Fix in version' });
    await expect(findings.getByRole('link', { name: 'CVE-2022-48174' })).toBeVisible();
    await expectToStay(findings.getByRole('link', { name: 'CVE-2022-48174' }));
  });

  test('opens the SBOM of an image', async ({ page }) => {
    await page.goto(kubescapePath('vulnerabilities?tab=images'));
    const panel = page.getByRole('tabpanel', { name: 'Images' });
    const nginx = panel
      .getByRole('row')
      .filter({ has: page.getByRole('link', { name: 'docker.io/library/nginx:1.21.6' }) });
    await nginx.getByRole('link', { name: 'SBOM' }).click();
    await expect(page).toHaveURL(
      /\/kubescape\/sbom\/kubescape\/docker\.io-library-nginx-1\.21\.6-/
    );
    const main = page.getByRole('main');
    await expect(definition(page, 'Image')).toHaveText('docker.io/library/nginx:1.21.6');
    await expect(definition(page, 'Components')).toHaveText(/^[1-9]\d*$/);
    // nginx 1.21.6 is built on Debian 11
    await expect(definition(page, 'Distro')).toHaveText('Debian GNU/Linux 11 (bullseye)');
    // the packages of the image, such as curl, which has CVEs
    const curl = main.getByRole('cell', { name: 'curl', exact: true }).first();
    await expect(curl).toBeVisible();
    await expectToStay(curl);
    await expect(definition(page, 'Components')).toHaveText(/^[1-9]\d*$/);
  });

  test('ranks the package upgrades by the CVEs they fix', async ({ page }) => {
    await page.goto(kubescapePath('vulnerabilities'));
    const main = page.getByRole('main');
    await main.getByRole('tab', { name: 'Upgrades' }).click();
    const panel = main.getByRole('tabpanel', { name: 'Upgrades' });
    const heading = panel.getByRole('heading', { name: /^\d+ package upgrades? fix CVEs?$/ });
    await expect(heading).toBeVisible();
    const all = await stableCount(heading, /^(\d+)/);
    expect(all).toBeGreaterThan(0);
    // curl of nginx 1.21.6 has a fix in a newer Debian release
    const curl = panel
      .getByRole('row')
      .filter({ hasText: 'docker.io/library/nginx:1.21.6' })
      .filter({ hasText: 'curl' })
      .first();
    await searchTable(panel, 'curl');
    await expect(curl).toBeVisible();
    await expect(curl).toContainText('shop/web/nginx');
    await searchTable(panel, '');
    // the upgrades of the packages the workloads were seen to use
    await panel.getByRole('checkbox', { name: 'Relevant' }).check();
    await expect(async () => {
      expect(await countIn(heading, /^(\d+)/)).toBeLessThanOrEqual(all);
    }).toPass({ timeout: 30_000 });
    await expect(bodyRows(panel.getByRole('table')).first()).toBeVisible();
  });
});
